#include "windbg_client.hpp"
#include <cctype>
#include <chrono>
#include <cstdio>
#include <sstream>
#include <unordered_set>
#include <wrl/client.h>

namespace windbg_agent
{

// ---------------------------------------------------------------------------
// Direct-API helpers — bypass output capture (unreliable inside trace loops)
// ---------------------------------------------------------------------------

// Read registers via IDebugRegisters and format like WinDbg's 'r' output.
static std::string ReadRegistersViaApi(IDebugClient* client)
{
    Microsoft::WRL::ComPtr<IDebugRegisters> regs;
    if (FAILED(client->QueryInterface(__uuidof(IDebugRegisters),
                                      reinterpret_cast<void**>(regs.GetAddressOf()))))
        return "";

    ULONG rip_idx = 0;
    bool is_x64 = SUCCEEDED(regs->GetIndexByName("rip", &rip_idx));

    struct RegGroup { const char* names[3]; };

    static const RegGroup x64_groups[] = {
        {{"rax", "rbx", "rcx"}}, {{"rdx", "rsi", "rdi"}},
        {{"rip", "rsp", "rbp"}}, {{"r8",  "r9",  "r10"}},
        {{"r11", "r12", "r13"}}, {{"r14", "r15", nullptr}},
        {{"efl", nullptr, nullptr}}, {{nullptr, nullptr, nullptr}},
    };
    static const RegGroup x86_groups[] = {
        {{"eax", "ebx", "ecx"}}, {{"edx", "esi", "edi"}},
        {{"eip", "esp", "ebp"}}, {{"efl", nullptr, nullptr}},
        {{nullptr, nullptr, nullptr}},
    };
    const RegGroup* groups = is_x64 ? x64_groups : x86_groups;

    auto get_reg = [&](const char* name, uint64_t& out) -> bool
    {
        ULONG idx = 0;
        if (FAILED(regs->GetIndexByName(name, &idx))) return false;
        DEBUG_VALUE val = {};
        if (FAILED(regs->GetValue(idx, &val))) return false;
        out = (val.Type == DEBUG_VALUE_INT32) ? val.I32 : val.I64;
        return true;
    };

    std::ostringstream out;
    for (int g = 0; groups[g].names[0] != nullptr; ++g)
    {
        bool first = true;
        for (int r = 0; r < 3 && groups[g].names[r] != nullptr; ++r)
        {
            uint64_t val = 0;
            if (!get_reg(groups[g].names[r], val)) continue;
            if (!first) out << ' ';
            first = false;
            char buf[32];
            if (is_x64 && strcmp(groups[g].names[r], "efl") != 0)
                sprintf_s(buf, sizeof(buf), "%3s=%016I64x", groups[g].names[r], val);
            else
                sprintf_s(buf, sizeof(buf), "%3s=%08x", groups[g].names[r], (unsigned)val);
            out << buf;
        }
        out << '\n';
    }
    return out.str();
}

// Disassemble one instruction at addr via IDebugControl::Disassemble.
static std::string DisassembleOneViaApi(IDebugControl* control, ULONG64 addr)
{
    char buf[256] = {};
    ULONG written = 0; ULONG64 end_off = 0;
    HRESULT hr = control->Disassemble(addr, 0, buf, sizeof(buf), &written, &end_off);
    if (FAILED(hr) || written == 0)
    {
        char fb[24];
        sprintf_s(fb, sizeof(fb), "%08x`%08x",
                  (unsigned)(addr >> 32), (unsigned)(addr & 0xFFFFFFFF));
        return fb;
    }
    std::string s(buf, written > 0 ? written - 1 : 0);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

// Open <dll_dir>\traces\<target>_YYYYMMDD_HHMMSS.log
static FILE* OpenTraceLog(const std::string& target_name, std::string& out_path)
{
    char dll_path[MAX_PATH] = {};
    {
        HMODULE hmod = nullptr;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&ReadRegistersViaApi), &hmod);
        GetModuleFileNameA(hmod, dll_path, MAX_PATH);
    }
    std::string dll_dir(dll_path);
    auto slash = dll_dir.rfind('\\');
    if (slash != std::string::npos) dll_dir = dll_dir.substr(0, slash);

    std::string traces_dir = dll_dir + "\\traces";
    CreateDirectoryA(traces_dir.c_str(), nullptr);

    std::string target = target_name;
    { auto b = target.rfind('\\'); if (b != std::string::npos) target = target.substr(b + 1); }
    { auto d = target.rfind('.');  if (d != std::string::npos) target = target.substr(0, d); }
    for (char& c : target)
        if (c=='/'||c==':'||c=='*'||c=='?'||c=='"'||c=='<'||c=='>'||c=='|') c = '_';
    if (target.empty()) target = "unknown";

    SYSTEMTIME st = {}; GetLocalTime(&st);
    char ts[32];
    sprintf_s(ts, sizeof(ts), "%04d%02d%02d_%02d%02d%02d",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    out_path = traces_dir + "\\" + target + "_" + ts + ".log";
    FILE* fp = nullptr;
    fopen_s(&fp, out_path.c_str(), "w");
    return fp;
}

// ---------------------------------------------------------------------------
// KD-mode callback-based trace
// ---------------------------------------------------------------------------

struct KdTraceState
{
    FILE*             log_fp    = nullptr;
    std::string       log_path;
    IDebugControl*    control   = nullptr;
    IDebugClient*     client    = nullptr;
    ULONG64           end_ip    = 0;
    int               max_steps = 0;
    int               step_count = 0;
    std::chrono::steady_clock::time_point t0;
    int               timeout_ms = 0;
    IDebugEventCallbacks* prev_cbs = nullptr;
    std::unordered_set<ULONG64> skip_addrs;
    IDebugBreakpoint* skip_bp  = nullptr;
};

class KdTraceCallbacks : public IDebugEventCallbacks
{
    LONG         ref_count_ = 1;
    KdTraceState state_;
    bool         done_      = false;

    void finish(const char* reason)
    {
        done_ = true;
        state_.control->Output(DEBUG_OUTPUT_NORMAL,
            "[tracealyzer] %s after %d steps.\n[tracealyzer] Log: %s\n",
            reason, state_.step_count, state_.log_path.c_str());
        if (state_.log_fp) { fclose(state_.log_fp); state_.log_fp = nullptr; }
        // Restore previous callbacks.
        // SetEventCallbacks causes the engine to Release() us (ref 2→1).
        // Object stays alive via g_kd_trace_cbs until next Trace() call.
        state_.client->SetEventCallbacks(state_.prev_cbs);
    }

    ULONG log_and_decide(ULONG64 ip)
    {
        ++state_.step_count;
        std::string disasm = DisassembleOneViaApi(state_.control, ip);
        std::string regs   = ReadRegistersViaApi(state_.client);
        fprintf(state_.log_fp, "step %5d:\n%s\n%s\n",
                state_.step_count, disasm.c_str(), regs.c_str());

        if (state_.step_count % 1000 == 0)
            state_.control->Output(DEBUG_OUTPUT_NORMAL,
                "[tracealyzer] %d steps...\n", state_.step_count);

        auto elapsed_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - state_.t0).count();

        if (ip == state_.end_ip)
        { finish("Reached end address"); return DEBUG_STATUS_BREAK; }
        if (state_.step_count >= state_.max_steps)
        { finish("Max steps reached"); return DEBUG_STATUS_BREAK; }
        if (elapsed_ms >= state_.timeout_ms)
        { finish("Timeout"); return DEBUG_STATUS_BREAK; }
        if (state_.control->GetInterrupt() == S_OK)
        { finish("Interrupted"); return DEBUG_STATUS_BREAK; }

        // Skip (step out of) certain addresses by setting a one-shot bp at [RSP].
        if (state_.skip_addrs.count(ip))
        {
            Microsoft::WRL::ComPtr<IDebugRegisters> regs_iface;
            Microsoft::WRL::ComPtr<IDebugDataSpaces> data;
            if (SUCCEEDED(state_.client->QueryInterface(__uuidof(IDebugRegisters),
                              reinterpret_cast<void**>(regs_iface.GetAddressOf()))) &&
                SUCCEEDED(state_.client->QueryInterface(__uuidof(IDebugDataSpaces),
                              reinterpret_cast<void**>(data.GetAddressOf()))))
            {
                ULONG rsp_idx = 0;
                DEBUG_VALUE rsp_val = {};
                if (SUCCEEDED(regs_iface->GetIndexByName("rsp", &rsp_idx)) &&
                    SUCCEEDED(regs_iface->GetValue(rsp_idx, &rsp_val)))
                {
                    ULONG64 ret_addr = 0; ULONG bytes_read = 0;
                    data->ReadVirtual(rsp_val.I64, &ret_addr, 8, &bytes_read);
                    if (bytes_read == 8 && ret_addr != 0)
                    {
                        IDebugBreakpoint* bp = nullptr;
                        if (SUCCEEDED(state_.control->AddBreakpoint(
                                DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp)))
                        {
                            bp->SetOffset(ret_addr);
                            bp->AddFlags(DEBUG_BREAKPOINT_ONE_SHOT | DEBUG_BREAKPOINT_ENABLED);
                            state_.skip_bp = bp;
                            return DEBUG_STATUS_GO;
                        }
                    }
                }
            }
            // Fallback: couldn't read return address — step into the function normally.
        }

        return DEBUG_STATUS_STEP_INTO;
    }

  public:
    KdTraceCallbacks(KdTraceState&& state) : state_(std::move(state)) {}
    ~KdTraceCallbacks()
    {
        if (state_.log_fp) { fclose(state_.log_fp); state_.log_fp = nullptr; }
        if (state_.prev_cbs) { state_.prev_cbs->Release(); state_.prev_cbs = nullptr; }
    }

    // IUnknown
    STDMETHOD(QueryInterface)(REFIID id, void** pp) override
    {
        if (id == __uuidof(IUnknown) || id == __uuidof(IDebugEventCallbacks))
        { *pp = static_cast<IDebugEventCallbacks*>(this); AddRef(); return S_OK; }
        *pp = nullptr; return E_NOINTERFACE;
    }
    STDMETHOD_(ULONG, AddRef)() override { return InterlockedIncrement(&ref_count_); }
    STDMETHOD_(ULONG, Release)() override
    {
        ULONG r = InterlockedDecrement(&ref_count_);
        if (r == 0) delete this;
        return r;
    }

    // IDebugEventCallbacks
    STDMETHOD(GetInterestMask)(PULONG Mask) override
    {
        *Mask = DEBUG_EVENT_EXCEPTION | DEBUG_EVENT_BREAKPOINT;
        return S_OK;
    }

    STDMETHOD(Exception)(PEXCEPTION_RECORD64 exc, ULONG /*FirstChance*/) override
    {
        if (exc->ExceptionCode != STATUS_SINGLE_STEP &&
            exc->ExceptionCode != 0x80000004u)
            return DEBUG_STATUS_NO_CHANGE;
        if (done_) return DEBUG_STATUS_BREAK;
        return log_and_decide(exc->ExceptionAddress);
    }

    STDMETHOD(Breakpoint)(IDebugBreakpoint* bp) override
    {
        if (state_.skip_bp != nullptr)
        {
            ULONG got_id = 0, skip_id = 0;
            bp->GetId(&got_id);
            state_.skip_bp->GetId(&skip_id);
            if (got_id == skip_id)
            {
                state_.skip_bp = nullptr;
                if (done_) return DEBUG_STATUS_BREAK;
                // Returned from the skipped function — read IP and continue tracing.
                ULONG64 ip = 0;
                Microsoft::WRL::ComPtr<IDebugRegisters2> regs2;
                if (SUCCEEDED(state_.client->QueryInterface(__uuidof(IDebugRegisters2),
                                  reinterpret_cast<void**>(regs2.GetAddressOf()))))
                {
                    ULONG idx = DEBUG_ANY_ID;
                    if (FAILED(regs2->GetIndexByName("rip", &idx)))
                        regs2->GetIndexByName("eip", &idx);
                    if (idx != DEBUG_ANY_ID)
                    {
                        DEBUG_VALUE val = {};
                        if (SUCCEEDED(regs2->GetValues2(DEBUG_REGSRC_DEBUGGEE, 1, &idx, 0, &val)))
                            ip = (val.Type == DEBUG_VALUE_INT32) ? val.I32 : val.I64;
                    }
                }
                if (ip == 0) { finish("Could not read IP after skip bp"); return DEBUG_STATUS_BREAK; }
                return log_and_decide(ip);
            }
        }
        return DEBUG_STATUS_NO_CHANGE;
    }

    // No-op implementations for all other IDebugEventCallbacks methods.
    STDMETHOD(ChangeDebuggeeState)(ULONG, ULONG64)                                override { return S_OK; }
    STDMETHOD(ChangeEngineState)(ULONG, ULONG64)                                  override { return S_OK; }
    STDMETHOD(ChangeSymbolState)(ULONG, ULONG64)                                  override { return S_OK; }
    STDMETHOD(SessionStatus)(ULONG)                                               override { return S_OK; }
    STDMETHOD(CreateProcess)(ULONG64,ULONG64,ULONG64,ULONG,PCSTR,PCSTR,ULONG,
                             ULONG,ULONG64,ULONG64,ULONG64)                       override { return DEBUG_STATUS_NO_CHANGE; }
    STDMETHOD(ExitProcess)(ULONG)                                                 override { return DEBUG_STATUS_NO_CHANGE; }
    STDMETHOD(CreateThread)(ULONG64,ULONG64,ULONG64)                              override { return DEBUG_STATUS_NO_CHANGE; }
    STDMETHOD(ExitThread)(ULONG)                                                  override { return DEBUG_STATUS_NO_CHANGE; }
    STDMETHOD(LoadModule)(ULONG64,ULONG64,ULONG,PCSTR,PCSTR,ULONG,ULONG)         override { return DEBUG_STATUS_NO_CHANGE; }
    STDMETHOD(UnloadModule)(PCSTR,ULONG64)                                        override { return DEBUG_STATUS_NO_CHANGE; }
    STDMETHOD(SystemError)(ULONG,ULONG)                                           override { return DEBUG_STATUS_NO_CHANGE; }
};

// Module-global raw (non-ref-counted) pointer to the live KD trace callbacks.
// Cleaned up at the start of the next Trace() call.
static KdTraceCallbacks* g_kd_trace_cbs = nullptr;

// ---------------------------------------------------------------------------
// WinDbgClient::Trace
// ---------------------------------------------------------------------------

static const char DEFAULT_STEP_FILTER[] =
    // ntdll / user-mode runtime noise
    "ntdll!Rtl*;ntdll!__*;"
    "ntdll!memset;ntdll!memcpy;ntdll!memcmp;ntdll!memmove;"
    "ntdll!wcs*;ntdll!str*;"
    "kernel32!HeapAlloc;kernel32!HeapFree;kernel32!LocalAlloc;kernel32!LocalFree;"
    "kernelbase!HeapAlloc;kernelbase!HeapFree;"
    "ntdll!RtlAllocateHeap;ntdll!RtlFreeHeap;ntdll!RtlReAllocateHeap;"
    "ntdll!RtlEnterCriticalSection;ntdll!RtlLeaveCriticalSection;"
    "ntdll!RtlTryEnterCriticalSection;kernel32!InitializeCriticalSection;"
    "kernel32!EnterCriticalSection;kernel32!LeaveCriticalSection;"
    "kernel32!TryEnterCriticalSection;kernel32!DeleteCriticalSection;"
    "ntdll!RtlCompareMemory;ntdll!RtlCopyMemory;ntdll!RtlZeroMemory;ntdll!RtlFillMemory;"
    "ntdll!__security_check_cookie;ntdll!__report_gsfailure;*!__crt*;*!__security*;"
    // nt! kernel noise — pool alloc/free, sync primitives, RTL, string/mem ops
    "nt!ExAllocatePool*;nt!ExFreePool*;"
    "nt!KeAcquireSpinLock*;nt!KeReleaseSpinLock*;nt!KeTryToAcquireSpinLock*;"
    "nt!KeEnterCriticalRegion;nt!KeLeaveCriticalRegion;"
    "nt!Rtl*;nt!__*;"
    "nt!memset;nt!memcpy;nt!memcmp;nt!memmove;"
    "nt!wcs*;nt!str*";

// JavaScript template embedded in source.
// windbg_agent writes the auto-generated globals header then appends this
// verbatim to StepTrace.js before each trace run.
// Entry point: invokeScript() — called by .scriptrun.
static const char kStepTraceJS[] = R"JS(
"use strict";

/**
 * StepTraceAuto.js — Silent-filter single-step tracer for WinDbg (kd/windbg)
 *
 * Template for C++ agent code generation.  The following global variables
 * are expected to be prepended by the agent before .scriptrun:
 *
 *   var g_endIp      = "0x...";           // stop-address (RIP match)
 *   var g_maxSteps   = 100000;            // step budget
 *   var g_logPath    = "c:\\...\\foo.log"; // trace log path
 *   var g_scriptPath = "c:\\...\\StepTraceAuto.js";
 *   var g_skipAddrs  = ["0x...", ...];     // raw addresses to skip
 */

/* ====================================================================== */

const hex = p => '0x' + p.toString(16).padStart(16, '0');

function stepTrace() {

    var ctl = host.namespace.Debugger.Utility.Control;

    /* ------------------------------------------------------------------ */
    /*  Build unified skip list: g_skipAddrs (literal)                    */
    /* ------------------------------------------------------------------ */

    var skipList = [];

    /* literal addresses */
    for (var i = 0; i < g_skipAddrs.length; i++) {
        skipList.push(host.parseInt64(g_skipAddrs[i]));
    }

    var target = host.parseInt64(g_endIp);

    /* open log file */
    ctl.ExecuteCommand(".logopen " + g_logPath);

    /* ------------------------------------------------------------------ */
    /*  Execute a debugger command and echo output to console + log        */
    /* ------------------------------------------------------------------ */

    function execAndLog(cmd) {
        var output = ctl.ExecuteCommand(cmd);
        for (var line of output) {
            host.diagnostics.debugLog(line + "\n");
        }
    }

    /* ------------------------------------------------------------------ */
    /*  Register helpers                                                   */
    /* ------------------------------------------------------------------ */

    var regNames = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
    ];

    function regs() {
        return host.namespace.Debugger.State.DebuggerVariables
                   .curthread.Registers.User;
    }

    function getReg(idx) {
        return regs()[regNames[idx & 0xF]];
    }

    /* ------------------------------------------------------------------ */
    /*  Memory read helpers                                                */
    /* ------------------------------------------------------------------ */

    function readU8(addr) {
        return host.memory.readMemoryValues(addr, 1, 1)[0];
    }

    function readU32(addr) {
        return host.memory.readMemoryValues(addr, 1, 4)[0];
    }

    function readU64(addr) {
        return host.memory.readMemoryValues(addr, 1, 8)[0];
    }

    /* ------------------------------------------------------------------ */
    /*  Sign-extension helpers  (JS number -> Int64)                       */
    /* ------------------------------------------------------------------ */

    function signExt8(v) {
        if (v <= 0x7F) return host.parseInt64(v);
        return host.parseInt64("0xFFFFFFFFFFFFFF00").add(v);
    }

    function signExt32(v) {
        if (v <= 0x7FFFFFFF) return host.parseInt64(v);
        return host.parseInt64("0xFFFFFFFF00000000").add(v);
    }

    /* ------------------------------------------------------------------ */
    /*  Int64 shift-left (scale factor for SIB)                            */
    /* ------------------------------------------------------------------ */

    function shl64(val, bits) {
        var r = val;
        for (var i = 0; i < bits; i++) r = r.add(r);
        return r;
    }

    /* ------------------------------------------------------------------ */
    /*  Skip-list check                                                    */
    /* ------------------------------------------------------------------ */

    function isSkipped(addr) {
        for (var i = 0; i < skipList.length; i++) {
            if (addr.compareTo(skipList[i]) == 0) return true;
        }
        return false;
    }

    /* ------------------------------------------------------------------ */
    /*  x86-64 CALL target resolver                                        */
    /*                                                                     */
    /*  Returns:  Int64 call target address, or null if current            */
    /*            instruction is not a CALL or cannot be decoded.          */
    /*                                                                     */
    /*  Handles:                                                           */
    /*    E8 rel32              -- direct near call                         */
    /*    FF /2  mod=11         -- call reg                                 */
    /*    FF /2  mod=00 rm=101  -- call [rip + disp32]                     */
    /*    FF /2  mod=00         -- call [reg]                               */
    /*    FF /2  mod=01         -- call [reg + disp8]                       */
    /*    FF /2  mod=10         -- call [reg + disp32]                      */
    /*    FF /2  SIB variants   -- call [base + index*scale + disp]        */
    /*    All of the above with optional REX prefix (0x40-0x4F)            */
    /* ------------------------------------------------------------------ */

    function resolveCallTarget(rip) {

        var pos = rip;
        var rex = 0;

        /* ---------- optional REX prefix ---------- */
        var b0 = readU8(pos);
        if (b0 >= 0x40 && b0 <= 0x4F) {
            rex = b0;
            pos = pos.add(1);
            b0  = readU8(pos);
        }

        var rexB = (rex >> 0) & 1;
        var rexX = (rex >> 1) & 1;

        /* ========== E8 rel32 -- direct near call ========== */

        if (b0 == 0xE8) {
            var disp = signExt32(readU32(pos.add(1)));
            return pos.add(5).add(disp);
        }

        /* ========== FF /2 -- indirect call ========== */

        if (b0 != 0xFF) return null;

        var modrm = readU8(pos.add(1));
        var mod   = (modrm >> 6) & 3;
        var regOp = (modrm >> 3) & 7;
        var rm    = modrm & 7;

        if (regOp != 2) return null;

        /* ----- mod 11: call register ----- */

        if (mod == 3) {
            return getReg(rm | (rexB << 3));
        }

        /* ----- memory operand: compute effective address ----- */

        var cursor = pos.add(2);
        var addr;

        if (rm == 4) {
            /* ---- SIB byte present ---- */
            var sib    = readU8(cursor);
            cursor     = cursor.add(1);

            var base   = sib & 7;
            var index  = (sib >> 3) & 7;
            var scale  = (sib >> 6) & 3;

            var baseIdx  = base  | (rexB << 3);
            var indexIdx = index | (rexX << 3);

            if (mod == 0 && base == 5) {
                addr   = signExt32(readU32(cursor));
                cursor = cursor.add(4);
            } else {
                addr = getReg(baseIdx);
            }

            if (!(index == 4 && rexX == 0)) {
                var indexVal = getReg(indexIdx);
                if (scale > 0) indexVal = shl64(indexVal, scale);
                addr = addr.add(indexVal);
            }

            if (mod == 1) {
                addr = addr.add(signExt8(readU8(cursor)));
            } else if (mod == 2) {
                addr = addr.add(signExt32(readU32(cursor)));
            }

        } else if (mod == 0 && rm == 5) {
            /* ---- RIP-relative: call [rip + disp32] ---- */
            var instrLen = (rex ? 1 : 0) + 1 + 1 + 4;
            var ripDisp  = signExt32(readU32(cursor));
            addr = rip.add(instrLen).add(ripDisp);

        } else {
            /* ---- simple [reg], [reg+disp8], [reg+disp32] ---- */
            addr = getReg(rm | (rexB << 3));

            if (mod == 1) {
                addr = addr.add(signExt8(readU8(cursor)));
            } else if (mod == 2) {
                addr = addr.add(signExt32(readU32(cursor)));
            }
        }

        /* dereference: the pointer at [addr] holds the call target */
        return readU64(addr);
    }

    /* ------------------------------------------------------------------ */
    /*  Main trace loop                                                    */
    /* ------------------------------------------------------------------ */

    for (var i = 0; i < g_maxSteps; i++) {

        var rip = regs().rip;

        /* target reached? */
        if (rip.compareTo(target) == 0) {
            ctl.ExecuteCommand(".logclose");
            host.diagnostics.debugLog(
                "[tracealyzer] Target address reached at step " + i + ".\n");
            host.diagnostics.debugLog(
                "[tracealyzer] Log: " + g_logPath + "\n");
            return;
        }

        /* already inside a skipped function (e.g. entered via interrupt)? */
        if (isSkipped(rip)) {
            host.diagnostics.debugLog("[tracealyzer] Skipped address " + hex(rip) + "\n");
            ctl.ExecuteCommand("gu");
            continue;
        }

        /* decode current instruction -- is it a CALL to a skipped target? */
        var callTarget = null;
        try {
            callTarget = resolveCallTarget(rip);
        } catch (e) {
            /* decode failed -- not a call or unreadable memory; fall through */
        }

        if (callTarget !== null && isSkipped(callTarget)) {
            host.diagnostics.debugLog("[tracealyzer] Skipped call(" + hex(callTarget) + ")\n");
            ctl.ExecuteCommand("p");
        } else {
            /* normal step: dump registers + disassembly, then trace into */
            execAndLog("r");
            ctl.ExecuteCommand("t");
        }
    }

    ctl.ExecuteCommand(".logclose");
    host.diagnostics.debugLog(
        "[tracealyzer] Max steps (" + g_maxSteps + ") reached.\n");
    host.diagnostics.debugLog(
        "[tracealyzer] Log: " + g_logPath + "\n");
}

/* ====================================================================== */
/*  Entry point -- called automatically by .scriptrun                     */
/* ====================================================================== */

function invokeScript() {
    stepTrace();
}
)JS";

std::string WinDbgClient::Trace(const TraceParams& params)
{
    if (!control_ || !client_)
        return "[tracealyzer] Error: No debugger control available\n";
    if (params.end_address.empty())
        return "[tracealyzer] Error: end_address is required\n";

    // Clean up any completed KD trace callback object from a previous run.
    if (g_kd_trace_cbs) { g_kd_trace_cbs->Release(); g_kd_trace_cbs = nullptr; }

    // Build step filter: default entries + user-supplied skip symbols.
    // KD mode: .step_filter is the only reliable skip mechanism — every attempt to
    // restart the t "$<script" chain from a bp command context hits a fundamental
    // kd.exe limitation where deferred commands from a bp handler cannot chain
    // further steps.  .step_filter works below the loop level at the engine's step
    // handler, replacing t with p for filtered symbols without interrupting the chain.
    // User mode: .step_filter also active; skip_addrs gu-skip in WaitForEvent loop
    // provides additional coverage for hex-address skips.
    //
    // Hex addresses (0x… or pure hex digits) are not supported by .step_filter —
    // it takes symbol name patterns only.  Warn and fall through to skip_addrs.
    //
    // WinDbg truncates .step_filter when too many entries are passed in one command
    // (~24 max).  Clear first, then add in small batches.
    {
        std::vector<std::string> entries;
        {
            std::istringstream ss(DEFAULT_STEP_FILTER);
            std::string e;
            while (std::getline(ss, e, ';'))
                if (!e.empty()) entries.push_back(e);
        }

        for (const auto& sym : params.skip_symbols)
        {
            bool is_hex = (sym.size() > 2 && sym[0] == '0' && (sym[1] == 'x' || sym[1] == 'X'));
            if (!is_hex && !sym.empty())
            {
                is_hex = true;
                for (char c : sym)
                    if (!isxdigit((unsigned char)c)) { is_hex = false; break; }
            }
            if (is_hex)
                control_->Output(DEBUG_OUTPUT_WARNING,
                    "[tracealyzer] Warning: skip '%s' is a hex address -"
                    " .step_filter requires symbol names; address-based skip"
                    " will be used in user-mode only.\n", sym.c_str());
            else
                entries.push_back(sym);
        }

        ExecuteCommandSilent(".step_filter /c");

        const int kBatch = 10;
        for (int i = 0; i < (int)entries.size(); i += kBatch)
        {
            std::string batch;
            for (int j = i; j < (int)entries.size() && j < i + kBatch; ++j)
            {
                if (!batch.empty()) batch += ";";
                batch += entries[j];
            }
            ExecuteCommandSilent(".step_filter \"" + batch + "\"");
        }
    }

    // Resolve an expression to ULONG64.
    auto resolve = [this](const std::string& expr, ULONG64& out) -> bool
    {
        DEBUG_VALUE v = {}; ULONG rem = 0;
        if (SUCCEEDED(control_->Evaluate(expr.c_str(), DEBUG_VALUE_INT64, &v, &rem)))
        { out = v.I64; return true; }
        return false;
    };

    // Read the instruction pointer.
    //
    // Primary: IDebugRegisters2::GetValues2(DEBUG_REGSRC_DEBUGGEE) — queries the
    // target directly over the KD wire (in KD) or via the live debug context (user
    // mode), bypassing the dbgeng register cache.  Gives fresh values right after
    // Execute("t") in KD without needing WaitForEvent.
    //
    // Fallback 1: IDebugRegisters::GetValue — reads from the dbgeng cache.  Stale
    // in KD unless WaitForEvent was called, but correct in user mode after WaitForEvent.
    //
    // Fallback 2: expression evaluator — last resort.
    auto read_ip = [&](ULONG64& ip) -> bool
    {
        Microsoft::WRL::ComPtr<IDebugRegisters2> regs2;
        if (SUCCEEDED(client_->QueryInterface(__uuidof(IDebugRegisters2),
                                              reinterpret_cast<void**>(regs2.GetAddressOf()))))
        {
            ULONG idx = DEBUG_ANY_ID;
            if (FAILED(regs2->GetIndexByName("rip", &idx)))
                regs2->GetIndexByName("eip", &idx);
            if (idx != DEBUG_ANY_ID)
            {
                DEBUG_VALUE val = {};
                if (SUCCEEDED(regs2->GetValues2(DEBUG_REGSRC_DEBUGGEE, 1, &idx, 0, &val)))
                { ip = (val.Type == DEBUG_VALUE_INT32) ? val.I32 : val.I64; return true; }
            }
        }
        // Fallback: cache read (fresh in user mode after WaitForEvent).
        Microsoft::WRL::ComPtr<IDebugRegisters> regs;
        if (SUCCEEDED(client_->QueryInterface(__uuidof(IDebugRegisters),
                                              reinterpret_cast<void**>(regs.GetAddressOf()))))
        {
            ULONG idx = 0;
            if (SUCCEEDED(regs->GetIndexByName("rip", &idx)) ||
                SUCCEEDED(regs->GetIndexByName("eip", &idx)))
            {
                DEBUG_VALUE val = {};
                if (SUCCEEDED(regs->GetValue(idx, &val)))
                { ip = (val.Type == DEBUG_VALUE_INT32) ? val.I32 : val.I64; return true; }
            }
        }
        // Last resort: expression evaluator.
        return resolve("@$ip", ip);
    };

    ULONG64 end_ip = 0;
    if (!resolve(params.end_address, end_ip))
        return "[tracealyzer] Error: Could not resolve end address: " + params.end_address + "\n";

    // Resolve skip symbols to addresses.
    // KD  — addresses embedded as .if checks in StepNPrint.txt
    // User — addresses checked in the WaitForEvent loop
    std::unordered_set<ULONG64> skip_addrs;
    for (const auto& sym : params.skip_symbols)
    {
        ULONG64 a = 0;
        if (resolve(sym, a) && a != 0)
            skip_addrs.insert(a);
        else
            control_->Output(DEBUG_OUTPUT_WARNING,
                "[tracealyzer] Warning: could not resolve skip symbol '%s' - ignored.\n",
                sym.c_str());
    }

    // Navigate to start address: explicit bp /1 + g avoids engine-state issues
    // caused by the "g <addr>" shorthand form.
    // Kernel mode: scope the bp to the target process via bp /p <eprocess> to
    // avoid false hits on the same address in another process/thread.
    if (params.start_address && !params.start_address->empty())
    {
        std::string bp_cmd = "bp /1 ";
        if (IsKernelMode() && params.eprocess_addr && !params.eprocess_addr->empty())
            bp_cmd += "/p " + *params.eprocess_addr + " ";
        bp_cmd += *params.start_address;
        ExecuteCommandSilent(bp_cmd);
        ExecuteCommandSilent("g");
    }

    // KD mode: use .logopen + self-looping script driven by kd.exe's event loop.
    if (IsKernelMode())
        return TraceKD_Script(params, end_ip, skip_addrs);

    std::string log_path;
    FILE* log_fp = OpenTraceLog(GetTargetName(), log_path);
    if (!log_fp)
        return "[tracealyzer] Error: Could not open log file: " + log_path + "\n";

    // Header.
    ULONG64 start_ip = 0;
    read_ip(start_ip);
    auto fmt = [](ULONG64 a) { char b[20]; sprintf_s(b,sizeof(b),"%08x`%08x",(unsigned)(a>>32),(unsigned)(a&0xFFFFFFFF)); return std::string(b); };
    std::string header = "[tracealyzer] Tracing from " + fmt(start_ip) +
                         " to " + fmt(end_ip) +
                         " (max " + std::to_string(params.max_steps) + " steps)\n";
    control_->Output(DEBUG_OUTPUT_NORMAL, "%s", header.c_str());
    fprintf(log_fp, "%s", header.c_str());

    // User-mode: WaitForEvent loop.
    auto t0 = std::chrono::steady_clock::now();
    int step_count = 0;
    std::string stop_reason;
    for (int i = 0; i < params.max_steps; ++i)
    {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        if (static_cast<int>(elapsed) >= params.timeout_ms)
        { stop_reason = "[tracealyzer] Timeout after " + std::to_string(step_count) + " steps.\n"; break; }

        if (IsInterrupted())
        { stop_reason = "[tracealyzer] Interrupted after " + std::to_string(step_count) + " steps.\n"; break; }

        ULONG64 current_ip = 0;
        if (!read_ip(current_ip))
        { stop_reason = "[tracealyzer] Error: Could not read instruction pointer.\n"; break; }

        if (current_ip == end_ip)
        { stop_reason = "[tracealyzer] Reached end address after " + std::to_string(step_count) + " steps.\n"; break; }

        ++step_count;
        std::string disasm = DisassembleOneViaApi(control_, current_ip);
        std::string regs_str = ReadRegistersViaApi(client_);
        fprintf(log_fp, "step %5d:\n%s\n%s\n", step_count, disasm.c_str(), regs_str.c_str());

        if (step_count % 1000 == 0)
            control_->Output(DEBUG_OUTPUT_NORMAL, "[tracealyzer] %d steps...\n", step_count);

        const char* step_cmd = (!skip_addrs.empty() && skip_addrs.count(current_ip)) ? "gu" : "t";
        ExecuteCommandSilent(step_cmd);

        // Execute("t") is async in user mode. WaitForEvent processes the break-back
        // event, refreshing thread/process context and the register cache.
        auto remaining_ms = params.timeout_ms - static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count());
        if (remaining_ms <= 0)
            break;
        HRESULT wait_hr = control_->WaitForEvent(0, static_cast<ULONG>(remaining_ms));
        if (FAILED(wait_hr))
        {
            stop_reason = "[tracealyzer] WaitForEvent failed (hr=" + std::to_string(wait_hr)
                        + ") after " + std::to_string(step_count) + " steps.\n";
            break;
        }
    }

    if (stop_reason.empty())
        stop_reason = "[tracealyzer] Max steps (" + std::to_string(params.max_steps) + ") reached.\n";

    fprintf(log_fp, "%s", stop_reason.c_str());
    fclose(log_fp);
    return stop_reason + "[tracealyzer] Log: " + log_path + "\n";
}

std::string WinDbgClient::TraceKD_Script(
    const TraceParams& params,
    ULONG64 end_ip,
    const std::unordered_set<ULONG64>& skip_addrs)
{
    // ── Step 1: locate traces directory (same logic as OpenTraceLog) ─────────
    char dll_path[MAX_PATH] = {};
    HMODULE hmod = nullptr;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(&ReadRegistersViaApi), &hmod);
    GetModuleFileNameA(hmod, dll_path, MAX_PATH);
    std::string dll_dir(dll_path);
    { auto s = dll_dir.rfind('\\'); if (s != std::string::npos) dll_dir = dll_dir.substr(0, s); }
    std::string traces_dir = dll_dir + "\\traces";
    CreateDirectoryA(traces_dir.c_str(), nullptr);

    // ── Step 2: open log via .logopen /t ─────────────────────────────────────
    // /t appends a timestamp before the .log extension, e.g.:
    //   "C:\traces\nt.log"  →  "C:\traces\nt_20260311_143022.log"
    std::string target = GetTargetName();
    { auto b = target.rfind('\\'); if (b != std::string::npos) target = target.substr(b + 1); }
    { auto d = target.rfind('.'); if (d != std::string::npos) target = target.substr(0, d); }
    for (char& c : target)
        if (c=='/'||c==':'||c=='*'||c=='?'||c=='"'||c=='<'||c=='>'||c=='|') c = '_';
    if (target.empty()) target = "unknown";

    std::string log_base = traces_dir + "\\" + target + ".log";
    std::string logopen_out = ExecuteCommandSilent(".logopen /t " + log_base);

    // Parse actual path from output like: Opened log file 'C:\...\name.log'
    std::string log_path;
    {
        auto q1 = logopen_out.find('\'');
        auto q2 = (q1 != std::string::npos) ? logopen_out.find('\'', q1 + 1) : std::string::npos;
        if (q1 != std::string::npos && q2 != std::string::npos)
            log_path = logopen_out.substr(q1 + 1, q2 - q1 - 1);
    }
    if (log_path.empty())
        log_path = log_base;  // fallback: best-guess (no timestamp)

    // ── Step 3: print header (goes to both console and open log) ─────────────
    ULONG64 start_ip = 0;
    {
        Microsoft::WRL::ComPtr<IDebugRegisters> regs;
        if (SUCCEEDED(client_->QueryInterface(__uuidof(IDebugRegisters),
                                              reinterpret_cast<void**>(regs.GetAddressOf()))))
        {
            ULONG idx = 0;
            if (SUCCEEDED(regs->GetIndexByName("rip", &idx)) ||
                SUCCEEDED(regs->GetIndexByName("eip", &idx)))
            {
                DEBUG_VALUE v{}; regs->GetValue(idx, &v);
                start_ip = (v.Type == DEBUG_VALUE_INT32) ? v.I32 : v.I64;
            }
        }
    }
    auto fmt = [](ULONG64 a) {
        char b[20];
        sprintf_s(b, sizeof(b), "%08x`%08x", (unsigned)(a >> 32), (unsigned)(a & 0xFFFFFFFF));
        return std::string(b);
    };
    control_->Output(DEBUG_OUTPUT_NORMAL,
        "[tracealyzer] Tracing from %s to %s (max %d steps)\n",
        fmt(start_ip).c_str(), fmt(end_ip).c_str(), params.max_steps);

    if (params.more_verbose)
    {
        // ── Step 4a: write StepNPrint.txt (self-looping WinDbg script) ──────────
        std::string script_path = traces_dir + "\\StepNPrint.txt";

        // Escape backslashes for use inside WinDbg command strings (e.g. t "$<...").
        std::string esc_script;
        for (char c : script_path) { esc_script += c; if (c == '\\') esc_script += '\\'; }

        std::string done_target =
            ".logclose; .echo [tracealyzer] Target address reached.;"
            " .echo [tracealyzer] Log: " + log_path;
        std::string done_max =
            ".logclose; .echo [tracealyzer] Max steps reached.;"
            " .echo [tracealyzer] Log: " + log_path;

        FILE* sf = nullptr;
        fopen_s(&sf, script_path.c_str(), "w");
        if (!sf)
        {
            ExecuteCommandSilent(".logclose");
            return "[tracealyzer] Error: could not write StepNPrint.txt\n";
        }
        fprintf(sf, "r\n");
        fprintf(sf, ".if (@rip == 0x%I64x) { %s }", end_ip, done_target.c_str());
        fprintf(sf, " .else { .if (@$t0 > 0) { r $t0 = @$t0 - 1; t \"$<%s\" }",
                esc_script.c_str());
        fprintf(sf, " .else { %s } }\n", done_max.c_str());
        fclose(sf);

        // ── Step 4b: initialise step counter then launch ─────────────────────────
        char t0_cmd[64];
        sprintf_s(t0_cmd, sizeof(t0_cmd), "r $t0 = 0x%x", params.max_steps);
        ExecuteCommandSilent(t0_cmd);

        control_->Output(DEBUG_OUTPUT_NORMAL, "[tracealyzer] Running %s\n", script_path.c_str());
        control_->Execute(DEBUG_OUTCTL_ALL_CLIENTS,
                          ("$$><" + script_path).c_str(),
                          DEBUG_EXECUTE_DEFAULT);
    }
    else
    {
        // ── Step 4: write StepTraceAuto.js (globals header + embedded JS template) ──────
        // Globals are regenerated on every run; the template body (kStepTraceJS) is
        // the canonical implementation embedded in the C++ source.
        std::string js_path = traces_dir + "\\StepTraceAuto.js";
        {
            FILE* jf = nullptr;
            fopen_s(&jf, js_path.c_str(), "w");
            if (!jf)
            {
                ExecuteCommandSilent(".logclose");
                return "[tracealyzer] Error: could not write StepTrace.js\n";
            }

            // Escape backslashes for JS string literals.
            auto js_str = [](const std::string& s) -> std::string {
                std::string r;
                for (char c : s) { if (c == '\\') r += "\\\\"; else r += c; }
                return r;
            };

            fprintf(jf, "// Auto-generated by windbg_agent — do not edit.\n");
            fprintf(jf, "var g_endIp      = \"0x%I64x\";\n", end_ip);
            fprintf(jf, "var g_maxSteps   = %d;\n", params.max_steps);
            fprintf(jf, "var g_logPath    = \"%s\";\n", js_str(log_path).c_str());
            fprintf(jf, "var g_scriptPath = \"%s\";\n", js_str(js_path).c_str());
            fprintf(jf, "var g_skipAddrs  = [");
            bool first = true;
            for (ULONG64 a : skip_addrs)
            {
                if (!first) fprintf(jf, ", ");
                fprintf(jf, "\"0x%I64x\"", a);
                first = false;
            }
            fprintf(jf, "];\n");

            // Append the JS template from C++ source.
            fprintf(jf, "%s", kStepTraceJS);
            fclose(jf);
        }

        // ── Step 5: run StepTrace.js via .scriptrun ───────────────────────────────
        // .scriptrun loads the script fresh and calls invokeScript().
        // Use ALL_CLIENTS so host.diagnostics.debugLog() output is captured by .logopen.
        control_->Output(DEBUG_OUTPUT_NORMAL, "[tracealyzer] Running %s\n", js_path.c_str());
        control_->Execute(DEBUG_OUTCTL_ALL_CLIENTS,
                          (".scriptrun " + js_path).c_str(),
                          DEBUG_EXECUTE_DEFAULT);
    }

    return "";
}

} // namespace windbg_agent
