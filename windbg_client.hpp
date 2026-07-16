#pragma once

#include "dml_output.hpp"
#include <dbgeng.h>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>
#include <windows.h>

namespace windbg_agent
{

// Parameters for instruction-level tracing
struct TraceParams
{
    std::string end_address;                  // required: stop when IP reaches this
    std::optional<std::string> start_address; // optional: run to this address first
    int max_steps = 20000;                    // safety cap on number of steps
    std::vector<std::string> skip_symbols;    // symbol names / hex addresses → gu when entered
    int timeout_ms = 300000;                  // wall-clock timeout in ms (default: 5 min)
    std::optional<std::string> eprocess_addr; // kernel mode: EPROCESS address for bp /p scoping
    bool more_verbose = false;                // KD: use StepNPrint.txt script (verbose, faster)
                                              //     instead of StepTraceAuto.js (quieter, smarter skip)
};

// WinDbg/CDB debugger client using dbgeng interfaces and DML for colored output
class WinDbgClient
{
  public:
    // Construct with an IDebugClient (typically from extension callback)
    explicit WinDbgClient(IDebugClient* client);
    ~WinDbgClient();

    // Execute a debugger command and return its output
    std::string ExecuteCommand(const std::string& command);

    // Execute a debugger command silently (no console echo)
    std::string ExecuteCommandSilent(const std::string& command);

    // Trace execution instruction-by-instruction and write to a log file.
    // Returns a brief summary (stop reason + log path).
    std::string Trace(const TraceParams& params);

    // Output methods for displaying messages to the user
    void Output(const std::string& message);
    void OutputError(const std::string& message);
    void OutputWarning(const std::string& message);

    // Get target info (dump file path or process name)
    std::string GetTargetName() const;

    // Get target architecture (x86, x64, ARM64, etc.)
    std::string GetTargetArchitecture() const;

    // Get debugger type (WinDbg, CDB, etc.)
    std::string GetDebuggerType() const;

    // Get debugger execution state as a human-readable string
    std::string GetTargetState() const;

    // Get the current process ID (0 if not available)
    ULONG GetProcessId() const;

    // Check if user requested interrupt (e.g., Ctrl+C)
    bool IsInterrupted() const;

    // Returns true when debugging a kernel-mode target (live KD or kernel dump)
    bool IsKernelMode() const;

  private:
    IDebugClient* client_;
    IDebugControl* control_;
    std::unique_ptr<DmlOutput> dml_;

    // KD-mode trace implementation: generates a self-looping WinDbg script
    // and runs it via $< so kd.exe's native event loop drives the stepping.
    std::string TraceKD_Script(
        const TraceParams& params,
        ULONG64 end_ip,
        const std::unordered_set<ULONG64>& skip_addrs);
};

} // namespace windbg_agent
