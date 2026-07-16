#include <dbgeng.h>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h>
#include <memory>

#include "http_server.hpp"
#include "mcp_server.hpp"
#include "version.h"
#include "dml_output.hpp"
#include "windbg_client.hpp"

namespace
{

// Trace defaults
#define DEFAULT_TRACE_MAX_STEPS 20000
#define DEFAULT_TRACE_TIMEOUT   300000

// Try to parse a hex address string ("0x..." or plain hex digits), return true on success
static bool TryParseAddress(const std::string& s, ULONG64& out)
{
    if (s.empty())
        return false;
    try
    {
        size_t pos = 0;
        const char* p = s.c_str();
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
            out = std::stoull(s, &pos, 16);
        else
            out = std::stoull(s, &pos, 16);
        return pos == s.size();
    }
    catch (...)
    {
        return false;
    }
}

// Persistent state for the headless server.  Owned references are released in reset().
struct AgentState {
    IDebugClient*  secondary_client  = nullptr;
    IDebugControl* secondary_control = nullptr;
    std::unique_ptr<windbg_agent::DmlOutput>    dml;
    std::unique_ptr<windbg_agent::WinDbgClient> dbg_client;

    void reset() {
        dml.reset();        // must die before secondary_control is released
        dbg_client.reset(); // must die before secondary_client is released (it holds QI refs)
        if (secondary_control) { secondary_control->Release(); secondary_control = nullptr; }
        if (secondary_client)  { secondary_client->Release();  secondary_client  = nullptr; }
    }

    ~AgentState() { reset(); }
};

AgentState                  g_agent_state;
windbg_agent::HttpServer    g_http_server;
windbg_agent::MCPServer     g_mcp_server;

// Create secondary IDebugClient + populate AgentState.  Returns false on failure.
bool setup_agent_state(PDEBUG_CLIENT Client, IDebugControl* control)
{
    g_agent_state.reset();

    IDebugClient* sec_client = nullptr;
    if (FAILED(Client->CreateClient(&sec_client))) {
        control->Output(DEBUG_OUTPUT_ERROR, "Failed to create secondary debug client.\n");
        return false;
    }

    IDebugControl* sec_control = nullptr;
    if (FAILED(sec_client->QueryInterface(__uuidof(IDebugControl), (void**)&sec_control))) {
        sec_client->Release();
        control->Output(DEBUG_OUTPUT_ERROR, "Failed to query IDebugControl from secondary client.\n");
        return false;
    }

    g_agent_state.secondary_client  = sec_client;
    g_agent_state.secondary_control = sec_control;
    g_agent_state.dbg_client = std::make_unique<windbg_agent::WinDbgClient>(sec_client);
    g_agent_state.dml        = std::make_unique<windbg_agent::DmlOutput>(sec_control);
    return true;
}

// Build the exec callback that runs on the command thread.
windbg_agent::ExecCallback make_exec_cb()
{
    auto* dbg_ptr = g_agent_state.dbg_client.get();
    auto* dml_ptr = g_agent_state.dml.get();
    return [dbg_ptr, dml_ptr](const std::string& command) -> std::string {
        dml_ptr->OutputCommand(command.c_str());
        std::string result = dbg_ptr->ExecuteCommand(command);
        dml_ptr->OutputCommandResult(result.c_str());
        return result;
    };
}

} // namespace

// Extension entry point
extern "C" HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
    *Version = DEBUG_EXTENSION_VERSION(WINDBG_AGENT_VERSION_MAJOR, WINDBG_AGENT_VERSION_MINOR);
    *Flags = 0;
    return S_OK;
}

// Extension cleanup - release COM objects before dbgeng unloads
extern "C" void CALLBACK DebugExtensionUninitialize()
{
    if (g_http_server.is_running()) g_http_server.stop();
    if (g_mcp_server.is_running())  g_mcp_server.stop();
    g_agent_state.reset();
}

// Extension notification
extern "C" void CALLBACK DebugExtensionNotify(ULONG Notify, ULONG64 Argument)
{
}

// Implementation
HRESULT CALLBACK agent_impl(PDEBUG_CLIENT Client, PCSTR Args)
{
    IDebugControl* control = nullptr;
    Client->QueryInterface(__uuidof(IDebugControl), (void**)&control);
    if (!control)
        return E_FAIL;

    // Parse subcommand
    std::string args_str = Args ? Args : "";

    size_t start = args_str.find_first_not_of(" \t");
    if (start != std::string::npos)
        args_str = args_str.substr(start);

    std::string subcmd;
    std::string rest;
    size_t space = args_str.find(' ');
    if (space != std::string::npos)
    {
        subcmd = args_str.substr(0, space);
        rest = args_str.substr(space + 1);
        size_t rest_start = rest.find_first_not_of(" \t");
        if (rest_start != std::string::npos)
            rest = rest.substr(rest_start);
    }
    else
    {
        subcmd = args_str;
    }

    // Handle subcommands
    if (subcmd.empty() || subcmd == "help")
    {
        control->Output(
            DEBUG_OUTPUT_NORMAL,
            "WinDbg Agent - Debugger server extension\n"
            "\n"
            "Usage: !agent <command> [args]\n"
            "\n"
            "Commands:\n"
            "  help                  Show this help\n"
            "  version               Show version information\n"
            "  http [bind_addr]      Start HTTP server (headless, returns immediately)\n"
            "  mcp  [bind_addr]      Start MCP server (headless, returns immediately)\n"
            "  stop                  Stop any running server\n"
            "  trace <end> [opts]    Trace to end addr; opts: start_addr, steps, skip, timeout, eprocess (KD), more_verbose (KD)\n"
            "\n"
            "The server runs entirely on background threads so WinDbg remains\n"
            "fully interactive.  Execution commands (g, t, p, ...) sent by an\n"
            "LLM will run the target normally and return output when it stops.\n"
            "\n"
            "Examples:\n"
            "  !agent http           (start HTTP server on localhost)\n"
            "  !agent http 0.0.0.0   (start HTTP server on all interfaces)\n"
            "  !agent mcp            (start MCP server on localhost)\n"
            "  !agent stop           (stop the running server)\n");
    }
    else if (subcmd == "version")
    {
        control->Output(DEBUG_OUTPUT_NORMAL, "WinDbg Agent v%d.%d.%d\n",
                        WINDBG_AGENT_VERSION_MAJOR, WINDBG_AGENT_VERSION_MINOR,
                        WINDBG_AGENT_VERSION_PATCH);
    }
    else if (subcmd == "http")
    {
        if (g_http_server.is_running())
        {
            control->Output(DEBUG_OUTPUT_ERROR,
                            "HTTP server already running. Use '!agent stop' to stop it first.\n");
            control->Release();
            return E_FAIL;
        }

        // Parse optional bind address
        std::string bind_addr = "127.0.0.1";
        if (!rest.empty())
        {
            bind_addr = rest;
            size_t s = bind_addr.find_first_not_of(" \t");
            size_t e = bind_addr.find_last_not_of(" \t");
            if (s != std::string::npos)
                bind_addr = bind_addr.substr(s, e - s + 1);
        }

        if (bind_addr != "127.0.0.1")
        {
            control->Output(DEBUG_OUTPUT_WARNING,
                "WARNING: Binding to non-loopback address '%s'. "
                "The server has no authentication.\n", bind_addr.c_str());
        }

        // Create secondary IDebugClient owned by the background command thread.
        // This lets Execute("g") and other blocking commands run without holding
        // the WinDbg extension thread, so the UI stays fully responsive.
        if (!setup_agent_state(Client, control))
        {
            control->Release();
            return E_FAIL;
        }

        // Snapshot target info (before background thread starts)
        std::string target = g_agent_state.dbg_client->GetTargetName();
        std::string state  = g_agent_state.dbg_client->GetTargetState();
        ULONG       pid    = g_agent_state.dbg_client->GetProcessId();

        int actual_port = g_http_server.start(make_exec_cb(), bind_addr);
        if (actual_port <= 0)
        {
            g_agent_state.reset();
            control->Output(DEBUG_OUTPUT_ERROR, "Failed to start HTTP server.\n");
            control->Release();
            return E_FAIL;
        }

        // /break calls SetInterrupt() directly on the HTTP handler thread so it
        // works even while g/t/p is blocking the command thread.
        auto* sec_ctrl = g_agent_state.secondary_control;
        g_http_server.set_break_callback([sec_ctrl]() {
            if (sec_ctrl)
                sec_ctrl->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
        });

        std::string url = "http://" + g_http_server.bind_addr() + ":" +
                          std::to_string(g_http_server.port());

        std::string http_info = windbg_agent::format_http_info(target, pid, state, url);
        control->Output(DEBUG_OUTPUT_NORMAL, "%s\n", http_info.c_str());

        if (windbg_agent::copy_to_clipboard(http_info))
            control->Output(DEBUG_OUTPUT_NORMAL, "[Copied to clipboard]\n");

        control->Output(DEBUG_OUTPUT_NORMAL,
            "Server running in headless mode - WinDbg is fully interactive.\n"
            "Use '!agent stop' or POST /shutdown to stop the server.\n");
    }
    else if (subcmd == "mcp")
    {
        if (g_mcp_server.is_running())
        {
            control->Output(DEBUG_OUTPUT_ERROR,
                            "MCP server already running. Use '!agent stop' to stop it first.\n");
            control->Release();
            return E_FAIL;
        }

        // Parse optional bind address
        std::string bind_addr = "127.0.0.1";
        if (!rest.empty())
        {
            bind_addr = rest;
            size_t s = bind_addr.find_first_not_of(" \t");
            size_t e = bind_addr.find_last_not_of(" \t");
            if (s != std::string::npos)
                bind_addr = bind_addr.substr(s, e - s + 1);
        }

        if (bind_addr != "127.0.0.1")
        {
            control->Output(DEBUG_OUTPUT_WARNING,
                "WARNING: Binding to non-loopback address '%s'. "
                "The server has no authentication.\n", bind_addr.c_str());
        }

        if (!setup_agent_state(Client, control))
        {
            control->Release();
            return E_FAIL;
        }

        std::string target = g_agent_state.dbg_client->GetTargetName();
        std::string state  = g_agent_state.dbg_client->GetTargetState();
        ULONG       pid    = g_agent_state.dbg_client->GetProcessId();

        int actual_port = g_mcp_server.start(0, make_exec_cb(), bind_addr);
        if (actual_port <= 0)
        {
            g_agent_state.reset();
            control->Output(DEBUG_OUTPUT_ERROR, "Failed to start MCP server.\n");
            control->Release();
            return E_FAIL;
        }

        std::string url = "http://" + bind_addr + ":" + std::to_string(actual_port);

        std::string mcp_info = windbg_agent::format_mcp_info(target, pid, state, url);
        control->Output(DEBUG_OUTPUT_NORMAL, "%s\n", mcp_info.c_str());

        if (windbg_agent::copy_to_clipboard(mcp_info))
            control->Output(DEBUG_OUTPUT_NORMAL, "[Copied to clipboard]\n");

        control->Output(DEBUG_OUTPUT_NORMAL,
            "Server running in headless mode - WinDbg is fully interactive.\n"
            "Use '!agent stop' or POST /shutdown to stop the server.\n");
    }
    else if (subcmd == "stop")
    {
        bool stopped = false;
        if (g_http_server.is_running())
        {
            g_http_server.stop();
            g_agent_state.reset();
            stopped = true;
            control->Output(DEBUG_OUTPUT_NORMAL, "HTTP server stopped.\n");
        }
        if (g_mcp_server.is_running())
        {
            g_mcp_server.stop();
            g_agent_state.reset();
            stopped = true;
            control->Output(DEBUG_OUTPUT_NORMAL, "MCP server stopped.\n");
        }
        if (!stopped)
            control->Output(DEBUG_OUTPUT_NORMAL, "No server is currently running.\n");
    }
    else if (subcmd == "trace")
    {
        // Usage: !agent trace <end_addr> [start_addr=<addr>] [steps=<N>] [skip=sym1,sym2] [timeout=<ms>] [eprocess=<addr>]
        if (rest.empty())
        {
            control->Output(DEBUG_OUTPUT_NORMAL,
                            "Usage: !agent trace <end_addr> [start_addr=<addr>] [steps=<N>] "
                            "[skip=sym1,sym2] [timeout=<ms>] [eprocess=<addr>] [more_verbose=1]\n");
            control->Release();
            return S_OK;
        }

        windbg_agent::WinDbgClient dbg_client(Client);
        windbg_agent::TraceParams params;
        params.max_steps = DEFAULT_TRACE_MAX_STEPS;
        params.timeout_ms = DEFAULT_TRACE_TIMEOUT;

        // Tokenize rest
        std::vector<std::string> tokens;
        {
            std::istringstream ss(rest);
            std::string tok;
            while (ss >> tok)
                tokens.push_back(tok);
        }

        // First token is end_addr
        params.end_address = tokens[0];

        // Parse remaining key=value options
        for (size_t i = 1; i < tokens.size(); ++i)
        {
            const std::string& tok = tokens[i];
            auto eq = tok.find('=');
            if (eq == std::string::npos)
            {
                control->Output(DEBUG_OUTPUT_ERROR, "Unknown trace option: %s\n", tok.c_str());
                control->Release();
                return E_INVALIDARG;
            }
            std::string key = tok.substr(0, eq);
            std::string val = tok.substr(eq + 1);

            if (key == "start_addr")
            {
                params.start_address = val;
            }
            else if (key == "steps")
            {
                try { params.max_steps = std::stoi(val); }
                catch (...) { control->Output(DEBUG_OUTPUT_ERROR, "Invalid steps value: %s\n", val.c_str()); }
            }
            else if (key == "timeout")
            {
                try { params.timeout_ms = std::stoi(val); }
                catch (...) { control->Output(DEBUG_OUTPUT_ERROR, "Invalid timeout value: %s\n", val.c_str()); }
            }
            else if (key == "skip")
            {
                // Comma-separated list of symbols/addresses to skip (gu)
                std::istringstream sv(val);
                std::string sym;
                while (std::getline(sv, sym, ','))
                    if (!sym.empty())
                        params.skip_symbols.push_back(sym);
            }
            else if (key == "eprocess")
            {
                params.eprocess_addr = val;
            }
            else if (key == "more_verbose")
            {
                params.more_verbose = (val == "1");
            }
            else
            {
                control->Output(DEBUG_OUTPUT_ERROR, "Unknown trace option: %s\n", key.c_str());
                control->Release();
                return E_INVALIDARG;
            }
        }

        control->Output(DEBUG_OUTPUT_NORMAL, "[trace] Tracing to %s (max %d steps)...\n",
                        params.end_address.c_str(), params.max_steps);

        std::string result = dbg_client.Trace(params);
        control->Output(DEBUG_OUTPUT_NORMAL, "%s\n", result.c_str());
    }
    else
    {
        control->Output(DEBUG_OUTPUT_ERROR, "Unknown subcommand: %s\n", subcmd.c_str());
        control->Output(DEBUG_OUTPUT_NORMAL, "Use '!agent help' for usage information.\n");
    }

    control->Release();
    return S_OK;
}

// !agent command - main entry point
extern "C" HRESULT CALLBACK agent(PDEBUG_CLIENT Client, PCSTR Args)
{
    return agent_impl(Client, Args);
}
