# WinDbg Agent

WinDbg/CDB extension that exposes the debugger via HTTP and MCP servers, letting external AI agents (Claude Code, Copilot, etc.) control debug sessions programmatically.

## Building

### Prerequisites
- Windows 10/11
- Visual Studio 2022 with C++ workload (2019 also works — [see below](#alternative-no-visual-studio-2022))
- CMake 3.20+
- Windows SDK (for dbgeng.h)

### Build Steps

```bash
# Clone with submodules
git clone --recursive https://github.com/0xeb/windbg-agent.git
cd windbg-agent

# Build for x64 (most common)
cmake --preset x64
cmake --build --preset x64

# Build for x86 (32-bit targets)
cmake --preset x86
cmake --build --preset x86
```

Output:
- **x64**: `build-x64/Release/windbg_agent.dll` and `windbg_agent.exe`
- **x86**: `build-x86/Release/windbg_agent.dll` and `windbg_agent.exe`

### Alternative: No Visual Studio 2022

If you have a different Visual Studio version or just the Build Tools, skip the presets and specify the generator manually:

```bash
# Visual Studio 2019 — x64
cmake -B build-x64 -G "Visual Studio 16 2019" -A x64
cmake --build build-x64 --config Release

# Visual Studio 2019 — x86 (32-bit targets)
cmake -B build-x86 -G "Visual Studio 16 2019" -A Win32
cmake --build build-x86 --config Release

# Ninja (works with any MSVC version — run from Developer Command Prompt)
cmake -B build-x64 -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-x64
```

> **Ninja x86 note**: For 32-bit Ninja builds, open the **x86 Native Tools Command Prompt** (instead of x64) so `cl.exe` targets Win32.

## Usage

### Loading the Extension

1. Open WinDbg and load a dump file or attach to a process
2. Load the extension:

```
.load C:\path\to\windbg_agent.dll
```

> **Note:** The extension DLL architecture must match the target. Use the x86 build when debugging 32-bit processes, and the x64 build for 64-bit processes.

### Commands

| Command | Description |
|---------|-------------|
| `!agent help` | Show help |
| `!agent version` | Show version |
| `!agent http [bind_addr]` | Start HTTP server (port auto-assigned) |
| `!agent mcp [bind_addr]` | Start MCP server for MCP-compatible clients |

### HTTP Server

Start an HTTP server to let external tools execute debugger commands:

```
!agent http                  # localhost only (default)
!agent http 0.0.0.0          # all interfaces (no auth — use with care)
```

The server prints the auto-assigned URL, endpoints, and usage examples. The output is also copied to the clipboard.

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/exec` | Execute a debugger command |
| GET | `/status` | Server status |
| POST | `/shutdown` | Stop the server |

**Examples:**

```bash
# Execute a debugger command
curl -X POST http://127.0.0.1:<port>/exec \
  -H "Content-Type: application/json" \
  -d '{"command": "kb"}'

# Python
import requests
r = requests.post('http://127.0.0.1:<port>/exec', json={'command': 'kb'})
print(r.json()['output'])
```

**Response format:**
```json
{"output": "...", "success": true}
```

### CLI Tool

A standalone HTTP client (`windbg_agent.exe`) for scripting against a running HTTP server:

```bash
windbg_agent.exe --url=http://127.0.0.1:<port> exec "kb"
windbg_agent.exe --url=http://127.0.0.1:<port> status
windbg_agent.exe --url=http://127.0.0.1:<port> shutdown
```

The URL defaults to `http://127.0.0.1:9999` or the `WINDBG_AGENT_URL` environment variable.

### MCP Server

Start an MCP (Model Context Protocol) server for MCP-compatible AI clients:

```
!agent mcp                   # localhost only (default)
!agent mcp 0.0.0.0           # all interfaces
```

Exposes a single `dbg_exec` tool. Add to your MCP client config:

```json
{
  "mcpServers": {
    "windbg-agent": {
      "url": "http://127.0.0.1:<port>/sse"
    }
  }
}
```

Before running a `dbg_exec` or HTTP `/exec` command, the agent checks whether
the target is running. If so, it requests a break and waits up to 10 seconds
before sending the command. Commands that resume execution (such as `g`, `t`,
and `p`) return after WinDbg accepts them; the next command will break the
target if it is still running.

### Screenshots

Start `!agent http` to let external tools control WinDbg:

![HTTP server start](assets/handoff_start.jpg)

The CLI executes commands remotely:

![CLI exec](assets/handoff_exec.jpg)

Claude Code controlling WinDbg via HTTP server — analyzing a crash:

![Claude Code controlling WinDbg](assets/handoff_claude_code.jpg)

## Author

Elias Bachaalany ([@0xeb](https://github.com/0xeb))

Pair-programmed with Claude Code and Codex.

## License

MIT
