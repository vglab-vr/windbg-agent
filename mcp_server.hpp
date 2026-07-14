#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>

namespace windbg_agent {

// Callback for handling exec requests
using ExecCallback = std::function<std::string(const std::string& command)>;

// Internal command structure for cross-thread execution
struct MCPPendingCommand {
    std::string input;
    std::string result;
    bool completed = false;
    std::mutex* done_mutex = nullptr;
    std::condition_variable* done_cv = nullptr;
};

struct MCPQueueResult {
    bool success;
    std::string payload;
};

class MCPServer {
public:
    MCPServer();
    ~MCPServer();

    // Non-copyable
    MCPServer(const MCPServer&) = delete;
    MCPServer& operator=(const MCPServer&) = delete;

    // Start MCP server on given port with callback.
    // Returns actual port used. exec_cb is called on a background thread - no wait() needed.
    // bind_addr: "127.0.0.1" for localhost only, "0.0.0.0" for all interfaces
    int start(int port, ExecCallback exec_cb,
              const std::string& bind_addr = "127.0.0.1");

    // Block the calling thread until the server stops (optional; server runs headlessly without this)
    void wait();

    // Stop the server
    void stop();

    // Check if running
    bool is_running() const { return running_.load(); }

    // Get the port the server is listening on
    int port() const { return port_; }

    // Set interrupt check function (called during wait loop)
    void set_interrupt_check(std::function<bool()> check);

    // Queue a command for execution on the command thread (called by MCP tool handlers)
    MCPQueueResult queue_and_wait(const std::string& input);

private:
    std::function<bool()> interrupt_check_;
    std::atomic<bool> running_{false};
    std::thread command_thread_;
    std::string bind_addr_{"127.0.0.1"};
    int port_{0};

    // Command queue for cross-thread execution
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<MCPPendingCommand*> pending_commands_;

    // Callback stored for main thread execution
    ExecCallback exec_cb_;

    // Forward declaration - impl hides fastmcpp
    class Impl;
    std::unique_ptr<Impl> impl_;

    void run_command_loop();
    void complete_pending_commands(const std::string& result);
};

// Format MCP server info for display
std::string format_mcp_info(
    const std::string& target_name,
    unsigned long pid,
    const std::string& state,
    const std::string& url
);

} // namespace windbg_agent
