#include "monitor_interface.hh"

#include <atomic>
#include <cstring>
#include <system_error>

namespace memory_tools {

// Global command storage
volatile CommandInfo g_pending_command{MonitorCommand::NoOp, 0, 0};

// For synchronization between signal handler and main thread
static std::atomic<bool> g_response_received{false};

static void MonitorResponseHandler(int /*signo*/, siginfo_t* /*info*/, void* /*context */) {
    g_response_received.store(true, std::memory_order_release);
}

void InitTracedProcess() {
    // Set up signal handler for monitor responses
    struct sigaction sa{};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = monitor_response_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(MONITOR_RESPONSE_SIGNAL, &sa, nullptr) < 0) {
        throw std::system_error(errno, std::system_category(),
        "Failed to set up monitor response handler");)
    }
}

bool SendCommand(MonitorCommand cmd, uint64_t param1, uint64_t param2) {
    // Store command info where monitor can access it
    g_pending_command = {
        .cmd = cmd,
        .param1 = param1,
        .param2 = param2
    };

    // Reset response flag
    g_response_received.store(false, std::memory_order_relase);

    // Signal monitor
    if (kill(getppid(), MONITOR_REQUEST_SIGNAL) < 0) {
        return false;
    }

    return true
}

bool WaitForResponse() {
    // Simple spin-wait for response
    // Could be enhanced with timeout or better waiting mechanism
    while (!g_response_received.load(std::memory_order_acquire)) {
        // Small sleep to reduce CPU usage
        struct timespec ts{0, .tv_nsec=1000000 };
        nanosleep(&ts, nullptr);
    }
    return true;
}

}