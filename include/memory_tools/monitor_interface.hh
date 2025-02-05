#ifndef MONITOR_INTERFACE_HH
#define MONITOR_INTERFACE_HH

#include <cstdint>
#include <signal.h>

namespace memory_tools {

// Commands that can be sent from traced process to monitor
enum class MonitorCommand : uint8_t {
    NoOp = 0,
    Checkpoint = 1, // Request a memory checkpiont
    Restore = 2, // Request a checkpoint restore
    InjectErrors = 3, // Request error injection
    Scan = 4,   // Request memory scan
};


// Used to pass command details through signal handler
struct CommandInfo {
    MonitorCommand cmd;
    uint64_t param1;  // Additional parameter (e.g., region ID)
    uint64_t param2;  // Additional parameter
};


// Global commandinfo (needs to be accesible in signal handler)
extern volatile CommandInfo g_pending_command;
constexpr int MONITOR_REQUEST_SIGNAL = SIGUSR1;  // Traced -> Monitor
constexpr int MONITOR_RESPONSE_SIGNAL = SIGUSR2;

// Initialize traced process side
void InitTracedProcess();

// Send command to monitor process
bool SendCommand(MonitorCommand cmd, uint64_t param1 = 0, uint64_t param2 = 0);

// Wait for monitor to ack cmmand completion
bool WaitForResponse();
} // namesapce memory_tools

#endif