#ifndef __COMMAND_HANDLER_HH__
#define __COMMAND_HANDLER_HH__

#include "monitor_interface.hh"
#include <signal.h>

namespace memory_tools {
// Used to pass command details through signal handler

// Handle incoming command signal
void HandleCommandSignal(int signo, siginfo_t *info, void *context);
void HandleCommandSignal(CommandInfo &info);

// Get the last recv'ed command
CommandInfo GetLastCommand();

// Check if there's a pending command
bool IsCommandPending();

// Clear the pending command flag
void ClearCommandPending();

// Send response back to traced process
bool SendResponse(pid_t target_pid);

} // namespace memory_tools

#endif
