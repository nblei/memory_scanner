#ifndef __PROCESS_MONITOR_GLOBAL_STATE_HH__
#define __PROCESS_MONITOR_GLOBAL_STATE_HH__

#include <csignal>
namespace memory_tools {
extern volatile sig_atomic_t g_should_exit;
} // namespace memory_tools
#endif
