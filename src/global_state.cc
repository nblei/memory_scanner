#include "global_state.hh"
#include "monitor_interface.hh"

namespace memory_tools {
volatile sig_atomic_t g_should_exit = 0;
} // namespace memory_tools
