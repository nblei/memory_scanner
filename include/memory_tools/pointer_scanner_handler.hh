#ifndef __POINTER_SCANNER_HANDLER_HH__
#define __POINTER_SCANNER_HANDLER_HH__
#include <csignal>

namespace memory_tools {
// Installs signal handler for SIGUSR1 that scans for pointers.
// Returns: true if handler was sucessfully installed.
bool InstallPointerScannerHandler();
} // namespace memory_tools
#endif
