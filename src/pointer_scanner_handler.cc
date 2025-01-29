#include "pointer_scanner_handler.hh"
#include "pointer_scanner.hh"
#include <csignal>

#include <iostream>

namespace memory_tools {

namespace {
void HandleUsr1(int /*signo*/) {
  static PointerScanner scanner;

  // Refersh memory map before scanning
  if (!scanner.RefreshMemoryMap()) {
    std::cerr << "Failed to refresh memory map" << std::endl;
    return;
  }

  scanner.ScanForPointers([](uint64_t addr, uint64_t value) {
    std::cout << "Pointer at 0x" << std::hex << addr << ": 0x" << value
              << std::endl;
  });
}
} // namespace

bool InstallPointerScannerHandler() {
  struct sigaction sa = {};
  sa.sa_handler = HandleUsr1;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART; // Restart interrupted system calls
  return sigaction(SIGUSR1, &sa, nullptr) == 0;
}

} // namespace memory_tools
