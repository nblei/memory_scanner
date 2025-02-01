#include "pointer_scanner.hh"
#include <chrono>
#include <csignal>
#include <fstream>
#include <iostream>
#include <ostream>
#include <thread>

namespace {
// Use volatile sig_atomic_t for maximum portability
volatile sig_atomic_t g_scan_requested = 0;
std::atomic<bool> g_scanner_running{false};

void signal_handler(int) { g_scan_requested = 1; }

// Worker thread function that performs the actual scanning
void scanner_worker() {
  // Pre-allocate scanner instance outside signal context
  memory_tools::PointerScanner scanner;

  while (g_scanner_running.load(std::memory_order_acquire)) {
    if (g_scan_requested) {
      // Get timestamp before scan
      auto start_time = std::chrono::steady_clock::now();

      // Perform scan
      scanner.RefreshMemoryMap();
      scanner.ScanForPointers([](uint64_t /* addr */, uint64_t /* value */) {});

      // Get time delta
      auto now = std::chrono::steady_clock::now();
      auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
          now - start_time);

      std::ofstream log("memory_scan.log", std::ios::app);
      auto stats = scanner.GetLastScanStats();
      log << "\n=== Scan Report ===\n"
          << "PID: " << getpid() << "\n"
          << "TID: " << std::this_thread::get_id() << "\n"
          << "Scan Duration: " << delta.count() << "ms\n"
          << stats << "\n"
          << "==================\n";
      log.close();

      // Reset scan request flag
      g_scan_requested = 0;
    }

    // Sleep briefly to avoid spinning
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

// RAII helper to manage scanner thread lifecycle
class ScannerThread {
public:
  ScannerThread() {
    g_scanner_running.store(true, std::memory_order_release);
    thread_ = std::thread(scanner_worker);
  }

  ~ScannerThread() {
    g_scanner_running.store(false, std::memory_order_release);
    if (thread_.joinable()) {
      thread_.join();
    }
  }

private:
  std::thread thread_;
};

// Static instance to manage thread lifetime
static ScannerThread g_scanner_thread;

} // namespace

extern "C" void __attribute__((constructor)) attach_scanner() {
  struct sigaction sa = {};
  sa.sa_handler = signal_handler;
  sa.sa_flags = SA_RESTART; // Restart interrupted system calls
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, nullptr);
}
