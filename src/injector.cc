#include "pointer_scanner.hh"
#include <chrono>
#include <csignal>
#include <fstream>
#include <iostream>
#include <ostream>
#include <unordered_map>

extern "C" void __attribute__((constructor)) attach_scanner() {
  struct sigaction sa = {};
  sa.sa_handler = [](int) {
    using time_type = decltype(std::chrono::high_resolution_clock::now());
    static std::unordered_map<pid_t, time_type> s_ids;
    memory_tools::PointerScanner scanner;

    // Get start time of process
    pid_t pid = getpid();
    time_type start_time;
    auto it = s_ids.find(pid);
    if (s_ids.end() == it) {
      start_time = std::chrono::high_resolution_clock::now();
      s_ids.insert(std::make_pair(pid, start_time));
    } else {
      start_time = it->second;
    }

    // Get time delta
    time_type now = std::chrono::high_resolution_clock::now();
    auto delta =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);

    std::ofstream log("memory_scan.log", std::ios::app);
    scanner.ScanForPointers([&](uint64_t addr, uint64_t value) {
      (void)addr;
      (void)value;
    });
    auto stats = scanner.GetLastScanStats();
    log << std::dec << std::endl
        << "PID " << pid << " @" << delta << ":" << std::endl
        << stats << std::endl;
  };
  sigaction(SIGUSR1, &sa, nullptr);
}
