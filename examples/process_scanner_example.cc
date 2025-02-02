#include "process_scanner.hh"
#include <iomanip>
#include <iostream>
#include <set>
#include <string>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <target_pid>\n";
    return 1;
  }

  pid_t target_pid = std::stoi(argv[1]);

  try {
    memory_tools::ProcessScanner scanner(target_pid);

    std::cout << "Attaching to process " << target_pid << "...\n";
    if (!scanner.Attach()) {
      std::cerr << "Failed to attach to process\n";
      return 1;
    }

    // Keep track of unique pointers found
    std::set<uint64_t> unique_pointers;

    std::cout << "Beginning memory scan...\n";
    scanner.ScanForPointers([&unique_pointers](uint64_t addr, uint64_t value) {
      unique_pointers.insert(value);
      std::cout << std::hex << "Found pointer at 0x" << addr << " -> 0x"
                << value << "\n";
    });

    // Print statistics
    const auto &stats = scanner.GetLastScanStats();
    std::cout << std::dec << "\nScan Statistics:\n"
              << "  Regions scanned:     " << stats.regions_scanned << "\n"
              << "  Total bytes scanned: " << stats.total_bytes_scanned << " ("
              << (static_cast<double>(stats.total_bytes_scanned) / 1024.0 /
                  1024.0)
              << " MB)\n"
              << "  Bytes skipped:       " << stats.bytes_skipped << " ("
              << (static_cast<double>(stats.bytes_skipped) / 1024.0 / 1024.0)
              << " MB)\n"
              << "  Pointers found:      " << stats.pointers_found << "\n"
              << "  Unique pointers:     " << unique_pointers.size() << "\n"
              << "  Scan time:           " << stats.scan_time_ms << " ms\n";

    std::cout << "Detaching from process...\n";
    scanner.Detach();

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
