#ifndef __PROCESS_SCANNER_HH__
#define __PROCESS_SCANNER_HH__

#include <cstdint>
#include <functional>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <vector>

namespace memory_tools {

struct MemoryRegion {
  uint64_t start_addr;
  uint64_t end_addr;
  bool is_readable;
  bool is_writable;
  bool is_executable;
  std::string mapping_name; // e.g., "[heap]", "[stack]", etc.
};

struct ScanStats {
  uint64_t total_bytes_scanned{0};
  uint64_t regions_scanned{0};
  uint64_t pointers_found{0};
  uint64_t bytes_skipped{0};
  int64_t scan_time_ms{0};
  friend std::ostream &operator<<(std::ostream &os, const ScanStats &stats) {
    os << "Scan Statistics:\n"
       << std::dec << "  Regions scanned:     " << stats.regions_scanned << "\n"
       << "  Total bytes scanned: " << stats.total_bytes_scanned << " ("
       << (static_cast<double>(stats.total_bytes_scanned) / (1024.0 * 1024.0))
       << " MB)\n"
       << "  Bytes skipped:       " << stats.bytes_skipped << " ("
       << (static_cast<double>(stats.bytes_skipped) / (1024.0 * 1024.0))
       << " MB)\n"
       << "  Pointers found:      " << stats.pointers_found << "\n"
       << "  Scan time:           " << stats.scan_time_ms << " ms";
    return os;
  }
};

class ProcessScanner {
public:
  using PointerCallback = std::function<void(uint64_t addr, uint64_t value)>;

  explicit ProcessScanner(pid_t target_pid);
  ~ProcessScanner();

  // Prevent copying and assignment
  ProcessScanner(const ProcessScanner &) = delete;
  ProcessScanner &operator=(const ProcessScanner &) = delete;

  // Core functionality
  bool Attach();
  bool Detach();
  void ScanForPointers(const PointerCallback &callback);

  // Statistics
  const ScanStats &GetLastScanStats() const { return last_scan_stats_; }
  void ResetStats() { last_scan_stats_ = ScanStats(); }

private:
  // Memory reading functions
  bool ReadMemory(uint64_t addr, void *buffer, size_t size);
  bool RefreshMemoryMap();
  bool IsValidPointerTarget(uint64_t addr) const;
  bool IsLikelyPointer(uint64_t value) const;

  // Process state
  pid_t target_pid_;
  bool is_attached_;
  size_t page_size_;

  // Memory regions
  std::vector<MemoryRegion> scan_regions_;   // Regions we should scan
  std::vector<MemoryRegion> target_regions_; // Valid pointer targets

  // Statistics
  ScanStats last_scan_stats_;
};

} // namespace memory_tools

#endif
