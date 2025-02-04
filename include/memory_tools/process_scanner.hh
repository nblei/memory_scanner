#ifndef __PROCESS_SCANNER_HH__
#define __PROCESS_SCANNER_HH__

#include <cstdint>
#include <iomanip>
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
  bool is_private;
  std::string mapping_name; // e.g., "[heap]", "[stack]", etc.
};

struct InjectionStrategy {
  virtual bool PreRunner() { return true; };
  virtual bool HandlePointer(uint64_t addr, uint64_t &value, bool writable) {
    (void)addr;
    (void)value;
    (void)writable;
    return false;
  }
  virtual bool HandleNonPointer(uint64_t addr, uint64_t &value, bool writable) {
    (void)addr;
    (void)value;
    (void)writable;
    return false;
  }
  virtual bool PostRunner() { return true; }
  virtual void SetCurrentRegion(const MemoryRegion & /* region */) {}
};

struct ScanStats {
  uint64_t total_bytes_scanned{0};
  uint64_t bytes_readable{0};
  uint64_t bytes_writable{0};
  uint64_t bytes_executable{0};
  uint64_t regions_scanned{0};
  uint64_t pointers_found{0};
  uint64_t bytes_skipped{0};
  int64_t scan_time_ms{0};
  friend std::ostream &operator<<(std::ostream &os, const ScanStats &stats) {
    double percent =
        100. * (sizeof(uintptr_t) * static_cast<double>(stats.pointers_found)) /
        static_cast<double>(stats.bytes_readable - stats.bytes_executable);
    os << "Scan Statistics:\n"
       << std::dec << "  Regions scanned:         " << stats.regions_scanned
       << "\n"
       << "  Total bytes scanned:     " << stats.total_bytes_scanned << " ("
       << (static_cast<double>(stats.total_bytes_scanned) / (1024.0 * 1024.0))
       << " MB)\n"
       << "  Readable bytes:          " << stats.bytes_readable << " ("
       << (static_cast<double>(stats.bytes_readable) / (1024.0 * 1024.0))
       << " MB)\n"
       << "  Writable bytes:          " << stats.bytes_writable << " ("
       << (static_cast<double>(stats.bytes_writable) / (1024.0 * 1024.0))
       << " MB)\n"
       << "  Executable bytes:        " << stats.bytes_executable << " ("
       << (static_cast<double>(stats.bytes_executable) / (1024.0 * 1024.0))
       << " MB)\n"
       << "  Bytes skipped:           " << stats.bytes_skipped << " ("
       << (static_cast<double>(stats.bytes_skipped) / (1024.0 * 1024.0))
       << " MB)\n"
       << "  Pointers found:          " << stats.pointers_found << "\n"
       << "  Pointers as % of memory: " << std::setprecision(2) << percent
       << "%\n"
       << "  Scan time:               " << stats.scan_time_ms << " ms";
    return os;
  }
};

class ProcessScanner {
public:
  explicit ProcessScanner(pid_t target_pid);
  ~ProcessScanner();

  // Prevent copying and assignment
  ProcessScanner(const ProcessScanner &) = delete;
  ProcessScanner &operator=(const ProcessScanner &) = delete;

  // Core functionality
  bool Attach();
  bool Detach();
  void ScanForPointers(InjectionStrategy &);

  // Statistics
  const ScanStats &GetLastScanStats() const { return last_scan_stats_; }
  void ResetStats() { last_scan_stats_ = ScanStats(); }

private:
  // Memory reading functions
  bool ReadMemory(uint64_t addr, void *buffer, size_t size);
  bool WriteMemory(uint64_t addr, const void *buffer, size_t size);
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
