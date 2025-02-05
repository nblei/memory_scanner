#ifndef __PROCESS_SCANNER_HH__
#define __PROCESS_SCANNER_HH__

#include "process_base.hh"
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sys/types.h>
#include <vector>

namespace memory_tools {

struct InjectionStrategy {
  virtual bool PreRunner() { return true; };
  virtual bool HandlePointer(uint64_t addr, uint64_t &value, bool writable,
                             const MemoryRegion &) {
    (void)addr;
    (void)value;
    (void)writable;
    return false;
  }
  virtual bool HandleNonPointer(uint64_t addr, uint64_t &value, bool writable,
                                const MemoryRegion &) {
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

class ProcessScanner : public ProcessBase {
public:
  ProcessScanner(pid_t target_pid, size_t num_threads = 4);

  // Core Scanning functionality
  void ScanForPointers(InjectionStrategy &strategy);

  // Statistics
  const ScanStats &GetLastScanStats() const { return last_scan_stats_; }
  void ResetStats() { last_scan_stats_ = ScanStats(); }

private:
  // For prallel processing
  void ScanRegion(const MemoryRegion &region, InjectionStrategy &strategy,
                  ScanStats &local_stats);

  // Process state
  pid_t target_pid_;
  bool is_attached_;
  size_t page_size_;

  // Memory regions
  std::vector<MemoryRegion> scan_regions_;   // Regions we should scan
  std::vector<MemoryRegion> target_regions_; // Valid pointer targets

  size_t num_threads_;

  // Statistics
  ScanStats last_scan_stats_;
};

} // namespace memory_tools

#endif
