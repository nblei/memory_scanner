#ifndef __POINTER_SCANNER_HH__
#define __POINTER_SCANNER_HH__

#include <csetjmp>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
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

// Statisitics about the most recent scan
struct ScanStats {
  uint64_t total_bytes_scanned{0};
  uint64_t regions_scanned{0};
  uint64_t pointers_found{0};
  uint64_t bytes_skipped{0};
  int64_t scan_time_ms{0};
  friend std::ostream &operator<<(std::ostream &os, const ScanStats &);
};

// Scans process memolry to identify likely pointers
class PointerScanner {
public:
  const ScanStats &GetLastScanStats() const { return last_scan_stats_; }
  void ResetStats() { last_scan_stats_ = ScanStats(); }
  using PointerCallback = std::function<void(uint64_t addr, uint64_t value)>;

  PointerScanner();
  ~PointerScanner() = default;

  // Scan memory for pointers, calling callback for each found.
  // callback: Function to call for each pointer found.
  void ScanForPointers(const PointerCallback &callback);

  // Updates internal memory map from /proc/self/maps
  // Returns false if maps couldn't be read.
  bool RefreshMemoryMap();

  // Test if a value is likely a valid pointer.
  // value: The potential pointer value to test.
  // Returns: true if value matches pointer heuristics.
  bool IsLikelyPointer(uint64_t value) const;

private:
  // Parse a single line from /proc/self/maps.
  // line: A line from /proc/self/maps file
  // Returns: Parameter for parsed region if parsing succeeds
  std::optional<MemoryRegion> ParseMapsLine(const std::string &line);

  // Check if address points to a valid memory region.
  // addr: Address to check
  // Returns: true if address is in a valid target region.
  bool IsValidPointerTarget(uint64_t addr) const;

  // Last ScanStats
  ScanStats last_scan_stats_;

  static uint64_t GetSystemPageSize();

  // Regions we should scan for pointers.
  std::vector<MemoryRegion> scan_regions_;

  // Regions that pointers might legitimately target.
  std::vector<MemoryRegion> target_regions_;

  // Scans a single region for pointers
  void ScanRegion(const MemoryRegion &region, const PointerCallback &callback);

  size_t page_size_;
  size_t page_mask_;
  sigjmp_buf jbuf_;
};

} // namespace memory_tools

#endif
