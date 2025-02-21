#ifndef PROCESS_BASE_HH
#define PROCESS_BASE_HH

#include <cstdint>
#include <optional>
#include <string>
#include <sys/types.h>
#include <sys/user.h>
#include <vector>

namespace memory_tools {

struct InjectionStrategy;

// Memory region information (moved from process_scanner.hh)
struct MemoryRegion {
  uint64_t start_addr;
  uint64_t end_addr;
  bool is_readable;
  bool is_writable;
  bool is_executable;
  bool is_private;
  std::string mapping_name;

  bool operator<(const MemoryRegion &other) const;
  bool contains(uintptr_t addr) const;
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
  friend std::ostream &operator<<(std::ostream &os, const ScanStats &stats);
};

class ProcessManager {
public:
  explicit ProcessManager(pid_t target_pid);
  virtual ~ProcessManager();

  // Prevent copying
  ProcessManager(const ProcessManager &) = delete;
  ProcessManager &operator=(const ProcessManager &) = delete;

  // Core process management
  bool Attach();
  bool Detach();
  bool IsAttached() const { return is_attached_; }
  // Returns PID of traced process
  pid_t GetPid() const { return target_pid_; }

  // Memory access methods available to derived classes
  bool ReadMemory(uint64_t addr, void *buffer, size_t size) const;
  bool WriteMemory(uint64_t addr, const void *buffer, size_t size) const;
  bool RefreshMemoryMap();

  // Scanner functionality
  std::optional<ScanStats> ScanForPointers(InjectionStrategy &strategy,
                                           size_t num_threads_);

  // Checkpoint Functionality
  bool CreateCheckpoint();
  bool RestoreCheckpoint();

private:
  struct MemoryChunk {
    uint64_t addr;
    std::vector<uint8_t> data;
    size_t size() const { return data.size(); }
  };

  // Pointer validation helpers
  bool IsValidPointerTarget(uint64_t addr) const;
  bool IsLikelyPointer(uint64_t value) const;
  void ScanRegion(const MemoryRegion &region, InjectionStrategy &strategy,
                  ScanStats &stats);
  std::string CheckpointDir() const;

  pid_t target_pid_;
  bool is_attached_;
  size_t page_size_;
  std::vector<MemoryRegion> readable_regions_; // Regions we can read from
  std::vector<MemoryRegion> all_regions_;      // All memory regions
};

} // namespace memory_tools

#endif // PROCESS_BASE_HH
