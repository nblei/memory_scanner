#ifndef PROCESS_BASE_HH
#define PROCESS_BASE_HH

#include <cstdint>
#include <string>
#include <sys/types.h>
#include <vector>

namespace memory_tools {

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

class ProcessBase {
public:
  explicit ProcessBase(pid_t target_pid);
  virtual ~ProcessBase();

  // Prevent copying
  ProcessBase(const ProcessBase &) = delete;
  ProcessBase &operator=(const ProcessBase &) = delete;

  // Core process management
  bool Attach();
  bool Detach();
  bool IsAttached() const { return is_attached_; }
  pid_t GetPid() const { return target_pid_; }

protected:
  // Memory access methods available to derived classes
  bool ReadMemory(uint64_t addr, void *buffer, size_t size) const;
  bool WriteMemory(uint64_t addr, const void *buffer, size_t size) const;

  // Memory map management
  bool RefreshMemoryMap();

  // Memory regions access for derived classes
  const std::vector<MemoryRegion> &GetReadableRegions() const {
    return readable_regions_;
  }
  const std::vector<MemoryRegion> &GetAllRegions() const {
    return all_regions_;
  }

  // Pointer validation helpers
  bool IsValidPointerTarget(uint64_t addr) const;
  bool IsLikelyPointer(uint64_t value) const;

  // System information
  size_t GetPageSize() const { return page_size_; }

  std::vector<MemoryRegion> readable_regions_; // Regions we can read from
  std::vector<MemoryRegion> all_regions_;      // All memory regions

private:
  pid_t target_pid_;
  bool is_attached_;
  size_t page_size_;
};

} // namespace memory_tools

#endif // PROCESS_BASE_HH
