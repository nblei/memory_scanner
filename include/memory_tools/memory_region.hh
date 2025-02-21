#ifndef __MEMORY_REGION_HH__
#define __MEMORY_REGION_HH__
#include <cstdint>
#include <string>

enum class PointerType {
  Heap,   // [heap] region
  Stack,  // [stack] region
  Static, // Binary and library regions
  Unknown
};

// Memory region information
struct MemoryRegion {
  uint64_t start_addr;
  uint64_t end_addr;
  bool is_readable;
  bool is_writable;
  bool is_executable;
  bool is_private;
  std::string mapping_name;

  bool operator<(const MemoryRegion &other) const {
    return start_addr < other.start_addr;
  }

  bool contains(uintptr_t addr) const {
    return addr >= start_addr && addr < end_addr;
  }

  PointerType DeterminePointerType() const {
    if (mapping_name.empty()) {
      return PointerType::Unknown;
    }
    if (mapping_name.find("[heap]") != std::string::npos) {
      return PointerType::Heap;
    }
    if (mapping_name.find("[stack]") != std::string::npos) {
      return PointerType::Stack;
    }
    return PointerType::Static;
  }
};

struct RegionStats {
  const MemoryRegion *region;
  size_t pointer_count{0};
  size_t nonpointer_count{0};
  uint64_t region_start; // For efficient location calculation later
};

#endif
