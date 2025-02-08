#ifndef __INJECTION_STRATEGY_HH__
#define __INJECTION_STRATEGY_HH__
#include "process_manager.hh"
#include <cstdint>

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
} // namespace memory_tools

#endif
