#ifndef __ATTACH_GUARD_HH
#define __ATTACH_GUARD_HH

#include "process_manager.hh"

namespace memory_tools {
class AttachGuard {
public:
  // Try to attach to process, track if we were the ones who attached
  explicit AttachGuard(ProcessManager &process);
  ~AttachGuard();

  bool Success() const;

private:
  ProcessManager &process_;
  bool should_detach_;
};
} // namespace memory_tools

#endif
