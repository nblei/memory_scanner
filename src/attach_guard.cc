#include "attach_guard.hh"

namespace memory_tools {
AttachGuard::AttachGuard(ProcessManager &process)
    : process_(process), should_detach_(false) {
  if (!process.IsAttached()) {
    should_detach_ = process.Attach();
  }
}

AttachGuard::~AttachGuard() {
  if (should_detach_) {
    process_.Detach();
  }
}

bool AttachGuard::Success() const { return process_.IsAttached(); }
} // namespace memory_tools
