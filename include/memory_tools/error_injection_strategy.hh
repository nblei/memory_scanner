#ifndef __ERROR_INJECTION_HH__
#define __ERROR_INJECTION_HH__

#include "memory_region.hh"
#include <chrono>
#include <optional>
#include <random>
#include <unordered_map>

namespace memory_tools {

enum class ErrorType {
  BitFlip,
  StuckAtZero,
  StuckAtOne,
};

struct ValueChange {
  uint64_t original;
  uint64_t modified;
  PointerType type;
  std::string region_name;
  std::chrono::steady_clock::time_point injection_time;
};

class ErrorInjectionStrategy {
public:
  // Public configuration fields
  ErrorType type_{ErrorType::BitFlip};
  // If double - then represents error rate.  If size_t, then repressents number
  // of errors to inject
  size_t pointer_error_amount_;
  size_t nonpointer_error_amount_;

  // State management
  const std::unordered_map<uint64_t, ValueChange> &GetChanges() const;
  void Reset();

private:
  void InitRng();

  // Private implementation state
  std::optional<size_t> pointer_remaining_errors_;
  std::optional<size_t> nonpointer_remaining_errors_;
  std::mt19937_64 rng_{static_cast<size_t>(
      std::chrono::system_clock::now().time_since_epoch().count())};
  std::uniform_real_distribution<double> dist_{0.0, 1.0};
  std::uniform_int_distribution<int> bit_dist_{0, sizeof(uintptr_t) * 8 - 1};
  std::unordered_map<uint64_t, ValueChange> changes_;

  // Pre-selected injection points
  std::vector<size_t> pointer_injection_points_;
  std::vector<size_t> nonpointer_injection_points_;
  size_t current_pointer_point_{0};
  size_t current_nonpointer_point_{0};
  size_t pointer_position_{0};
  size_t nonpointer_position_{0};
};

} // namespace memory_tools
#endif
