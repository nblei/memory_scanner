// error_injection.hh
#ifndef __ERROR_INJECTION_HH__
#define __ERROR_INJECTION_HH__

#include "process_scanner.hh"
#include "spdlog/spdlog.h"
#include <chrono>
#include <random>

namespace memory_tools {

enum class ErrorType {
  BitFlip, // Flip random bits
  StuckAtZero,
  StuckAtOne,
};

enum class PointerType {
  Heap,   // [heap] region
  Stack,  // [stack] region
  Static, // Binary and library regions
  Unknown
};

struct ValueChange {
  uint64_t original;
  uint64_t modified;
  PointerType type;
  std::string region_name; // For tracking which region it came from
  std::chrono::steady_clock::time_point injection_time;
};

class ErrorInjectionStrategy : public InjectionStrategy {
public:
  struct RegionQuota {
    size_t heap_errors{0};
    size_t stack_errors{0};
    size_t static_errors{0};
    size_t wildcard_errors{0};

    // How many errors we want in each region
    size_t heap_quota{0};
    size_t stack_quota{0};
    size_t static_quota{0};
    size_t wildcard_quota{0};

    bool Available(PointerType type) const {
      bool wildcard_avail = wildcard_errors < wildcard_quota;
      switch (type) {
      case PointerType::Heap:
        return (heap_errors < heap_quota) || wildcard_avail;
      case PointerType::Stack:
        return (stack_errors < stack_quota) || wildcard_avail;
      case PointerType::Static:
        return (static_errors < static_quota) || wildcard_avail;
      default:
        return false;
      }
    }

    void Increment(PointerType type) {
      switch (type) {
      case PointerType::Heap:
        if (heap_quota == heap_errors) {
          wildcard_errors++;
        } else {
          heap_errors++;
        }
        break;
      case PointerType::Stack:
        if (stack_errors == stack_quota) {
          wildcard_errors++;
        } else {
          stack_errors++;
        }
        break;
      case PointerType::Static:
        if (static_errors == static_quota) {
          wildcard_errors++;
        } else {
          static_errors++;
        }
        break;
      default:
        break;
      }
    }
  };
  static constexpr size_t g_bits_per_byte = 8;

  ErrorInjectionStrategy(ErrorType type, double pointer_error_rate,
                         double non_pointer_error_rate, size_t error_limit,
                         uint64_t seed)
      : type_(type), pointer_error_rate_(pointer_error_rate),
        non_pointer_error_rate_(non_pointer_error_rate),
        rng_(seed ? seed
                  : static_cast<size_t>(std::chrono::system_clock::now()
                                            .time_since_epoch()
                                            .count())),
        dist_(0.0, 1.0), bit_dist_(0, sizeof(uintptr_t) * g_bits_per_byte - 1) {
    quota_.wildcard_quota = error_limit;
  }

  // For monitoring results
  const std::unordered_map<uint64_t, ValueChange> &get_changes() const {
    return changes_;
  }

  void SetCurrentRegion(const MemoryRegion &region) override {
    current_region_ = &region;
  }

  bool PreRunner() override { return true; }

  bool HandlePointer(uint64_t addr, uint64_t &value, bool writable) override {
    return inject_error(pointer_error_rate_, quota_, addr, value, writable);
  }

  bool HandleNonPointer(uint64_t addr, uint64_t &value,
                        bool writable) override {
    return inject_error(non_pointer_error_rate_, quota_, addr, value, writable);
  }

  bool PostRunner() override { return true; }

private:
  PointerType determine_pointer_type() const {
    if (!current_region_ || current_region_->mapping_name.empty()) {
      spdlog::debug("No region or empty mapping name");
      return PointerType::Unknown;
    }

    if (current_region_->mapping_name.find("[heap]") != std::string::npos) {
      return PointerType::Heap;
    }
    if (current_region_->mapping_name.find("[stack]") != std::string::npos) {
      return PointerType::Stack;
    }
    return PointerType::Static;
  }

  bool inject_error(double rate, RegionQuota &quota, uint64_t addr,
                    uint64_t &value, bool writable) {
    auto type = determine_pointer_type();
    if (!writable || dist_(rng_) > rate || !quota.Available(type)) {
      return false;
    }
    auto old_value = value;
    auto bit = bit_dist_(rng_);

    switch (type_) {
    case ErrorType::BitFlip:
      value ^= (1ULL << bit);
      break;
    case ErrorType::StuckAtZero:
      value &= ~(1ULL << bit_dist_(rng_));
      break;
    case ErrorType::StuckAtOne:
      value |= 1ULL << bit_dist_(rng_);
      break;
    }
    changes_[addr] = ValueChange{
        old_value,
        value,
        type,
        current_region_ ? current_region_->mapping_name : "unknown",
        std::chrono::steady_clock::now(),
    };
    spdlog::info("Injected {} error in {} region at {:#x}: {:#x} -> {:#x}",
                 type == PointerType::Heap     ? "heap"
                 : type == PointerType::Stack  ? "stack"
                 : type == PointerType::Static ? "static"
                                               : "unknown",
                 current_region_ ? current_region_->mapping_name : "unknown",
                 addr, old_value, value);

    quota.Increment(type);
    return true;
  }

  void check_value(uint64_t addr, uint64_t current_value) {
    auto it = changes_.find(addr);
    if (it != changes_.end()) {
      const auto &change = it->second;
      if (current_value == change.original) {
        spdlog::info("Address {:#x} reverted to original value {:#x}", addr,
                     change.original);
      } else if (current_value == change.modified) {
        spdlog::info("Address {:#x} retained modified value {:#x}", addr,
                     change.modified);
      } else {
        spdlog::info("Address {:#x} changed to new value {:#x} (was: "
                     "orig={:#x}, mod={:#x})",
                     addr, current_value, change.original, change.modified);
      }
    }
  }

  ErrorType type_;
  RegionQuota quota_;
  double pointer_error_rate_;
  double non_pointer_error_rate_;
  std::mt19937_64 rng_;
  std::uniform_real_distribution<double> dist_;
  std::uniform_int_distribution<int> bit_dist_;
  std::unordered_map<uint64_t, ValueChange> changes_;
  const MemoryRegion *current_region_{nullptr};
};

} // namespace memory_tools

#endif
