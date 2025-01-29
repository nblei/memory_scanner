#include "pointer_scanner.hh"

#include <chrono>
#include <csetjmp>
#include <csignal>
#include <fcntl.h>
#include <iostream>
#include <ostream>
#include <sys/mman.h>
#include <unistd.h>

#include <fstream>
#include <sstream>

namespace memory_tools {

namespace {
constexpr uint64_t kMinimumAlignment = sizeof(uintptr_t);
constexpr uint64_t kCanonicalFormMask = 0xffff000000000000;
constexpr uint64_t kCanonicalFormZero = 0x0000000000000000;
constexpr uint64_t kCanonicalFormOnes = 0xffff000000000000;
} // namespace

PointerScanner::PointerScanner()
    : page_size_(GetSystemPageSize()), page_mask_(~(page_size_ - 1)) {
  RefreshMemoryMap();
}

uint64_t PointerScanner::GetSystemPageSize() {
  long result = sysconf(_SC_PAGESIZE);
  if (result == -1) {
    // This should never happen
    return 4096;
  }
  return static_cast<uint64_t>(result);
}

std::optional<MemoryRegion>
PointerScanner::ParseMapsLine(const std::string &line) {
  std::istringstream iss(line);
  std::string addr_range;
  std::string perms;
  std::string offset;
  std::string dev;
  std::string inode;

  if (!(iss >> addr_range >> perms)) {
    return {};
  }
  size_t dash_pos = addr_range.find('-');
  if (dash_pos == std::string::npos) {
    return {};
  }
  MemoryRegion region;
  region.start_addr = std::stoull(addr_range.substr(0, dash_pos), nullptr, 16);
  region.end_addr = std::stoull(addr_range.substr(dash_pos + 1), nullptr, 16);

  // Parse permissions
  region.is_readable = (perms[0] == 'r');
  region.is_writable = (perms[1] == 'w');
  region.is_executable = (perms[2] == 'x');

  // Skip to mapping name (last field)
  std::getline(iss >> offset >> dev >> inode, region.mapping_name);
  // Trim leading whitespace
  region.mapping_name.erase(0, region.mapping_name.find_first_not_of(" \t"));

  return region;
}

bool PointerScanner::RefreshMemoryMap() {
  std::ifstream maps("/proc/self/maps");
  if (!maps) {
    return false;
  }

  scan_regions_.clear();
  target_regions_.clear();

  std::string line;
  while (std::getline(maps, line)) {
    auto opt_region = ParseMapsLine(line);

    if (!opt_region.has_value()) {
      continue;
    }
    auto region = std::move(opt_region.value());

    // Add readable regions to scan list
    if (region.is_readable) {
      scan_regions_.push_back(region);
    }

    // All regions are potential targets
    target_regions_.push_back(region);
  }
  return true;
}

bool PointerScanner::IsValidPointerTarget(uint64_t addr) const {
  for (const auto &region : target_regions_) {
    // If this is a stack region, add some padding
    uint64_t start = region.start_addr;
    uint64_t end = region.end_addr;
    if (region.mapping_name.find("[stack]") != std::string::npos) {
      // Add 1MB padding for stack growth
      start -= 1024 * 1024;
      end += 1024 * 1024;
    }
    if (addr >= start && addr < end) {
      return true;
    }
  }
  return false;
}

bool PointerScanner::IsLikelyPointer(uint64_t value) const {
  // Check null pointer - may be a pointer, but is not in use.
  if (value == 0) {
    return false;
  }

  // Check alignment
  bool is_aligned =
      (value & 0x7) == 0 || (value & 0x3) == 0 || (value & 0x1) == 0;
  if (!is_aligned) {
    return false;
  }

  // Check canonical form
  uint64_t high_bits = value & kCanonicalFormMask;
  if (high_bits != kCanonicalFormOnes && high_bits != kCanonicalFormZero) {
    return false;
  }

  // Consider Refresh on each check - might be too expensive, though
  // const_cast<PointerScanner*>(this)->RefreshMemoryMap();
  return IsValidPointerTarget(value);
}

void PointerScanner::ScanForPointers(const PointerCallback &callback) {
  auto start_time = std::chrono::steady_clock::now();
  ResetStats();

  // Set uip signal handling once at the start
  struct sigaction sa, old_sa_segv, old_sa_bus;
  static sigjmp_buf jbuf;
  sa.sa_handler = [](int) { siglongjmp(jbuf, 1); };
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if (sigaction(SIGSEGV, &sa, &old_sa_segv) == -1 ||
      sigaction(SIGBUS, &sa, &old_sa_bus) == -1) {
    std::cerr << "sigaction failed with erno: " << errno << std::endl;
    return;
  }

  const uint64_t kAlignment = 8;

  for (const auto &region : scan_regions_) {
    last_scan_stats_.regions_scanned++;
    // Align up
    uint64_t current_addr =
        (region.start_addr + kAlignment - 1) & ~(kAlignment - 1);
    // Align down
    uint64_t region_end = region.end_addr & ~(kAlignment - 1);

    while (current_addr < region_end) {
      if (sigsetjmp(jbuf, 1) == 0) {
        uint64_t value = *reinterpret_cast<volatile uint64_t *>(current_addr);
        if (IsLikelyPointer(value)) {
          callback(current_addr, value);
          last_scan_stats_.pointers_found++;
        }
        last_scan_stats_.total_bytes_scanned += kMinimumAlignment;
        current_addr += kMinimumAlignment;
      } else {
        // On SIGSEGV/SIGBUS, skip to next page
        uint64_t next_page = (current_addr + page_size_) & page_mask_;
        last_scan_stats_.bytes_skipped += (next_page - current_addr);
        current_addr = next_page;
        if (current_addr < region.start_addr || current_addr >= region_end) {
          break;
        }
      }
    }
  }
  // Restore old signal handler
  sigaction(SIGSEGV, &old_sa_segv, nullptr);
  sigaction(SIGSEGV, &old_sa_bus, nullptr);
  auto end_time = std::chrono::steady_clock::now();
  last_scan_stats_.scan_time_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(end_time -
                                                            start_time)
          .count();
}

std::ostream &operator<<(std::ostream &os, const ScanStats &stats) {
  os << "Scan Statistics:\n"
     << "  Regions scanned:     " << stats.regions_scanned << "\n"
     << "  Total bytes scanned: " << stats.total_bytes_scanned << " ("
     << (static_cast<double>(stats.total_bytes_scanned) / (1024.0 * 1024.0))
     << " MB)\n"
     << "  Bytes skipped:       " << stats.bytes_skipped << " ("
     << (static_cast<double>(stats.bytes_skipped) / (1024.0 * 1024.0))
     << " MB)\n"
     << "  Pointers found:      " << stats.pointers_found << "\n"
     << "  Scan time:           " << stats.scan_time_ms << " ms";
  return os;
}

} // namespace memory_tools
