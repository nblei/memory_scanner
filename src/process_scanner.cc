#include "process_scanner.hh"
#include <chrono>
#include <cstring>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

namespace memory_tools {

ProcessScanner::ProcessScanner(pid_t target_pid)
    : target_pid_(target_pid), is_attached_(false),
      page_size_(static_cast<size_t>(getpagesize())) {
  if (target_pid_ <= 0) {
    throw std::invalid_argument("Invalid process ID");
  }
}

ProcessScanner::~ProcessScanner() {
  if (is_attached_) {
    Detach();
  }
}

bool ProcessScanner::Attach() {
  if (is_attached_) {
    return true; // Already attached
  }

  if (ptrace(PTRACE_ATTACH, target_pid_, nullptr, nullptr) == -1) {
    std::cerr << "Failed to attach to process " << target_pid_ << ": "
              << strerror(errno) << std::endl;
    return false;
  }

  int status;

  if (waitpid(target_pid_, &status, 0) == -1) {
    std::cerr << "Failed to wait for process " << target_pid_ << ": "
              << strerror(errno) << std::endl;
    ptrace(PTRACE_DETACH, target_pid_, nullptr, nullptr);
    return false;
  }

  if (!WIFSTOPPED(status)) {
    std::cerr << "Process did not stop as expected" << std::endl;
    ptrace(PTRACE_DETACH, target_pid_, nullptr, nullptr);
    return false;
  } else {
    if (WSTOPSIG(status) == SIGTRAP) {
      // Handle exec's SIGTRAP
      ptrace(PTRACE_CONT, target_pid_, &status, 0);
      if (waitpid(target_pid_, &status, 0) == -1) {
        std::cerr << "Failed to wait for process " << target_pid_ << ": "
                  << strerror(errno) << std::endl;
        ptrace(PTRACE_DETACH, target_pid_, nullptr, nullptr);
        return false;
      }
      if (WIFSTOPPED(status)) {
        if (WSTOPSIG(status) != SIGSTOP) {
          std::cerr << "Unexpected stop signal" << std::endl;
          return false;
        }
      } else {
        std::cerr << "Process did not stop as expected" << std::endl;
        ptrace(PTRACE_DETACH, target_pid_, nullptr, nullptr);
        return false;
      }
    }
  }

  is_attached_ = true;
  return RefreshMemoryMap();
}

bool ProcessScanner::Detach() {
  if (!is_attached_) {
    return true; // Already detached
  }

  if (ptrace(PTRACE_DETACH, target_pid_, nullptr, nullptr) == -1) {
    std::cerr << "Failed to detach from process " << target_pid_ << ": "
              << strerror(errno) << std::endl;
    return false;
  }

  is_attached_ = false;
  return true;
}

bool ProcessScanner::ReadMemory(uint64_t addr, void *buffer, size_t size) {
  if (!is_attached_) {
    return false;
  }

  struct iovec local_iov = {.iov_base = buffer, .iov_len = size};

  struct iovec remote_iov = {.iov_base = reinterpret_cast<void *>(addr),
                             .iov_len = size};

  // Try process_vm_readv first
  ssize_t read_bytes =
      process_vm_readv(target_pid_, &local_iov, 1, &remote_iov, 1, 0);
  if (read_bytes != -1) {
    return static_cast<size_t>(read_bytes) == size;
  }

  // Fall back to ptrace if process_vm_readv fails
  long *ptr = reinterpret_cast<long *>(buffer);
  size_t words = (size + sizeof(long) - 1) / sizeof(long);

  for (size_t i = 0; i < words; i++) {
    errno = 0;
    ptr[i] =
        ptrace(PTRACE_PEEKDATA, target_pid_, addr + i * sizeof(long), nullptr);
    if (errno != 0) {
      return false;
    }
  }

  return true;
}

bool ProcessScanner::RefreshMemoryMap() {
  std::string maps_path = "/proc/" + std::to_string(target_pid_) + "/maps";
  std::ifstream maps(maps_path);
  if (!maps) {
    std::cerr << "Failed to open " << maps_path << ": " << strerror(errno)
              << std::endl;
    return false;
  }

  scan_regions_.clear();
  target_regions_.clear();

  std::string line;
  while (std::getline(maps, line)) {
    std::istringstream iss(line);
    std::string addr_range, perms, offset, dev, inode;

    if (!(iss >> addr_range >> perms)) {
      std::cerr << "Failed to parse line: " << line << std::endl;
      continue;
    }

    size_t dash_pos = addr_range.find('-');
    if (dash_pos == std::string::npos) {
      std::cerr << "Invalid address range: " << addr_range << std::endl;
      continue;
    }

    try {
      MemoryRegion region;
      region.start_addr =
          std::stoull(addr_range.substr(0, dash_pos), nullptr, 16);
      region.end_addr =
          std::stoull(addr_range.substr(dash_pos + 1), nullptr, 16);
      region.is_readable = (perms[0] == 'r');
      region.is_writable = (perms[1] == 'w');
      region.is_executable = (perms[2] == 'x');

      // Skip the offset, device, and inode
      iss >> offset >> dev >> inode;

      // Get mapping name (rest of the line)
      std::getline(iss, region.mapping_name);
      if (!region.mapping_name.empty()) {
        size_t first = region.mapping_name.find_first_not_of(" \t");
        if (first != std::string::npos) {
          region.mapping_name = region.mapping_name.substr(first);
        }
      }

      if (region.is_readable) {
        scan_regions_.push_back(region);
      }
      target_regions_.push_back(region);

    } catch (const std::exception &e) {
      std::cerr << "Error parsing line '" << line << "': " << e.what()
                << std::endl;
      continue;
    }
  }

  return !scan_regions_.empty();
}

bool ProcessScanner::IsValidPointerTarget(uint64_t addr) const {
  for (const auto &region : target_regions_) {
    if (addr >= region.start_addr && addr < region.end_addr) {
      return true;
    }
  }
  return false;
}

bool ProcessScanner::IsLikelyPointer(uint64_t value) const {
  // Quick checks first
  if (value == 0) {
    return false; // Null pointer
  }

  // Check alignment (most pointers are at least 2-byte aligned)
  if (value & 0x1) {
    return false;
  }

  // Check if high bits follow canonical form
  uint64_t high_bits = value & 0xffff000000000000;
  if (high_bits != 0 && high_bits != 0xffff000000000000) {
    return false;
  }

  return IsValidPointerTarget(value);
}

void ProcessScanner::ScanForPointers(const PointerCallback &callback) {
  if (!is_attached_) {
    throw std::runtime_error("Not attached to target process");
  }

  auto start_time = std::chrono::steady_clock::now();
  ResetStats();

  std::vector<uint8_t> buffer(page_size_);

  for (const auto &region : scan_regions_) {
    uint64_t current_addr = region.start_addr;
    last_scan_stats_.regions_scanned++;

    while (current_addr < region.end_addr) {
      size_t remaining = region.end_addr - current_addr;
      size_t to_read = std::min(remaining, page_size_);

      if (!ReadMemory(current_addr, buffer.data(), to_read)) {
        last_scan_stats_.bytes_skipped += to_read;
      } else {
        // Process the data looking for pointers
        for (size_t offset = 0; offset + sizeof(uint64_t) <= to_read;
             offset += sizeof(uint64_t)) {
          uint64_t value;
          std::memcpy(&value, buffer.data() + offset, sizeof(uint64_t));

          if (IsLikelyPointer(value)) {
            callback(current_addr + offset, value);
            last_scan_stats_.pointers_found++;
          }
        }
        last_scan_stats_.total_bytes_scanned += to_read;
      }
      current_addr += to_read;
    }
  }

  auto end_time = std::chrono::steady_clock::now();
  last_scan_stats_.scan_time_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(end_time -
                                                            start_time)
          .count();
}

} // namespace memory_tools
