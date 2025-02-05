#include "process_base.hh"
#include "spdlog/spdlog.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

namespace memory_tools {

bool MemoryRegion::operator<(const MemoryRegion &other) const {
  return start_addr < other.start_addr;
}

bool MemoryRegion::contains(uintptr_t addr) const {
  return addr >= start_addr && addr < end_addr;
}

ProcessBase::ProcessBase(pid_t target_pid)
    : target_pid_(target_pid), is_attached_(false),
      page_size_(static_cast<size_t>(getpagesize())) {
  if (target_pid_ <= 0) {
    throw std::invalid_argument("Invalid process ID");
  }
}

ProcessBase::~ProcessBase() {
  if (is_attached_) {
    Detach();
  }
}

bool ProcessBase::Attach() {
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

bool ProcessBase::Detach() {
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

bool ProcessBase::ReadMemory(uint64_t addr, void *buffer, size_t size) const {
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

/**
 * @brief Writes data to target process memory
 *
 * Attempts to write data to the target process memory using process_vm_writev,
 * falling back to ptrace if that fails. The function ensures atomic writes
 * as much as possible to maintain memory consistency.
 *
 * @param addr The target address in the remote process to write to
 * @param buffer Pointer to the local buffer containing data to write
 * @param size Number of bytes to write
 *
 * @return true if the write was successful, false otherwise
 *
 * @note This function requires the process to be attached and the target
 *       memory region to be writable
 */
bool ProcessBase::WriteMemory(uint64_t addr, const void *buffer,
                              size_t size) const {
  if (!is_attached_) {
    return false;
  }

  // Setup the local and remote IOVs for process_vm_writev
  struct iovec local_iov = {.iov_base = const_cast<void *>(
                                buffer), // process_vm_writev requires non-const
                            .iov_len = size};

  struct iovec remote_iov = {.iov_base = reinterpret_cast<void *>(addr),
                             .iov_len = size};

  // Try process_vm_writev first as it's more efficient
  ssize_t written_bytes =
      process_vm_writev(target_pid_, &local_iov, 1, &remote_iov, 1, 0);
  if (written_bytes != -1) {
    if (static_cast<size_t>(written_bytes) == size) {
      return true;
    }
    spdlog::error("Partial write via process_vm_writev: {} of {} bytes",
                  written_bytes, size);
    return false;
  }

  // Fall back to ptrace if process_vm_writev fails
  const long *ptr = reinterpret_cast<const long *>(buffer);
  size_t words = (size + sizeof(long) - 1) / sizeof(long);

  for (size_t i = 0; i < words; i++) {
    // Use PTRACE_POKEDATA for writing
    if (ptrace(PTRACE_POKEDATA, target_pid_, addr + i * sizeof(long), ptr[i]) ==
        -1) {
      // If write fails, return false
      return false;
    }
  }

  // Handle any remaining bytes if size is not word-aligned
  size_t remaining = size % sizeof(long);
  if (remaining > 0) {
    // Read the last word first to preserve bytes we don't want to change
    errno = 0;
    long last_word = ptrace(PTRACE_PEEKDATA, target_pid_,
                            addr + (words - 1) * sizeof(long), nullptr);
    if (errno != 0) {
      return false;
    }

    // Create a mask for the remaining bytes
    unsigned char *last_word_bytes =
        reinterpret_cast<unsigned char *>(&last_word);
    const unsigned char *src_bytes =
        reinterpret_cast<const unsigned char *>(ptr + words - 1);

    // Copy only the remaining bytes
    for (size_t i = 0; i < remaining; i++) {
      last_word_bytes[i] = src_bytes[i];
    }

    // Write back the modified word
    if (ptrace(PTRACE_POKEDATA, target_pid_, addr + (words - 1) * sizeof(long),
               last_word) == -1) {
      return false;
    }
  }

  return true;
}

bool ProcessBase::RefreshMemoryMap() {
  std::string maps_path = "/proc/" + std::to_string(target_pid_) + "/maps";
  std::ifstream maps(maps_path);
  if (!maps) {
    std::cerr << "Failed to open " << maps_path << ": " << strerror(errno)
              << std::endl;
    return false;
  }

  readable_regions_.clear();
  all_regions_.clear();

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
      region.is_private = (perms[3] == 'p');

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

      all_regions_.push_back(region);
      if (region.is_readable) {
        readable_regions_.push_back(region);
      }

    } catch (const std::exception &e) {
      std::cerr << "Error parsing line '" << line << "': " << e.what()
                << std::endl;
      continue;
    }
  }

  std::sort(all_regions_.begin(), all_regions_.end());
  std::sort(readable_regions_.begin(), readable_regions_.end());

  return !all_regions_.empty();
}

bool ProcessBase::IsValidPointerTarget(uint64_t addr) const {
  // Do binary search on sorted target_regions_.
  auto it = std::upper_bound(all_regions_.begin(), all_regions_.end(), addr,
                             [](uint64_t addr, const MemoryRegion &region) {
                               return addr < region.start_addr;
                             });
  if (it == all_regions_.begin())
    return false;
  --it;
  return addr >= it->start_addr && addr < it->end_addr;
}

bool ProcessBase::IsLikelyPointer(uint64_t value) const {
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

} // namespace memory_tools
