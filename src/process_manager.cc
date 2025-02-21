#include "process_manager.hh"
#include "injection_strategy.hh"
#include "spdlog/spdlog.h"
#include <algorithm>
#include <criu/criu.h>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <sys/ptrace.h>
#include <sys/stat.h>
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

ProcessManager::ProcessManager(pid_t target_pid)
    : target_pid_(target_pid), is_attached_(false),
      page_size_(static_cast<size_t>(getpagesize())) {
  if (target_pid_ <= 0) {
    throw std::invalid_argument("Invalid process ID");
  }
}

ProcessManager::~ProcessManager() {
  if (is_attached_) {
    Detach();
  }
}

bool ProcessManager::Attach() {
  if (is_attached_) {
    return true; // Already attached
  }
  spdlog::info("Attaching Process");

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

bool ProcessManager::Detach() {
  if (!is_attached_) {
    return true; // Already detached
  }

  spdlog::info("Detaching process");
  if (ptrace(PTRACE_DETACH, target_pid_, nullptr, nullptr) == -1) {
    std::cerr << "Failed to detach from process " << target_pid_ << ": "
              << strerror(errno) << std::endl;
    return false;
  }

  is_attached_ = false;
  return true;
}

bool ProcessManager::ReadMemory(uint64_t addr, void *buffer,
                                size_t size) const {
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
bool ProcessManager::WriteMemory(uint64_t addr, const void *buffer,
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

bool ProcessManager::RefreshMemoryMap() {
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

bool ProcessManager::IsValidPointerTarget(uint64_t addr) const {
  // Do binary search on sorted target_regions_.
  auto it = std::upper_bound(all_regions_.begin(), all_regions_.end(), addr,
                             [](uint64_t addr_, const MemoryRegion &region) {
                               return addr_ < region.start_addr;
                             });
  if (it == all_regions_.begin())
    return false;
  --it;
  return addr >= it->start_addr && addr < it->end_addr;
}

bool ProcessManager::IsLikelyPointer(uint64_t value) const {
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

bool ProcessManager::CreateCheckpoint() {
  bool attached = IsAttached();
  bool retval = false;
  // Set directory for checkpoint files
  std::string checkpoint_dir = CheckpointDir();
  int dir_fd;

  if (attached) {
    if (!Detach()) {
      spdlog::error("Failed to detach from process before checkpoint");
      goto done;
    }
  }

  // Create (if needed) directory, allocate file descriptor
  if (mkdir(checkpoint_dir.c_str(), 0777) < 0 && errno != EEXIST) {
    spdlog::error("Failed to create checkpoint directory: {}", strerror(errno));
    goto cond_reattach;
  }
  dir_fd = open(checkpoint_dir.c_str(), O_DIRECTORY);
  if (dir_fd < 0) {
    spdlog::error("Failed to open checkpoint directory: {}", strerror(errno));
    goto cond_reattach;
  }

  if (int ret = criu_init_opts(); ret < 0) {
    spdlog::error("Failed to initialize CRIU options");
    goto close_fd;
  }

  criu_set_work_dir_fd(dir_fd);

  // Set basic options
  criu_set_pid(target_pid_);
  criu_set_shell_job(true);     // Handle process groups
  criu_set_leave_running(true); // Don't kill after checkpoint

  // Log Options
  criu_set_log_level(4);
  criu_set_log_file(std::format("criu_log_{}.txt", target_pid_).c_str());

  criu_set_track_mem(false);       // No need for incremental checkpointing
  criu_set_auto_dedup(false);      // We want to preseve exact memory pages
  criu_set_ext_unix_sk(false);     // Don't try to checkpoint unix sockets
  criu_set_file_locks(false);      // Don't try to checkpoint file locks
  criu_set_tcp_established(false); // Don't try to checkpoint TCP connections
  criu_set_images_dir_fd(dir_fd);
  criu_set_ghost_limit(0);     // Disable ghost file support
  criu_set_force_irmap(false); // Don't force inode remap

  if (int ret = criu_dump(); ret != 0) {
    spdlog::error("CRIU dump failed: {}", strerror(-ret));
    goto cond_reattach;
  }
  retval = true;

close_fd:
  close(dir_fd);
cond_reattach:
  if (attached) {
    if (!Attach()) {
      spdlog::error("Failed to reattach process after checkpoint");
    }
  }
done:
  return retval;
}

std::string ProcessManager::CheckpointDir() const {
  return fmt::format("/tmp/checkpoint_{}", target_pid_);
}

bool ProcessManager::RestoreCheckpoint() {
  bool attached = IsAttached();
  bool retval = false;
  std::string checkpoint_dir = CheckpointDir();
  int dir_fd;

  if (access(checkpoint_dir.c_str(), F_OK) == -1) {
    spdlog::error("Checkpoint directory does not exist");
    goto done;
  }

  if (attached) {
    if (!Detach()) {
      spdlog::error(
          "Failed to detach from process before restoring checkpoint");
      goto done;
    }
  }

  if (dir_fd = open(checkpoint_dir.c_str(), O_DIRECTORY); dir_fd < 0) {
    spdlog::error("Failed to open checkpoint directory: {}", strerror(errno));
    goto cond_reattach;
  }

  if (criu_init_opts() < 0) {
    spdlog::error("Failed to initialize CRIU options");
    goto close_fd;
  }

  criu_set_images_dir_fd(dir_fd);

  if (int ret = criu_restore(); ret < 0) {
    spdlog::error("CRIU restore failed: {}", strerror(-ret));
    goto close_fd;
  }

  retval = true;
close_fd:
  close(dir_fd);
cond_reattach:
  if (attached) {
    if (!Attach()) {
      spdlog::error("Failed to reattach process after checkpoint restoration");
    }
  }
done:
  return retval;
}

std::optional<ScanStats>
ProcessManager::ScanForPointers(InjectionStrategy &strategy,
                                size_t num_threads_) {
  if (!IsAttached()) {
    throw std::runtime_error("Not attached to target process");
  }

  if (!strategy.PreRunner()) {
    return {};
  }

  auto start_time = std::chrono::steady_clock::now();
  ScanStats stats;
  strategy.PreRunner();

  // Divide regions among threads
  const auto &regions = readable_regions_;
  std::vector<std::vector<const MemoryRegion *>> thread_regions(num_threads_);
  for (size_t i = 0; i < regions.size(); i++) {
    thread_regions[i % num_threads_].push_back(&regions[i]);
  }

  // Create per-thread stats and syncrhonization
  std::vector<ScanStats> thread_stats(num_threads_);

  // Launch threads
  std::vector<std::thread> threads;
  for (size_t thread_id = 0; thread_id < num_threads_; ++thread_id) {
    threads.emplace_back(
        [this, thread_id, &thread_regions, &thread_stats, &strategy]() {
          for (const MemoryRegion *region : thread_regions[thread_id]) {
            ScanRegion(*region, strategy, thread_stats[thread_id]);
            thread_stats[thread_id].regions_scanned++;
          }
        });
  }

  // Wait for all threads
  for (auto &thread : threads) {
    thread.join();
  }

  // Merge stats
  for (const auto &thread_stat : thread_stats) {
    stats.total_bytes_scanned += thread_stat.total_bytes_scanned;
    stats.bytes_readable += thread_stat.bytes_readable;
    stats.bytes_writable += thread_stat.bytes_writable;
    stats.bytes_executable += thread_stat.bytes_executable;
    stats.bytes_skipped += thread_stat.bytes_skipped;
    stats.pointers_found += thread_stat.pointers_found;
    stats.regions_scanned += thread_stat.regions_scanned;
  }

  strategy.PostRunner();

  auto end_time = std::chrono::steady_clock::now();
  stats.scan_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                           end_time - start_time)
                           .count();
  return stats;
}

void ProcessManager::ScanRegion(const MemoryRegion &region,
                                InjectionStrategy &strategy,
                                ScanStats &local_stats) {
  std::vector<uint8_t> buffer(page_size_);
  uint64_t current_addr = region.start_addr;

  while (current_addr < region.end_addr) {
    size_t remaining = region.end_addr - current_addr;
    size_t to_read = std::min(remaining, page_size_);

    if (!ReadMemory(current_addr, buffer.data(), to_read)) {
      local_stats.bytes_skipped += to_read;
    } else {
      bool write_back = false;

      for (size_t offset = 0; offset + sizeof(uint64_t) <= to_read;
           offset += sizeof(uint64_t)) {
        uint64_t value;
        std::memcpy(&value, buffer.data() + offset, sizeof(uint64_t));

        bool modified = false;
        if (IsLikelyPointer(value)) {
          modified = strategy.HandlePointer(current_addr + offset, value,
                                            region.is_writable, region);
          local_stats.pointers_found++;
        } else {
          modified = strategy.HandleNonPointer(current_addr + offset, value,
                                               region.is_writable, region);
        }

        if (modified) {
          write_back = true;
          std::memcpy(buffer.data() + offset, &value, sizeof(value));
        }
      }

      local_stats.total_bytes_scanned += to_read;
      local_stats.bytes_readable += to_read;
      if (region.is_writable) {
        local_stats.bytes_writable += to_read;
      }
      if (region.is_executable) {
        local_stats.bytes_executable += to_read;
      }

      if (write_back && region.is_writable) {
        WriteMemory(current_addr, buffer.data(), to_read);
      }
    }
    current_addr += to_read;
  }
}

std::ostream &operator<<(std::ostream &os, const ScanStats &stats) {
  double percent =
      100. * (sizeof(uintptr_t) * static_cast<double>(stats.pointers_found)) /
      static_cast<double>(stats.bytes_readable - stats.bytes_executable);
  os << "Scan Statistics:\n"
     << std::dec << "  Regions scanned:         " << stats.regions_scanned
     << "\n"
     << "  Total bytes scanned:     " << stats.total_bytes_scanned << " ("
     << (static_cast<double>(stats.total_bytes_scanned) / (1024.0 * 1024.0))
     << " MB)\n"
     << "  Readable bytes:          " << stats.bytes_readable << " ("
     << (static_cast<double>(stats.bytes_readable) / (1024.0 * 1024.0))
     << " MB)\n"
     << "  Writable bytes:          " << stats.bytes_writable << " ("
     << (static_cast<double>(stats.bytes_writable) / (1024.0 * 1024.0))
     << " MB)\n"
     << "  Executable bytes:        " << stats.bytes_executable << " ("
     << (static_cast<double>(stats.bytes_executable) / (1024.0 * 1024.0))
     << " MB)\n"
     << "  Bytes skipped:           " << stats.bytes_skipped << " ("
     << (static_cast<double>(stats.bytes_skipped) / (1024.0 * 1024.0))
     << " MB)\n"
     << "  Pointers found:          " << stats.pointers_found << "\n"
     << "  Pointers as % of memory: " << std::setprecision(2) << percent
     << "%\n"
     << "  Scan time:               " << stats.scan_time_ms << " ms";
  return os;
}

} // namespace memory_tools
