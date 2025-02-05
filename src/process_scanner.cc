#include "process_scanner.hh"
#include "spdlog/spdlog.h"
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

ProcessScanner::ProcessScanner(pid_t target_pid, size_t num_threads)
    : ProcessBase(target_pid), num_threads_(num_threads) {
  if (num_threads == 0) {
    throw ::std::invalid_argument("Invalid number of threads (0)");
  }
}

/**
 * @brief Scans memory regions for potential pointers and collects statistics
 *
 * This method performs the core scanning logic for the ProcessScanner class.
 * For each memory page in the readable regions:
 * 1. Attempts to read the page into a local buffer
 * 2. If read fails, increments skipped bytes counter
 * 3. If read succeeds:
 *    - Examines each 8-byte aligned value as a potential pointer
 *    - Calls appropriate callback for pointer/non-pointer values
 *    - Updates various statistics (total bytes, readable/writable/executable
 * bytes)
 *
 * The method uses 8-byte alignment scanning since we're looking for 64-bit
 * pointers. It processes memory page by page to improve efficiency and reduce
 * memory usage.
 *
 * Statistics tracked include:
 * - Total bytes scanned
 * - Number of bytes that were readable/writable/executable
 * - Number of likely pointers found
 * - Number of bytes skipped due to read failures
 * - Total scan time in milliseconds
 *
 * @param is_pointer Callback function called for each value identified as
 * likely pointer Takes (address, value) parameters. If function returns `true`,
 *                  then the value at `address` will be transfered to target
 *                  process' memory.
 * @param not_pointer Callback function called for each value identified as not
 *                    a pointer Takes (address, value) parameters. If function
 * returns `true`, then the value at `address` will be transfered to target
 * process' memory.
 *
 * @throws std::runtime_error if scanner is not attached to target process
 *
 * @note Memory permissions (readable/writable/executable) are tracked per
 * region
 * @note Scan statistics are stored in last_scan_stats_ member variable
 */
void ProcessScanner::ScanForPointers(InjectionStrategy &strategy) {
  if (!is_attached_) {
    throw std::runtime_error("Not attached to target process");
  }

  if (!strategy.PreRunner()) {
    return;
  }

  auto start_time = std::chrono::steady_clock::now();
  ResetStats();
  strategy.PreRunner();

  // Divide regions among threads
  std::vector<std::vector<const MemoryRegion *>> thread_regions(num_threads_);
  for (size_t i = 0; i < scan_regions_.size(); i++) {
    thread_regions[i % num_threads_].push_back(&scan_regions_[i]);
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
  for (const auto &stats : thread_stats) {
    last_scan_stats_.total_bytes_scanned += stats.total_bytes_scanned;
    last_scan_stats_.bytes_readable += stats.bytes_readable;
    last_scan_stats_.bytes_writable += stats.bytes_writable;
    last_scan_stats_.bytes_executable += stats.bytes_executable;
    last_scan_stats_.bytes_skipped += stats.bytes_skipped;
    last_scan_stats_.pointers_found += stats.pointers_found;
    last_scan_stats_.regions_scanned += stats.regions_scanned;
  }

  strategy.PostRunner();

  auto end_time = std::chrono::steady_clock::now();
  last_scan_stats_.scan_time_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(end_time -
                                                            start_time)
          .count();
}

void ProcessScanner::ScanRegion(const MemoryRegion &region,
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

} // namespace memory_tools
