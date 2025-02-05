#include "process_checkpoint.hh"
#include "spdlog/spdlog.h"

namespace memory_tools {

ProcessCheckpoint::ProcessCheckpoint(pid_t pid) : ProcessBase(pid) {}

bool ProcessCheckpoint::CreateCheckpoint() {
  if (!IsAttached()) {
    spdlog::error("Unable to create checkpoint --- ptrace not attached");
    return false;
  }

  if (!RefreshMemoryMap()) {
    spdlog::error("Unable to RefreshMemoryMap");
    return false;
  }

  checkpoint_data_.clear();
  checkpoint_regions_ = GetReadableRegions();

  // Store each writable region
  for (const auto &region : checkpoint_regions_) {
    if (!region.is_writable) {
      spdlog::warn("Skipping non-writable region in CreateCheckpoint");
      continue;
    }

    MemoryChunk chunk;
    chunk.addr = region.start_addr;
    chunk.data.resize(region.end_addr - region.start_addr);

    if (!ReadMemory(chunk.addr, chunk.data.data(), chunk.data.size())) {
      Clear();
      spdlog::error("Unable to read target process memory");
      return false;
    }

    checkpoint_data_.push_back(std::move(chunk));
  }

  return true;
}

bool ProcessCheckpoint::RestoreCheckpoint() {
  if (!IsAttached()) {
    spdlog::error("Unable to restore checkpoint --- process not attached");
    return false;
  }
  if (checkpoint_data_.empty()) {
    spdlog::error("Unable to restore checkpoint --- no checkpoint exists");
    return false;
  }

  // Verify regions still match
  auto current_regions = GetReadableRegions();
  if (!std::equal(checkpoint_regions_.begin(), checkpoint_regions_.end(),
                  current_regions.begin(), current_regions.end(),
                  [](const MemoryRegion &a, const MemoryRegion &b) {
                    return a.start_addr == b.start_addr &&
                           a.end_addr == b.end_addr &&
                           a.is_writable == b.is_writable;
                  })) {
    return false;
  }

  // Restore each saved region
  for (const auto &chunk : checkpoint_data_) {
    if (!WriteMemory(chunk.addr, chunk.data.data(), chunk.data.size())) {
      spdlog::error(
          "Unable to write-back checkpoint to traced process' memory");
      return false;
    }
  }

  return true;
}

void ProcessCheckpoint::Clear() {
  checkpoint_data_.clear();
  checkpoint_regions_.clear();
}

} // namespace memory_tools
