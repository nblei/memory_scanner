#ifndef PROCESS_CHECKPOINT_HH
#define PROCESS_CHECKPOINT_HH

#include "process_scanner.hh"
#include <map>
#include <vector>

namespace memory_tools {

class ProcessCheckpoint {
public:
    explicit ProcessCheckpoint(pid_t pid);

    // Take checkpoint of the current process memory state
    bool CreateCheckpoint();

    // Restore process to last checkpoint
    bool RestoreCheckpoint();

    // Clear checkpoint data
    void clear();

private:
    struct MemoryChunk {
        uint64_t addr;
        std::vector<uint8_t> data;
    }

    pid_t pid_;
    std::vector<MemoryChunk> checkpoint_data_;
    std::vector<MemoryRegion> checkpoint_regions_;

    // Read process memory map
    bool RefreshMemoryMap();

    // Read/write helpers
    bool ReadMemory(uintptr_t addr, void* buffer, size_t size) const;
    bool WriteMemory(uintptr_t addr, void* buffer, size_t size) const;
};

} // namespace memory_tools
#endif