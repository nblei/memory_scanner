#ifndef MONITOR_INTERFACE_HH
#define MONITOR_INTERFACE_HH

#include <cstdint>
#include <signal.h>

namespace memory_tools {

// Commands that can be sent from traced process to monitor
enum class MonitorCommand : uint8_t {
  NoOp = 0,
  Checkpoint = 1,   // Request a memory checkpiont
  Restore = 2,      // Request a checkpoint restore
  InjectErrors = 3, // Request error injection
  Scan = 4,         // Request memory scan
};

struct CommandInfo {
  MonitorCommand cmd;
  uint64_t param1; // Additional parameter (e.g., region ID)
  uint64_t param2; // Additional parameter

  CommandInfo(MonitorCommand cmd_, uint64_t param1_, uint64_t param2_)
      : cmd(cmd_), param1(param1_), param2(param2_) {}
  CommandInfo() : CommandInfo(MonitorCommand::NoOp, 0, 0) {}

  // Construct from signal value
  explicit CommandInfo(union sigval value) {
    uint64_t packed = reinterpret_cast<uint64_t>(value.sival_ptr);
    cmd = static_cast<MonitorCommand>(packed >> CMD_SHIFT);
    param1 = (packed >> PARAM1_SHIFT) & PARAM_MASK;
    param2 = packed & PARAM_MASK;
  }

  // Pack command and parameters into a single uint64_t
  // Format: [cmd: 8 bits][param1: 28 bits][param2: 28 bits]
  union sigval Pack() {
    void *ptr = reinterpret_cast<void *>(
        (static_cast<uint64_t>(cmd) << CMD_SHIFT) |
        ((param1 & PARAM_MASK) << PARAM1_SHIFT) | (param2 & PARAM_MASK));
    union sigval ret;
    ret.sival_ptr = ptr;
    return ret;
  }

  // Unpack command data
  void Unpack(union sigval value) { Unpack(value.sival_ptr); }

  void Unpack(void *value) {
    uint64_t packed_ = reinterpret_cast<uint64_t>(value);
    cmd = static_cast<MonitorCommand>(packed_ >> CMD_SHIFT);
    param1 = (packed_ >> PARAM1_SHIFT) & PARAM_MASK;
    param2 = packed_ & PARAM_MASK;
  }

private:
  static constexpr uint64_t PARAM_MASK = (1ULL << 28) - 1;
  static constexpr uint64_t CMD_SHIFT = 56;
  static constexpr uint64_t PARAM1_SHIFT = 28;
};

class CommandData {
  // Pack command
public:
};

constexpr int MONITOR_REQUEST_SIGNAL = SIGUSR1; // Traced -> Monitor
constexpr int MONITOR_RESPONSE_SIGNAL = SIGUSR2;

// Initialize traced process side
void InitTracedProcess();

// Send command to monitor process
bool SendCommand(MonitorCommand cmd, uint64_t param1 = 0, uint64_t param2 = 0);

// Wait for monitor to ack command completion
bool WaitForResponse();
} // namespace memory_tools

#endif
