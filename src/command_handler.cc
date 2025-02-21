#include "command_handler.hh"
#include "spdlog/spdlog.h"
#include <atomic>

namespace memory_tools {

namespace {
// Thread-safe storage for the last received command
std::atomic<void *> g_last_cmd_data;
std::atomic<bool> g_command_pending{false};
} // namespace

void HandleCommandSignal(int /* signo */, siginfo_t *info,
                         void * /* context */) {
  // spdlog::info("Received command signal");
  const char *msg = "HandleCommandSignal entered\n";
  (void)!write(STDERR_FILENO, msg, strlen(msg));
  if (!info->si_ptr) {
    // spdlog::error("Recieved signal with null data");
    const char *err = "Received signal with null data\n";
    (void)!write(STDERR_FILENO, err, strlen(err));
    return;
  }
  g_last_cmd_data.store(info->si_value.sival_ptr);
  g_command_pending.store(true, std::memory_order_release);
  // spdlog::info("Stored command data");
}

void HandleCommandSignal(CommandInfo &info) {
  // spdlog::info("Received command signal");
  const char *err = "Received signal with null data\n";
  (void)!write(STDERR_FILENO, err, strlen(err));
  g_last_cmd_data.store(reinterpret_cast<void *>(info.Pack().sival_ptr));
  g_command_pending.store(true, std::memory_order_release);
  // spdlog::info("Stored command data");
}

CommandInfo GetLastCommand() {
  CommandInfo cmd;
  cmd.Unpack(g_last_cmd_data.load(std::memory_order_acquire));
  return cmd;
}

bool IsCommandPending() {
  return g_command_pending.load(std::memory_order_acquire);
}

void ClearCommandPending() {
  g_command_pending.store(false, std::memory_order_release);
}

bool SendResponse(pid_t target_pid) {
  spdlog::info("Sending response to pid {}", target_pid);
  union sigval value;
  value.sival_ptr = nullptr; // Could use this to send status codes if needed

  if (sigqueue(target_pid, MONITOR_RESPONSE_SIGNAL, value) < 0) {
    spdlog::error("Failed to send response signal: {}", strerror(errno));
    return false;
  }
  spdlog::info("Response signal sent succesfully");
  return true;
}

} // namespace memory_tools
