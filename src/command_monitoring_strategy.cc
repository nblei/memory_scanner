#include "attach_guard.hh"
#include "command_handler.hh"
#include "monitor_interface.hh"
#include "monitor_strategy.hh"

namespace memory_tools {

CommandMonitoringStrategy::CommandMonitoringStrategy(pid_t child_pid,
                                                     const CommonOptions &opts)
    : MonitoringStrategy(child_pid, opts) {}

bool CommandMonitoringStrategy::ProcessCommand() {
  // Read command info from traced process
  spdlog::info("Processing Command");
  CommandInfo cmd_info = GetLastCommand();

  // Create attach guard which will handle attach/detach
  AttachGuard guard(manager_);
  if (!guard.Success()) {
    spdlog::error("Failed to attach to process for command processing");
    return false;
  }

  bool success = true;
  switch (cmd_info.cmd) {
  case memory_tools::MonitorCommand::NoOp:
    spdlog::info("Handling NoOp");
    break;
  case memory_tools::MonitorCommand::Checkpoint:
    success = HandleCheckpoint();
    break;
  case memory_tools::MonitorCommand::Restore:
    success = HandleRestore();
    break;
  case memory_tools::MonitorCommand::InjectErrors:
    success = HandleInjectErrors();
    break;
  case memory_tools::MonitorCommand::Scan:
    success = HandleScan();
    break;
  }

  if (!SendResponse(ChildPid())) {
    spdlog::error("Failed to signal command completion");
  } else {
    spdlog::info("Sent response signal");
  }
  if (!success) {
    spdlog::error("Command processing failed");
  }

  return success;
}
bool CommandMonitoringStrategy::HandleScan() {
  auto stats = manager_.ScanForPointers(injection_strategy_, num_threads_);
  if (stats.has_value()) {
    std::stringstream ss;
    ss << stats.value();
    spdlog::info(ss.str());
  } else {
    spdlog::error("Unable to scan for pointers");
  }
  return true;
}

bool CommandMonitoringStrategy::HandleCheckpoint() {
  spdlog::info("Creating Checkpoint");
  return manager_.CreateCheckpoint();
}

bool CommandMonitoringStrategy::HandleRestore() {
  spdlog::info("Restoring from checkpoint");
  return manager_.RestoreCheckpoint();
}

bool CommandMonitoringStrategy::HandleInjectErrors() {
  spdlog::info("Injecting errors (if applicable)");
  manager_.ScanForPointers(injection_strategy_, num_threads_);
  return true;
}

void CommandMonitoringStrategy::AfterScan() {
  // Small sleep to prevent CPU spinning
  static constexpr struct timespec ts{0, 10000000}; // 10 ms
  nanosleep(&ts, nullptr);
}

void CommandMonitoringStrategy::MonitoringIteration() {
  // spdlog::info("MonitoringIteration entered");
  // For command-based monitoring, we only act when there's a command
  if (IsCommandPending()) {
    spdlog::info("Received command signal");
    ClearCommandPending();
    ProcessCommand();
  }
}

} // namespace memory_tools
