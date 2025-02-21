#include "monitor_controller.hh"
#include "attach_guard.hh"
#include "command_handler.hh"
#include <sys/wait.h>
#include <thread>

namespace memory_tools {

MonitorController::MonitorController(pid_t child_pid, const CommonOptions &opts,
                                     MonitorMode mode, MonitorConfig config)
    : process_manager_(child_pid), injection_strategy_(opts),
      num_threads_(opts.num_threads), mode_(mode), config_(config) {}

bool MonitorController::StartMonitoring() { return RunMonitorLoop(); }

bool MonitorController::CheckChildRunning() {
  int status;
  if (pid_t result = waitpid(process_manager_.GetPid(), &status, WNOHANG);
      result == -1) {
    spdlog::error("Error checking child process: {}", strerror(errno));
    return false;
  } else if (result > 0) {
    spdlog::info("Child process terminated");
    return false;
  } else {
    return true;
  }
}

bool MonitorController::RunMonitorLoop() {
  switch (mode_) {
  case MonitorMode::Periodic:
    return HandlePeriodicMode();
    break;
  case MonitorMode::Command:
    return HandleCommandMode();
    break;
  }
  __builtin_unreachable();
}

bool MonitorController::HandlePeriodicMode() {
  // Initial delay if specified
  if (config_.initial_delay > std::chrono::milliseconds{0}) {
    std::this_thread::sleep_for(config_.initial_delay);
  }

  size_t iterations = 0;
  while (CheckChildRunning()) {
    {
      AttachGuard guard(process_manager_);
      if (!guard.Success()) {
        spdlog::error("Unable to attach to process {}",
                      process_manager_.GetPid());
        return false;
      }
      auto stats =
          process_manager_.ScanForPointers(injection_strategy_, num_threads_);
      if (!stats.has_value()) {
        return false;
      }

      std::stringstream ss;
      ss << stats.value();
      spdlog::info(ss.str());

      iterations++;
      if (config_.iteration_limit && iterations >= *config_.iteration_limit) {
        break;
      }
    }

    std::this_thread::sleep_for(config_.interval);
  }
  return true;
}

bool MonitorController::HandleCommandMode() {
  while (CheckChildRunning()) {
    if (IsCommandPending()) {
      spdlog::info("Received command signal");
      ClearCommandPending();
      if (!ProcessCommand()) {
        return false;
      }
    }

    // Small sleep to prevent CPU spinning
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return true;
}

// Command handling implementations
bool MonitorController::ProcessCommand() {
  CommandInfo cmd_info = GetLastCommand();
  AttachGuard guard(process_manager_);

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

  if (!SendResponse(process_manager_.GetPid())) {
    spdlog::error("Failed to signal command completion");
  } else {
    spdlog::info("Sent response signal");
  }
  if (!success) {
    spdlog::error("Command processing failed");
  }

  return success;
}

bool MonitorController::HandleScan() {
  auto stats =
      process_manager_.ScanForPointers(injection_strategy_, num_threads_);
  if (stats.has_value()) {
    std::stringstream ss;
    ss << stats.value();
    spdlog::info(ss.str());
  } else {
    spdlog::error("Unable to scan for pointers");
  }
  return true;
}

bool MonitorController::HandleCheckpoint() {
  spdlog::info("Creating Checkpoint");
  return process_manager_.CreateCheckpoint();
}

bool MonitorController::HandleRestore() {
  spdlog::info("Restoring from checkpoint");
  return process_manager_.RestoreCheckpoint();
}

bool MonitorController::HandleInjectErrors() {
  spdlog::info("Injecting errors (if applicable)");
  process_manager_.ScanForPointers(injection_strategy_, num_threads_);
  return true;
}

} // namespace memory_tools
