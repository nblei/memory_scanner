#include "attach_guard.hh"
#include "global_state.hh"
#include "monitor_strategy.hh"
#include "spdlog/spdlog.h"

namespace memory_tools {
void MonitoringStrategy::MonitoringIteration() {
  AttachGuard guard(manager_);

  if (guard.Success()) {
    auto stats = manager_.ScanForPointers(injection_strategy_, num_threads_);
    if (stats.has_value()) {
      std::stringstream ss;
      ss << stats.value();
      spdlog::info(ss.str());
    } else {
      spdlog::error("Unable to scan for pointers");
    }
  } else {
    spdlog::error("Unable to attach to process {}", ChildPid());
  }
}

bool MonitoringStrategy::MonitoringProcess() {
  BeforeMonitoring();

  while (ShouldContinue()) {
    MonitoringIteration();
    AfterScan();
  }

  return true;
}

void PeriodicMonitoringStrategy::BeforeMonitoring() {
  spdlog::info("Starting periodic scan with {} ms interval", interval_ms_);
}

bool PeriodicMonitoringStrategy::_ShouldContinue() { return !g_should_exit; }

void PeriodicMonitoringStrategy::AfterScan() {
  std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms_));
}

void OnceMonitoringStrategy::BeforeMonitoring() {
  spdlog::info("Waiting {}ms before scanning", delay_ms_);
  std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms_));
}

bool OnceMonitoringStrategy::_ShouldContinue() { return !scan_completed_; }

void OnceMonitoringStrategy::AfterScan() { scan_completed_ = true; }

} // namespace memory_tools
