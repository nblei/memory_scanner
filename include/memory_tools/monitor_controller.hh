#ifndef __MONITOR_CONTROLLER_HH__
#define __MONITOR_CONTROLLER_HH__

#include "cli.hh"
#include "error_injection.hh"
#include "process_manager.hh"
#include <atomic>

namespace memory_tools {
// Represents different modes the monitor can operate in
enum class MonitorMode { Periodic, Command };

struct MonitorConfig {
  std::chrono::milliseconds initial_delay{1000};
  std::chrono::milliseconds interval{1000};
  std::optional<size_t> iteration_limit{std::nullopt};
};

/**
 * @brief Controls process monitoring and error injection
 *
 * @details The MonitorController manages process attachment, memory scanning,
 * and error injection based on the configured monitoring mode.
 */
class MonitorController {
public:
  MonitorController(pid_t child_pid, const CommonOptions &opts,
                    MonitorMode mode, MonitorConfig config);

  // Non-copyable
  MonitorController(const MonitorController &) = delete;
  MonitorController &operator=(const MonitorController &) = delete;

  // Core monitoring functions
  bool StartMonitoring();

  // Mode specific configuration
  void SetDelay(std::chrono::milliseconds delay);
  void SetInterval(std::chrono::milliseconds interval);

private:
  // Core monitoring loop implementation
  bool RunMonitorLoop();

  // Mode specific monitoring implementations
  bool HandlePeriodicMode();
  bool HandleCommandMode();
  bool CheckChildRunning();

  // Command mode specific handlers
  bool ProcessCommand();
  bool HandleCheckpoint();
  bool HandleRestore();
  bool HandleInjectErrors();
  bool HandleScan();

  // Core components
  ProcessManager process_manager_;
  ErrorInjectionStrategy injection_strategy_;
  const size_t num_threads_;
  const MonitorMode mode_;
  const MonitorConfig config_;
};

} // namespace memory_tools

#endif
