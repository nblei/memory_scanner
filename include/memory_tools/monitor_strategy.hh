#ifndef __MONITORING_STRATEGY_HH__
#define __MONITORING_STRATEGY_HH__

#include "cli.hh"
#include "error_injection.hh"
#include <csignal>
#include <sys/wait.h>
namespace memory_tools {

// Abstract base class for monitoring strategies.
class MonitoringStrategy {
public:
  explicit MonitoringStrategy(pid_t child_pid, const CommonOptions &opts)
      : manager_(child_pid), injection_strategy_(opts),
        num_threads_(opts.num_threads) {}
  virtual ~MonitoringStrategy() = default;

  virtual bool MonitoringProcess();

protected:
  virtual bool _ShouldContinue() = 0;
  virtual void BeforeMonitoring() = 0;
  virtual void AfterScan() = 0;
  virtual void MonitoringIteration();

  pid_t ChildPid() const { return manager_.GetPid(); }
  bool ShouldContinue() { return _ShouldContinue() && CheckChildRunning(); }

  ProcessManager manager_; // Owns the process management
  ErrorInjectionStrategy injection_strategy_;
  const size_t num_threads_;

private:
  bool CheckChildRunning() {
    int status;
    pid_t result = waitpid(ChildPid(), &status, WNOHANG);
    if (result == -1) {
      spdlog::error("Error checking child process: {}", strerror(errno));
      return false;
    } else if (result > 0) {
      spdlog::info("Child process terminated");
      return false;
    }
    return true;
  }
};

// Strategy for periodic scanning
class PeriodicMonitoringStrategy : public MonitoringStrategy {
  unsigned interval_ms_;

public:
  explicit PeriodicMonitoringStrategy(unsigned interval_ms, pid_t child_pid,
                                      const CommonOptions &opts)
      : MonitoringStrategy(child_pid, opts), interval_ms_(interval_ms) {}

protected:
  void BeforeMonitoring() override;
  bool _ShouldContinue() override;
  void AfterScan() override;
};

// Strategy for single scan with delay
class OnceMonitoringStrategy : public MonitoringStrategy {
  unsigned delay_ms_;
  bool scan_completed_ = false;

public:
  explicit OnceMonitoringStrategy(unsigned delay_ms, pid_t child_pid,
                                  const CommonOptions &opts)
      : MonitoringStrategy(child_pid, opts), delay_ms_(delay_ms) {}

protected:
  void BeforeMonitoring() override;
  bool _ShouldContinue() override;
  void AfterScan() override;
};

// Strategy for Command Handling
class CommandMonitoringStrategy : public MonitoringStrategy {
public:
  CommandMonitoringStrategy(pid_t child_pid, const CommonOptions &opts);

protected:
  void BeforeMonitoring() override { /* noop */ };
  bool _ShouldContinue() override { return true; };
  void AfterScan() override;
  void MonitoringIteration() override;

private:
  bool ProcessCommand();
  bool HandleCheckpoint();
  bool HandleRestore();
  bool HandleInjectErrors();
  bool HandleScan();
};

} // namespace memory_tools
#endif
