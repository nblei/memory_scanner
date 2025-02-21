#include "cli.hh"
#include "command_handler.hh"
#include "monitor_controller.hh"
#include "monitor_interface.hh"
#include <CLI/CLI.hpp>
#include <cstring>
#include <ctime>
#include <signal.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
using namespace memory_tools;
// Global state for coordination
pid_t g_child_pid = 0;

void handle_child_signal(int /*signo*/, siginfo_t *info, void * /*context*/) {
  if (info->si_pid == g_child_pid) {
    // Check for SEGFAULT
    if (info->si_signo == SIGSEGV) {
      spdlog::info("Child process segfaulted - will atempt restore");
      // Handle restore through command mechanism
      CommandInfo cmd{MonitorCommand::Restore, 0, 0};
      HandleCommandSignal(cmd);
    }
  }
}

// void signal_handler(int) { g_should_exit = 1; }

void setup_signal_handlers() {
  struct sigaction sa = {};
  spdlog::info("Setting up signal handlers");
  spdlog::info("MONITOR_REQUEST_SIGNAL = {}", MONITOR_REQUEST_SIGNAL);
  spdlog::info("MONITOR_RESPONSE_SIGNAL = {}", MONITOR_RESPONSE_SIGNAL);

  // Handler for commands from traced process
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = HandleCommandSignal;
  sigemptyset(&sa.sa_mask);
  if (sigaction(MONITOR_REQUEST_SIGNAL, &sa, nullptr) < 0) {
    spdlog::error("Failed to register MONITOR_REQUEST_SIGNAL handler: {}",
                  strerror(errno));
  } else {
    spdlog::info("Registered MONITOR_REQUEST_SIGNAL handler");
  }
  // Handler for child process signals
  sa.sa_sigaction = handle_child_signal;
  if (sigaction(SIGSEGV, &sa, nullptr) < 0) {
    spdlog::error("Failed to register SIGSEGV handler: {}", strerror(errno));
  } else {
    spdlog::info("Registered SIGSEGV handler");
  }
}

} // namespace

int main(int argc, char *argv[]) {
  // Main program setup
  CLI::App app{"Process Monitor - analyzes process memory for pointers"};
  RunPeriodicOptions periodic_opts;
  RunCommandOptions cmd_opts;

  auto subcmds = CreateCli(app, periodic_opts, cmd_opts);

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError &e) {
    return app.exit(e);
  }

  const bool is_periodic = subcmds.run_periodic->parsed();
  const bool is_cmd = subcmds.run_cmd->parsed();
  CommonOptions &active_opts = is_periodic
                                   ? static_cast<CommonOptions &>(periodic_opts)
                                   : static_cast<CommonOptions &>(cmd_opts);

  active_opts.program_args = app.remaining();

  setup_signal_handlers();
  SetupLogging(active_opts);

  pid_t child_pid = fork();
  if (child_pid == -1) {
    spdlog::error("Fork failed: {}", strerror(errno));
    return 1;
  }

  if (child_pid == 0) {
    // Child process
    std::vector<char *> exec_args;

    // Convert all program arguments to char* for execvp
    exec_args.push_back(const_cast<char *>(active_opts.program_name.c_str()));
    for (const auto &arg : active_opts.program_args) {
      exec_args.push_back(const_cast<char *>(arg.c_str()));
    }
    exec_args.push_back(nullptr); // Required null terminator

    execvp(exec_args[0], exec_args.data());
    spdlog::error("Exec failed: {}", strerror(errno));
    exit(1);
  }

  MonitorMode mode;
  MonitorConfig config;

  // Parent process
  if (is_periodic) {
    mode = MonitorMode::Periodic;
    config.initial_delay =
        std::chrono::milliseconds(periodic_opts.initial_delay_ms);
    config.iteration_limit = periodic_opts.max_iterations;
    config.interval = std::chrono::milliseconds(periodic_opts.interval_ms);
  } else if (is_cmd) {
    mode = MonitorMode::Command;
  } else {
    exit(1);
  }

  MonitorController controller(child_pid, active_opts, mode, config);
  controller.StartMonitoring();

  // Cleanup
  spdlog::info("Killing child process");
  kill(child_pid, SIGKILL);
  waitpid(child_pid, nullptr, 0);
  spdlog::info("Child process terminated");
  spdlog::info("Monitoring complete");

  return 0;
}
