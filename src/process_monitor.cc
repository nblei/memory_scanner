#include "error_injection.hh"
#include "process_scanner.hh"
#include <CLI/CLI.hpp>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <signal.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sstream>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {
volatile sig_atomic_t g_should_exit = 0;

void signal_handler(int) { g_should_exit = 1; }

void setup_signal_handlers() {
  // Set up signal handler
  struct sigaction sa = {};
  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);
}

struct CommonOptions {
  bool verbose{false};
  size_t num_threads;
  std::string log_file;
  std::string program_name;
  std::vector<std::string> program_args;
  memory_tools::ErrorType error_type{memory_tools::ErrorType::BitFlip};
  double pointer_error_rate{0.0};
  double non_pointer_error_rate{0.0};
  size_t error_limit{std::numeric_limits<size_t>::max()};
  uint64_t error_seed{0};
  spdlog::level::level_enum log_level{spdlog::level::info};
};
struct RunOnceOptions;
struct RunPeriodicOptions;

// Abstract base class for monitoring strategies.
class MonitoringStrategy {
public:
  virtual ~MonitoringStrategy() = default;
  virtual void before_monitoring() = 0;
  virtual bool should_continue() = 0;
  virtual void after_scan() = 0;
};

// Strategy for single scan with delay
class SingleScanStrategy : public MonitoringStrategy {
  unsigned delay_ms_;
  bool scan_completed_ = false;

public:
  explicit SingleScanStrategy(unsigned delay_ms) : delay_ms_(delay_ms) {}

  void before_monitoring() override {
    spdlog::info("Waiting {}ms before scanning", delay_ms_);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms_));
  }

  bool should_continue() override { return !scan_completed_; }

  void after_scan() override { scan_completed_ = true; }
};

// Strategy for periodic scanning
class PeriodicScanStrategy : public MonitoringStrategy {
  unsigned interval_ms_;

public:
  explicit PeriodicScanStrategy(unsigned interval_ms)
      : interval_ms_(interval_ms) {}

  void before_monitoring() override {
    spdlog::info("Starting periodic scan with {}ms interval", interval_ms_);
  }

  bool should_continue() override { return !g_should_exit; }

  void after_scan() override {
    std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms_));
  }
};

// Core monitoring function used by both modes
bool monitor_process_core(pid_t child_pid, MonitoringStrategy &strategy,
                          const CommonOptions &options) {
  memory_tools::ErrorInjectionStrategy injection_strategy(
      options.error_type, options.pointer_error_rate,
      options.non_pointer_error_rate, options.error_limit, options.error_seed);
  try {
    memory_tools::ProcessScanner scanner(child_pid, options.num_threads);
    strategy.before_monitoring();

    // Open log file for scan results
    spdlog::info("Monitoring process {}", child_pid);

    while (strategy.should_continue()) {
      // Check if child is still running
      int status;
      pid_t result = waitpid(child_pid, &status, WNOHANG);
      if (result == -1) {
        spdlog::error("Error checking child process: {}", strerror(errno));
        return false;
      } else if (result > 0) {
        spdlog::info("Child process terminated");
        return false;
      }

      // Perform scan
      if (!scanner.Attach()) {
        spdlog::error("Failed to attach to process");
        return false;
      }

      scanner.ScanForPointers(injection_strategy);

      std::stringstream ss;
      ss << scanner.GetLastScanStats();
      spdlog::info(ss.str());

      scanner.Detach();
      strategy.after_scan();
    }

    return true;
  } catch (const std::exception &e) {
    spdlog::error("Error in monitor: {}", e.what());
    return false;
  }
}

// Wrapper functions for different monitoring modes
void monitor_process_once(pid_t child_pid, unsigned delay_ms,
                          const CommonOptions &options) {
  SingleScanStrategy strategy(delay_ms);
  monitor_process_core(child_pid, strategy, options);
}

void monitor_process_periodic(pid_t child_pid, unsigned delay_ms,
                              const CommonOptions &options) {
  PeriodicScanStrategy strategy(delay_ms);
  monitor_process_core(child_pid, strategy, options);
}

struct RunOnceOptions : CommonOptions {
  unsigned delay_ms{1000};
};

struct RunPeriodicOptions : CommonOptions {
  unsigned interval_ms{1000};
};

void setup_logging(const CommonOptions &options) {
  try {
    std::vector<spdlog::sink_ptr> sinks;

    // File sink is always enabled
    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
        options.log_file, true);
    file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    sinks.push_back(file_sink);

    // Console sink only if verbose mode is enabled
    if (options.verbose) {
      auto console_sink =
          std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
      console_sink->set_pattern("[%^%l%$] %v");
      sinks.push_back(console_sink);
    }

    auto logger =
        std::make_shared<spdlog::logger>("scanner", sinks.begin(), sinks.end());
    spdlog::set_default_logger(logger);
    spdlog::set_level(options.log_level);

    std::string prog_msg = "Starting memory scanner for program:";
    for (const auto &arg : options.program_args) {
      prog_msg += " " + arg;
    }
    spdlog::info(prog_msg);
  } catch (const spdlog::spdlog_ex &ex) {
    std::cerr << "Logger initialization failed: " << ex.what() << std::endl;
    exit(1);
  }
}

template <typename Options>
void add_common_options(CLI::App *app, Options &options) {
  app->add_flag("-v,--verbose", options.verbose,
                "Enable verbose console output");
  app->add_option("-l,--log-file", options.log_file, "Log file path")
      ->default_val("memory_scanner.log");
  app->add_option("--threads", options.num_threads, "Number of scanner threads")
      ->default_val(12)
      ->check(CLI::Range(1, 256));

  app->add_option("--log-level", options.log_level,
                  "Log level (trace, debug, info, warn, error, critical)")
      ->default_val(spdlog::level::info)
      ->transform(CLI::CheckedTransformer(
          std::map<std::string, spdlog::level::level_enum>{
              {"trace", spdlog::level::trace},
              {"debug", spdlog::level::debug},
              {"info", spdlog::level::info},
              {"warn", spdlog::level::warn},
              {"error", spdlog::level::err},
              {"critical", spdlog::level::critical}},
          CLI::ignore_case));

  // Add to add_common_options function:
  app->add_option("--error-type", options.error_type,
                  "Error injection type (bitflip, stuck at zero, stuck at one)")
      ->transform(CLI::CheckedTransformer(
          std::map<std::string, memory_tools::ErrorType>{
              {"bitflip", memory_tools::ErrorType::BitFlip},
              {"zero", memory_tools::ErrorType::StuckAtZero},
              {"one", memory_tools::ErrorType::StuckAtOne}},
          CLI::ignore_case));

  app->add_option("--pointer-error-rate", options.pointer_error_rate,
                  "Error injection rate (0.0-1.0)")
      ->default_val(0.)
      ->check(CLI::Range(0.0, 1.0));

  app->add_option("--non-pointer-error-rate", options.non_pointer_error_rate,
                  "Error injection rate (0.0-1.0)")
      ->default_val(0.)
      ->check(CLI::Range(0.0, 1.0));

  app->add_option("--error-limit", options.error_limit,
                  "Maximum number of errors to inject")
      ->default_val(std::numeric_limits<size_t>::max())
      ->check(CLI::PositiveNumber);

  app->add_option("--error-seed", options.error_seed,
                  "RNG seed for error injection (0 for random)")
      ->default_val(0);

  // Create a special option group for the program and its arguments
  app->add_option("Program", options.program_name, "Program to monitor")
      ->check(CLI::ExistingFile)
      ->required();
}
} // namespace

int main(int argc, char *argv[]) {
  // Main program setup
  CLI::App app{"Process Monitor - analyzes process memory for pointers"};
  app.require_subcommand(1, 1);
  app.allow_extras();

  auto run_once = app.add_subcommand("once", "Run a single scan after a delay");
  auto run_periodic = app.add_subcommand("periodic", "Run periodic scans");

  RunOnceOptions once_opts;
  RunPeriodicOptions periodic_opts;

  add_common_options(run_once, once_opts);
  run_once
      ->add_option("-d,--delay", once_opts.delay_ms,
                   "Delay before scanning (milliseconds)")
      ->default_val(1000)
      ->check(CLI::PositiveNumber);

  add_common_options(run_periodic, periodic_opts);
  run_periodic
      ->add_option("-i,--interval", periodic_opts.interval_ms,
                   "Scan interval in milliseconds")
      ->default_val(1000)
      ->check(CLI::PositiveNumber);

  app.require_subcommand(1, 1); // Exactly one subcommand required

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError &e) {
    return app.exit(e);
  }

  CommonOptions &active_opts =
      run_once->parsed() ? static_cast<CommonOptions &>(once_opts)
                         : static_cast<CommonOptions &>(periodic_opts);

  active_opts.program_args = app.remaining();

  setup_signal_handlers();
  setup_logging(active_opts);

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

  // Parent process
  if (run_once->parsed()) {
    monitor_process_once(child_pid, once_opts.delay_ms, active_opts);
  } else {
    monitor_process_periodic(child_pid, periodic_opts.interval_ms, active_opts);
  }

  // Cleanup
  spdlog::info("Killing child process");
  kill(child_pid, SIGKILL);
  waitpid(child_pid, nullptr, 0);
  spdlog::info("Child process terminated");
  spdlog::info("Monitoring complete");

  return 0;
}
