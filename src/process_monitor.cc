#include "process_scanner.hh"
#include <CLI/CLI.hpp>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
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

struct ScannerOptions {
  bool verbose{false};
  unsigned interval{0};
  std::string log_file;
  std::vector<std::string> program_args;
  spdlog::level::level_enum log_level{spdlog::level::info};
};

// std::string get_timestamp() {
//   auto now = std::chrono::system_clock::now();
//   auto time = std::chrono::system_clock::to_time_t(now);
//   std::stringstream ss;
//   ss << std::put_time(std::localtime(&time), "%Y%m%d_%H%M%S");
//   return ss.str();
// }

void monitor_process(pid_t child_pid, unsigned interval) {
  try {
    memory_tools::ProcessScanner scanner(child_pid);

    // Open log file for scan results

    spdlog::info("Monitoring process {}", child_pid);

    while (!g_should_exit) {
      // Check if child is still running
      int status;
      pid_t result = waitpid(child_pid, &status, WNOHANG);
      if (result == -1) {
        spdlog::error("Error checking child process: {}", strerror(errno));
        break;
      } else if (result > 0) {
        spdlog::info("Child process terminated");
        break;
      }

      // Perform scan
      if (!scanner.Attach()) {
        spdlog::error("Failed to attach to process");
        break;
      }

      scanner.ScanForPointers([](uint64_t addr, uint64_t value) {
        (void)addr;
        (void)value;
        // logfile << std::hex << "0x" << addr << " -> 0x" << value << "\n";
      });

      std::stringstream ss;
      ss << scanner.GetLastScanStats();
      spdlog::info(ss.str());

      scanner.Detach();

      // Wait before next scan
      if (interval == 0) {
        break;
      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(interval));
      }
    }
  } catch (const std::exception &e) {
    spdlog::error("Error in monitor: {}", e.what());
  }
}

void setup_logging(const ScannerOptions &options) {
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

    std::string prog_msg =
        "Starting memory scanner for program: " + options.program_args[0];
    spdlog::info(prog_msg);
  } catch (const spdlog::spdlog_ex &ex) {
    std::cerr << "Logger initialization failed: " << ex.what() << std::endl;
    exit(1);
  }
}

} // namespace

int main(int argc, char *argv[]) {
  ScannerOptions options;

  CLI::App app{"Process Monitor - analyzes process memory for pointers"};

  // Add CLI options
  app.add_flag("-v,--verbose", options.verbose,
               "Enable verbose console output");

  app.add_option("-i,--interval", options.interval,
                 "Scan interval in milliseconds (0 for single scan)")
      ->check(CLI::TypeValidator<unsigned>())
      ->default_val(1000);

  app.add_option("-l,--log-file", options.log_file, "Log file path")
      ->default_val("memory_scanner.log");

  std::string level_str = "info";
  app.add_option("--log-level", level_str,
                 "Log level (trace, debug, info, warn, error, critical)")
      ->default_val("info")
      ->transform(CLI::CheckedTransformer(
          std::map<std::string, spdlog::level::level_enum>{
              {"trace", spdlog::level::trace},
              {"debug", spdlog::level::debug},
              {"info", spdlog::level::info},
              {"warn", spdlog::level::warn},
              {"error", spdlog::level::err},
              {"critical", spdlog::level::critical}},
          CLI::ignore_case));

  // Program and its arguments
  app.add_option("program", options.program_args,
                 "Program to scan and its arguments")
      ->required()
      ->expected(-1); // Accept unlimited arguments after program

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError &e) {
    return app.exit(e);
  }

  setup_signal_handlers();
  setup_logging(options);

  pid_t child_pid = fork();
  if (child_pid == -1) {
    std::cerr << "Fork failed: " << strerror(errno) << "\n";
    exit(1);
  }

  if (child_pid == 0) {
    // Child process
    std::vector<char *> exec_args;
    for (auto &arg : options.program_args) {
      exec_args.push_back(arg.data());
    }
    execvp(exec_args[0], exec_args.data());
    std::cerr << "Exec failed: " << strerror(errno) << "\n";
    exit(1);
  }
  // Parent process
  monitor_process(child_pid, options.interval);

  // Ensure child is terminated
  spdlog::info("Killing child");
  kill(child_pid, SIGKILL);
  waitpid(child_pid, nullptr, 0);
  spdlog::info("Child killed");
  spdlog::info("Monitoring complete");

  return 0;
}
