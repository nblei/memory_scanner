#include "cli.hh"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/spdlog.h"

namespace memory_tools {
void SetupLogging(const CommonOptions &options) {
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

void AddCommonOptions(CLI::App *app, CommonOptions &options) {
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
      // ->check(CLI::ExistingFile)
      ->required();
}

CliSubcommands CreateCli(CLI::App &app, RunPeriodicOptions &periodic_opts,
                         RunCommandOptions &cmd_opts) {
  // Main program setup
  app.require_subcommand(1, 1);
  app.allow_extras();

  auto run_once = app.add_subcommand("once", "Run a single scan after a delay");
  auto run_periodic = app.add_subcommand("periodic", "Run periodic scans");
  auto run_cmd = app.add_subcommand(
      "command",
      "Run in command mode - monitor responds to signals from traced process");

  AddCommonOptions(run_periodic, periodic_opts);
  run_periodic
      ->add_option("-i,--interval", periodic_opts.interval_ms,
                   "Scan interval in milliseconds")
      ->default_val(1000)
      ->check(CLI::PositiveNumber);
  run_periodic
      ->add_option("-d,--delay", periodic_opts.initial_delay_ms,
                   "Initial delay before first scan in milliseconds")
      ->default_val(1000)
      ->check(CLI::PositiveNumber);

  AddCommonOptions(run_cmd, cmd_opts);
  return CliSubcommands{run_once, run_periodic, run_cmd};
}

} // namespace memory_tools
