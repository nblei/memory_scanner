#ifndef __MEMORY_TOOLS_CLI_HH__
#define __MEMORY_TOOLS_CLI_HH__
#include "CLI/App.hpp"
#include "spdlog/common.h"
#include <cstddef>
#include <string>
#include <vector>

namespace memory_tools {

enum class ErrorType {
  BitFlip, // Flip random bits
  StuckAtZero,
  StuckAtOne,
};

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
struct RunOnceOptions : CommonOptions {
  unsigned delay_ms{1000};
};

struct RunPeriodicOptions : CommonOptions {
  unsigned interval_ms{1000};
};

struct RunCommandOptions : CommonOptions {};

struct CliSubcommands {
  CLI::App *run_once;
  CLI::App *run_periodic;
  CLI::App *run_cmd;
};

void AddCommonOptions(CLI::App *app, CommonOptions &options);
CliSubcommands CreateCli(CLI::App &app, RunOnceOptions &once_opts,
                         RunPeriodicOptions &periodic_opts,
                         RunCommandOptions &cmd_opts);
void SetupLogging(const CommonOptions &options);

} // namespace memory_tools
#endif
