#include "monitor_interface.hh"

#include "spdlog/spdlog.h"
#include <atomic>
#include <cstring>
#include <system_error>

namespace memory_tools {

namespace {
// For synchronization between signal handler and main thread
static std::atomic<bool> g_response_received{false};

static void MonitorResponseHandler(int /*signo*/, siginfo_t * /*info*/,
                                   void * /*context */) {
  g_response_received.store(true, std::memory_order_release);
}

} // namespace

void InitTracedProcess() {
  // Set up signal handler for monitor responses
  struct sigaction sa{};
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = MonitorResponseHandler;
  sigemptyset(&sa.sa_mask);

  if (sigaction(MONITOR_RESPONSE_SIGNAL, &sa, nullptr) < 0) {
    throw std::system_error(errno, std::system_category(),
                            "Failed to set up monitor response handler");
  }
}

bool SendCommand(MonitorCommand cmd, uint64_t param1, uint64_t param2) {
  // Store command info where monitor can access it
  g_response_received.store(false, std::memory_order_release);
  const pid_t parent_pid = getppid();
  spdlog::info("Sending command {} to parent pid {}", static_cast<int>(cmd),
               parent_pid);

  // Send signal with data to parent process
  CommandInfo info{cmd, param1, param2};
  if (sigqueue(parent_pid, MONITOR_REQUEST_SIGNAL, info.Pack()) < 0) {
    spdlog::error("Failed to send command signal: {}", strerror(errno));
    return false;
  }
  spdlog::info("Successfully sent command signal");

  // Wait for response with timeout
  constexpr auto TIMEOUT = std::chrono::seconds(5);
  auto start = std::chrono::steady_clock::now();

  while (!g_response_received.load(std::memory_order_acquire)) {
    if (std::chrono::steady_clock::now() - start > TIMEOUT) {
      spdlog::error("Timeout waiting for monitor response");
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  return true;
}

bool WaitForResponse() {
  // Simple spin-wait for response
  // Could be enhanced with timeout or better waiting mechanism
  while (!g_response_received.load(std::memory_order_acquire)) {
    // Small sleep to reduce CPU usage
    struct timespec ts{.tv_sec = 0, .tv_nsec = 1000000};
    nanosleep(&ts, nullptr);
  }
  return true;
}

} // namespace memory_tools
