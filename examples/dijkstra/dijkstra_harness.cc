#include "dijkstra.hh"
#include "monitor_interface.hh"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <thread>

void print_usage(const char *program_name) {
  std::cerr << "Usage: " << program_name
            << " <random_seed> <num_vertices> <src_vertex> <dst_vertex> "
               "[edge_probability]\n";
}

// Returns true if computation succeeded
bool compute_path(memory_tools::ShortestPath &sp, size_t src, size_t dst,
                  std::vector<size_t> &path, std::optional<double> &distance) {
  try {
    distance = sp.ComputeShortestPath(src, dst, path);
    return true;
  } catch (const std::exception &e) {
    std::cerr << "Error during path computation: " << e.what() << "\n";
    return false;
  }
}

int main(int argc, char *argv[]) {
  using namespace memory_tools;

  if (argc != 5 && argc != 6) {
    print_usage(argv[0]);
    return 1;
  }

  // Initialize monitor interface
  InitTracedProcess();

  // Parse arguments
  uint64_t seed;
  size_t num_vertices, src, dst;
  double edge_probability = 0.01; // Default 1%

  try {
    seed = std::stoull(argv[1]);
    num_vertices = std::stoull(argv[2]);
    src = std::stoull(argv[3]);
    dst = std::stoull(argv[4]);

    if (argc == 6) {
      edge_probability = std::stod(argv[5]);
      if (edge_probability <= 0.0 || edge_probability >= 1.0) {
        throw std::out_of_range("Edge probability must be between 0 and 1");
      }
    }

    if (src >= num_vertices || dst >= num_vertices) {
      throw std::out_of_range(
          "Vertex IDs must be less than number of vertices");
    }

    if (num_vertices < 2 || num_vertices > 1000000) {
      throw std::out_of_range(
          "Number of vertices must be between 2 and 1,000,000");
    }

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << "\n";
    print_usage(argv[0]);
    return 1;
  }

  // Create graph
  std::mt19937_64 rng(seed);
  ShortestPath sp(rng);

  std::cout << "Generating random graph with:\n"
            << "  " << num_vertices << " vertices\n"
            << "  " << std::fixed << std::setprecision(3)
            << edge_probability * 100 << "% edge probability\n"
            << "  " << "seed: " << seed << "\n\n";

  auto gen_start = std::chrono::steady_clock::now();
  sp.GenerateRandomGraph(num_vertices, edge_probability);
  auto gen_end = std::chrono::steady_clock::now();

  auto gen_time =
      std::chrono::duration_cast<std::chrono::milliseconds>(gen_end - gen_start)
          .count();
  std::cout << "Graph generation time: " << gen_time << "ms\n\n";

  // Create checkpoint after graph generation
  if (!SendCommand(MonitorCommand::Checkpoint)) {
    std::cerr << "Failed to create checkpoint\n";
    return 1;
  }

  // Start error injection
  if (!SendCommand(MonitorCommand::InjectErrors)) {
    std::cerr << "Failed to start error injection\n";
    return 1;
  }

  // Run pathfinding with retries on failure
  const int MAX_RETRIES = 5;
  int retry_count = 0;
  std::vector<size_t> path;
  std::optional<double> distance;
  bool success = false;

  while (!success && retry_count < MAX_RETRIES) {
    auto start_time = std::chrono::steady_clock::now();

    if (compute_path(sp, src, dst, path, distance)) {
      auto end_time = std::chrono::steady_clock::now();
      auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                          end_time - start_time)
                          .count();

      std::cout << "Shortest Path Results (attempt " << retry_count + 1
                << "):\n";
      std::cout << "Computation time: " << duration << "ms\n\n";

      if (!distance) {
        std::cout << "No path exists between vertices " << src << " and " << dst
                  << "\n";
      } else {
        std::cout << "Path length: " << std::fixed << std::setprecision(2)
                  << *distance << "\n";

        bool print_path =
            (num_vertices <= 100) || (std::getenv("PRINT_PATH") != nullptr);
        if (print_path) {
          std::cout << "Path: ";
          for (size_t i = 0; i < path.size(); ++i) {
            std::cout << path[i];
            if (i < path.size() - 1)
              std::cout << " -> ";
          }
          std::cout << "\n";
        } else {
          std::cout << "Path has " << path.size() << " vertices "
                    << "(set PRINT_PATH environment variable to display)\n";
        }
      }
      success = true;
    } else {
      retry_count++;
      std::cout << "Retry " << retry_count << "/" << MAX_RETRIES << "\n";

      // Request checkpoint restore
      if (!SendCommand(MonitorCommand::Restore)) {
        std::cerr << "Failed to restore checkpoint\n";
        return 1;
      }

      // Small delay before retry
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }

  if (!success) {
    std::cerr << "Failed to compute path after " << MAX_RETRIES
              << " attempts\n";
    return 1;
  }

  return 0;
}
