#include "pagerank.hh"
#include <chrono>
#include <iostream>
#include <random>
void print_usage(const char *program_name) {
  std::cerr << "Usage: " << program_name << " <random_seed>\n";
  std::cerr << "  random_seed: Unsigned integer for RNG initialization\n";
}

int main(int argc, char *argv[]) {
  using namespace memory_tools;

  if (argc != 2) {
    print_usage(argv[0]);
    return 1;
  }

  // Parse random seed
  uint64_t seed;
  try {
    seed = std::stoull(argv[1]);
  } catch (const std::exception &e) {
    std::cerr << "Error: Invalid random seed\n";
    print_usage(argv[0]);
    return 1;
  }

  // Create a reasonably sized graph
  constexpr size_t NUM_PAGES = 5000;
  constexpr double EDGE_PROBABILITY =
      0.01; // 1% chance of edge between any two pages
  // Create RNG with specified seed
  std::mt19937_64 rng(seed);

  PageRank pr(rng); // Pass RNG to PageRank
  pr.GenerateRandomGraph(NUM_PAGES, EDGE_PROBABILITY);

  // First run - get baseline results
  auto start_time = std::chrono::steady_clock::now();
  size_t iterations = pr.ComputePagerank();
  auto end_time = std::chrono::steady_clock::now();
  auto baseline = pr.GetTopPages(10);

  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                      end_time - start_time)
                      .count();

  std::cout << "Baseline PageRank Results:\n";
  std::cout << "Iterations to converge: " << iterations << "\n";
  std::cout << "Time to converge: " << duration << "ms\n";
  std::cout << "Average time per iteration: "
            << static_cast<double>(duration) / static_cast<double>(iterations)
            << "ms\n\n";

  std::cout << "Top 10 pages:\n";
  for (const auto &[id, rank] : baseline) {
    std::cout << "Page " << std::setw(4) << id << ": " << std::fixed
              << std::setprecision(6) << rank << "\n";
  }

  // Detect non-convergence
  if (iterations >= 100) { // Using default max_iterations
    std::cout
        << "\nWARNING: Algorithm hit iteration limit without converging\n";
  }

  return 0;
}
