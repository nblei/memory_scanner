#ifndef PAGERANK_H_
#define PAGERANK_H_

#include <memory>
#include <random>
#include <utility>
#include <vector>

namespace memory_tools {

class PageRank {
public:
  explicit PageRank(std::mt19937_64 &rng);
  ~PageRank();

  // Prevent copying and assignment
  PageRank(const PageRank &) = delete;
  PageRank &operator=(const PageRank &) = delete;

  // Create a random web graph
  void GenerateRandomGraph(size_t num_vertices, double edge_probability);

  // Run PageRank algorithm until convergence
  size_t ComputePagerank(size_t max_iterations = 100);

  // Get top N pages by rank
  std::vector<std::pair<size_t, double>> GetTopPages(size_t n) const;

private:
  class PageRankImpl;
  std::unique_ptr<PageRankImpl> impl_;
  std::mt19937_64 &rng_; // reference to external RNG
};

} // namespace memory_tools

#endif // PAGERANK_H_
