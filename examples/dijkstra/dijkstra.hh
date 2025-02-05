// dijkstra.hh
#ifndef DIJKSTRA_H_
#define DIJKSTRA_H_

#include <memory>
#include <optional>
#include <random>
#include <vector>

namespace memory_tools {

class ShortestPath {
public:
  explicit ShortestPath(std::mt19937_64 &rng);
  ~ShortestPath();

  // Prevent copying and assignment
  ShortestPath(const ShortestPath &) = delete;
  ShortestPath &operator=(const ShortestPath &) = delete;

  // Create a random weighted graph
  void GenerateRandomGraph(size_t num_vertices, double edge_probability,
                           double max_weight = 100.0);

  // Find shortest path between src and dst
  // Returns total path cost and populates path vector
  std::optional<double> ComputeShortestPath(size_t src, size_t dst,
                                            std::vector<size_t> &path);

  // For testing/verification
  std::vector<std::pair<size_t, size_t>> GetAllEdges() const;
  std::vector<double> GetAllWeights() const;

private:
  class ShortestPathImpl;
  std::unique_ptr<ShortestPathImpl> impl_;
  std::mt19937_64 &rng_;
};

} // namespace memory_tools

#endif // DIJKSTRA_H_
