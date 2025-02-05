// dijkstra.cc
#include "dijkstra.hh"
#include <algorithm>
#include <limits>
#include <queue>

namespace memory_tools {

struct Vertex;

struct Edge {
  Vertex *target; // Pointer: critical for graph structure
  double weight;  // Non-pointer: errors less critical
};

struct Vertex {
  size_t id;
  std::vector<Edge> edges;
  double distance{std::numeric_limits<double>::infinity()}; // Non-pointer
  Vertex *prev{nullptr};                                    // Pointer
};

class ShortestPath::ShortestPathImpl {
public:
  std::vector<std::unique_ptr<Vertex>> vertices;
  size_t num_vertices{0};

  void ResetState() {
    for (auto &v : vertices) {
      v->distance = std::numeric_limits<double>::infinity();
      v->prev = nullptr;
    }
  }

  bool RunDijkstra(size_t src, size_t dst) {
    if (src >= vertices.size() || dst >= vertices.size()) {
      return false;
    }

    ResetState();

    // Priority queue ordered by distance
    using QueueEntry = std::pair<double, Vertex *>;
    std::priority_queue<QueueEntry, std::vector<QueueEntry>,
                        std::greater<QueueEntry>>
        queue;

    // Initialize source
    vertices[src]->distance = 0;
    queue.push({0, vertices[src].get()});

    while (!queue.empty()) {
      auto [dist, current] = queue.top();
      queue.pop();

      // Found destination
      if (current->id == dst) {
        return true;
      }

      // Skip if we've found a better path
      if (dist > current->distance) {
        continue;
      }

      // Process each outgoing edge
      for (const auto &edge : current->edges) {
        double new_dist = current->distance + edge.weight;
        if (new_dist < edge.target->distance) {
          edge.target->distance = new_dist;
          edge.target->prev = current;
          queue.push({new_dist, edge.target});
        }
      }
    }

    return false; // No path found
  }

  std::vector<size_t> ReconstructPath(size_t src, size_t dst) const {
    std::vector<size_t> path;
    if (vertices[dst]->distance == std::numeric_limits<double>::infinity()) {
      return path;
    }

    for (Vertex *v = vertices[dst].get(); v != nullptr; v = v->prev) {
      path.push_back(v->id);
      if (v->id == src)
        break;
    }
    std::reverse(path.begin(), path.end());
    return path;
  }
};

ShortestPath::ShortestPath(std::mt19937_64 &rng)
    : impl_(std::make_unique<ShortestPathImpl>()), rng_(rng) {}

ShortestPath::~ShortestPath() = default;

void ShortestPath::GenerateRandomGraph(size_t num_vertices,
                                       double edge_probability,
                                       double max_weight) {
  std::uniform_real_distribution<> weight_dist(1.0, max_weight);

  // Calculate expected number of edges
  size_t expected_edges = static_cast<size_t>(
      edge_probability *
      static_cast<double>(num_vertices * (num_vertices - 1)));

  impl_->num_vertices = num_vertices;
  impl_->vertices.clear();
  impl_->vertices.reserve(num_vertices);

  // Create vertices
  for (size_t i = 0; i < num_vertices; ++i) {
    auto vertex = std::make_unique<Vertex>();
    vertex->id = i;
    impl_->vertices.push_back(std::move(vertex));
  }

  // Generate edges directly
  std::uniform_int_distribution<size_t> vertex_dist(0, num_vertices - 1);

  for (size_t i = 0; i < expected_edges; ++i) {
    size_t src, dst;
    do {
      src = vertex_dist(rng_);
      dst = vertex_dist(rng_);
    } while (src == dst);

    impl_->vertices[src]->edges.push_back(
        Edge{impl_->vertices[dst].get(), weight_dist(rng_)});
  }
}

std::optional<double>
ShortestPath::ComputeShortestPath(size_t src, size_t dst,
                                  std::vector<size_t> &path) {
  if (!impl_->RunDijkstra(src, dst)) {
    return std::nullopt;
  }

  path = impl_->ReconstructPath(src, dst);
  return impl_->vertices[dst]->distance;
}

std::vector<std::pair<size_t, size_t>> ShortestPath::GetAllEdges() const {
  std::vector<std::pair<size_t, size_t>> edges;
  for (const auto &vertex : impl_->vertices) {
    for (const auto &edge : vertex->edges) {
      edges.emplace_back(vertex->id, edge.target->id);
    }
  }
  return edges;
}

std::vector<double> ShortestPath::GetAllWeights() const {
  std::vector<double> weights;
  for (const auto &vertex : impl_->vertices) {
    for (const auto &edge : vertex->edges) {
      weights.push_back(edge.weight);
    }
  }
  return weights;
}

} // namespace memory_tools
