#include "pagerank.hh"

#include <algorithm>
#include <cmath>
#include <random>

namespace memory_tools {

struct Page {
  size_t id;
  double rank{1.0};          // Non-pointer: errors dampen out
  double next_rank{0.0};     // Temporary value for computation
  std::vector<Page *> links; // Pointer: critical for graph structure
};

class PageRank::PageRankImpl {
public:
  static constexpr double kDampingFactor = 0.85;
  static constexpr double kConvergenceThreshold = 1e-10;

  std::vector<std::unique_ptr<Page>> pages;
  size_t num_pages{0};

  // Single iteration of PageRank
  double RunIteration() {
    // Reset next_rank values
    for (auto &page : pages) {
      page->next_rank = (1.0 - kDampingFactor) / static_cast<double>(num_pages);
    }

    // Distribute rank via links
    for (const auto &page : pages) {
      if (!page->links.empty()) {
        double out_rank = kDampingFactor * page->rank /
                          static_cast<double>(page->links.size());
        for (auto *target : page->links) {
          target->next_rank += out_rank;
        }
      }
    }

    // Compute difference and update ranks
    double max_diff = 0.0;
    for (auto &page : pages) {
      double diff = std::abs(page->next_rank - page->rank);
      max_diff = std::max(max_diff, diff);
      page->rank = page->next_rank;
    }

    return max_diff;
  }
};

PageRank::PageRank(std::mt19937_64 &rng)
    : impl_(std::make_unique<PageRankImpl>()), rng_(rng) {}

PageRank::~PageRank() = default;

void PageRank::GenerateRandomGraph(size_t num_vertices,
                                   double edge_probability) {
  std::uniform_real_distribution<> dist(0.0, 1.0);

  impl_->num_pages = num_vertices;
  impl_->pages.clear();
  impl_->pages.reserve(num_vertices);

  // Create pages
  for (size_t i = 0; i < num_vertices; ++i) {
    auto page = std::make_unique<Page>();
    page->id = i;
    page->rank = 1.0 / static_cast<double>(num_vertices);
    impl_->pages.push_back(std::move(page));
  }

  // Create random edges
  for (auto &page : impl_->pages) {
    for (auto &target : impl_->pages) {
      if (page != target && dist(rng_) < edge_probability) {
        page->links.push_back(target.get());
      }
    }
  }
}

size_t PageRank::ComputePagerank(size_t max_iterations) {
  size_t iterations = 0;
  double diff;

  do {
    diff = impl_->RunIteration();
    ++iterations;
  } while (diff > PageRankImpl::kConvergenceThreshold &&
           iterations < max_iterations);

  return iterations;
}

std::vector<std::pair<size_t, double>> PageRank::GetTopPages(size_t n) const {
  std::vector<std::pair<size_t, double>> ranks;
  ranks.reserve(impl_->pages.size());

  for (const auto &page : impl_->pages) {
    ranks.emplace_back(page->id, page->rank);
  }

  // Sort by rank
  std::partial_sort(
      ranks.begin(),
      ranks.begin() + static_cast<long>(std::min(n, ranks.size())), ranks.end(),
      [](const auto &a, const auto &b) { return a.second > b.second; });

  ranks.resize(std::min(n, ranks.size()));
  return ranks;
}

} // namespace memory_tools
