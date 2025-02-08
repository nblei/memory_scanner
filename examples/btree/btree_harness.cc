#include "btree.hh"
#include <iostream>
#include <random>

void print_usage(const char *program_name) {
  std::cerr << "Usage: " << program_name
            << " <random_seed> <num_insertions> <num_queries>\n";
}

int main(int argc, char *argv[]) {
  using namespace memory_tools;

  if (argc != 4) {
    print_usage(argv[0]);
    return 1;
  }

  uint64_t seed;
  size_t num_insertions, num_queries;
  try {
    seed = std::stoull(argv[1]);
    num_insertions = std::stoull(argv[2]);
    num_queries = std::stoull(argv[3]);
  } catch (const std::exception &e) {
    print_usage(argv[0]);
    return 1;
  }

  std::mt19937_64 rng(seed);
  std::uniform_int_distribution<int> insert_dist(
      0, static_cast<int>(num_insertions * 3));
  std::uniform_int_distribution<int> query_dist(
      0, static_cast<int>(num_insertions * 3));

  BTree<int> tree;

  // Insert elements
  for (size_t i = 0; i < num_insertions; ++i) {
    tree.insert(insert_dist(rng));
  }

  // Query elements
  for (size_t i = 0; i < num_queries; ++i) {
    int query_val = query_dist(rng);
    if (tree.search(query_val).has_value()) {
      std::cout << "Query " << query_val << ": Found\n";
    } else {
      std::cout << "Query " << query_val << ": Not Found\n";
    }
  }

  return 0;
}
