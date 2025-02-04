#include <CLI/CLI.hpp>
#include <cstdlib>
#include <iostream>
#include <random>
#include <vector>

struct Node {
  unsigned value;
  Node *next;
  std::vector<Node *> children;
  Node *random;
  explicit Node(unsigned v) : value(v), next(nullptr), random(nullptr) {}
};

int main(int argc, char *argv[]) {
  CLI::App app{"Creates a hybrid data structure with linked list, tree, and random connections"};
  
  unsigned num_nodes = 1000;
  unsigned max_children = 3;
  
  app.add_option("-n,--nodes", num_nodes, "Number of nodes to create")
     ->required()
     ->check(CLI::PositiveNumber)
     ->check(CLI::Range(1u, 1000000u));
  app.add_option("-c,--max-children", max_children, "Maximum children per node")
     ->check(CLI::Range(0u, 100u));

  CLI11_PARSE(app, argc, argv);

  std::random_device rd;
  std::mt19937 rng(rd());
  std::uniform_int_distribution<unsigned> child_dist(0, max_children);

  std::vector<Node *> all_nodes;
  all_nodes.reserve(num_nodes);

  for (unsigned i = 0; i < num_nodes; i++) {
    all_nodes.push_back(new Node(i));
  }

  for (size_t i = 0; i < all_nodes.size(); i++) {
    if (i < all_nodes.size() - 1) {
      all_nodes[i]->next = all_nodes[i + 1];
    }

    unsigned num_children = child_dist(rng);
    size_t remaining = all_nodes.size() - i - 1;
    num_children = std::min(num_children, static_cast<unsigned>(remaining));

    for (unsigned j = 0; j < num_children; j++) {
      std::uniform_int_distribution<size_t> dist(i + 1, all_nodes.size() - 1);
      all_nodes[i]->children.push_back(all_nodes[dist(rng)]);
    }

    std::uniform_int_distribution<size_t> dist(0, all_nodes.size() - 1);
    all_nodes[i]->random = all_nodes[dist(rng)];
  }

  std::cout << "Graph created with " << num_nodes << " nodes\n";
  std::cout << "Press enter to continue...\n";
  std::cin.get();
}
