#include <CLI/CLI.hpp>
#include <cstdlib>
#include <iostream>
#include <random>
#include <vector>

struct Node {
  unsigned value;
  std::vector<Node *> edges;
  Node(unsigned v, unsigned edge_count)
      : value(v), edges(edge_count, nullptr) {}
};

int main(int argc, char *argv[]) {
  CLI::App app{
      "Creates a cyclic graph with configurable node count and edge density"};

  unsigned num_nodes = 1000;
  unsigned edges_per_node = 3;

  app.add_option("-n,--nodes", num_nodes, "Number of nodes")
      ->required()
      ->check(CLI::PositiveNumber)
      ->check(CLI::Range(1u, 1000000u));
  app.add_option("-e,--edges", edges_per_node, "Edges per node")
      ->check(CLI::Range(0u, 1000u));

  CLI11_PARSE(app, argc, argv);

  std::cout << "Creating graph with " << num_nodes << " nodes and "
            << edges_per_node << " edges per node\n";

  std::random_device rd;
  std::mt19937 rng(rd());

  std::vector<Node *> nodes;
  nodes.reserve(num_nodes);

  for (unsigned i = 0; i < num_nodes; i++) {
    nodes.push_back(new Node(i, edges_per_node));
  }

  std::uniform_int_distribution<size_t> dist(0, nodes.size() - 1);
  for (auto *node : nodes) {
    for (unsigned i = 0; i < edges_per_node; i++) {
      node->edges[i] = nodes[dist(rng)];
    }
  }

  std::cout << "Graph created. Press enter to continue...\n";
  std::cin.get();
}
