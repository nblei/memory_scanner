#include <CLI/CLI.hpp>
#include <cstdlib>
#include <random>
#include <vector>

struct Node {
  unsigned value;
  Node *left;
  Node *right;
  Node *random_link;
};

Node *create_tree(unsigned depth, std::vector<Node *> &all_nodes,
                  std::mt19937 &rng, double link_probability) {
  if (depth == 0) {
    return nullptr;
  }

  Node *node = new Node{static_cast<unsigned>(all_nodes.size()), nullptr,
                        nullptr, nullptr};
  all_nodes.push_back(node);

  node->left = create_tree(depth - 1, all_nodes, rng, link_probability);
  node->right = create_tree(depth - 1, all_nodes, rng, link_probability);

  if (!all_nodes.empty()) {
    std::bernoulli_distribution do_link(link_probability);
    if (do_link(rng)) {
      std::uniform_int_distribution<size_t> dist(0, all_nodes.size() - 1);
      node->random_link = all_nodes[dist(rng)];
    }
  }

  return node;
}

int main(int argc, char *argv[]) {
  CLI::App app{"Creates a binary tree with random cross-links"};

  unsigned depth = 10;
  double link_prob = 0.5;

  app.add_option("-d,--depth", depth, "Tree depth")
      ->required()
      ->check(CLI::PositiveNumber)
      ->check(CLI::Range(1u, 20u));
  app.add_option("-p,--link-probability", link_prob,
                 "Probability of random links")
      ->check(CLI::Range(0.0, 1.0));

  CLI11_PARSE(app, argc, argv);

  std::random_device rd;
  std::mt19937 rng(rd());
  std::vector<Node *> all_nodes;

  create_tree(depth, all_nodes, rng, link_prob);

  std::cout << "Graph tree with depth " << depth << " and " << all_nodes.size()
            << " nodes.\n Press enter to continue...\n";
  std::cin.get();
}
