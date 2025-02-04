#include <CLI/CLI.hpp>
#include <cstdlib>
#include <random>
#include <vector>

struct SkipNode {
  unsigned value;
  static const unsigned MAX_LEVEL = 16;
  std::vector<SkipNode *> forward;

  explicit SkipNode(unsigned v, unsigned level)
      : value(v), forward(level, nullptr) {}
};

int main(int argc, char *argv[]) {
  CLI::App app{
      "Creates a skip list with configurable parameters for memory analysis"};

  unsigned num_nodes = 1000;
  double prob = 0.5;

  app.add_option("-n,--nodes", num_nodes, "Number of nodes to create")
      ->required()
      ->check(CLI::PositiveNumber)
      ->check(CLI::Range(1u, 10000000u));
  app.add_option("-p,--probability", prob, "Probability of level increase")
      ->check(CLI::Range(0.0, 1.0));

  CLI11_PARSE(app, argc, argv);

  std::random_device rd;
  std::mt19937 rng(rd());
  std::bernoulli_distribution level_up(prob);

  std::vector<SkipNode *> nodes;
  nodes.reserve(num_nodes);
  for (unsigned i = 0; i < num_nodes; i++) {
    unsigned level = 1;
    while (level < SkipNode::MAX_LEVEL && level_up(rng)) {
      level++;
    }
    nodes.push_back(new SkipNode(i, level));
  }

  std::cout << "Created skip-list with " << num_nodes << " nodes.  ";
  std::cout << "Press enter to continue...\n";
  std::cin.get();

  return 0;
}
