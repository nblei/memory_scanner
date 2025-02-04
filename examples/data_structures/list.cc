#include <CLI/CLI.hpp>
#include <cstdlib>
#include <list>

int main(int argc, char *argv[]) {
  CLI::App app{"Creates a linked list of specified size for memory analysis"};

  unsigned num_nodes = 1000;
  app.add_option("-n,--nodes", num_nodes, "Number of nodes to create")
      ->required()
      ->check(CLI::PositiveNumber)
      ->check(CLI::Range(1u, 1000000u));

  CLI11_PARSE(app, argc, argv);

  std::list<char *> vals;
  vals.resize(num_nodes);
  for (unsigned i = 0; i < num_nodes; ++i) {
    char *k = new char;
    *k = 23;
    vals.emplace_back(k);
  }
  std::cout << "Created list with " << num_nodes << " nodes.  ";
  std::cout << "Press enter to continue...\n";
  std::cin.get();

  return 0;
}
