#include <algorithm>
#include <memory>
#include <optional>
#include <random>
#include <vector>

namespace memory_tools {

template <typename T, size_t B = 6> class BTree {
private:
  struct Node {
    std::vector<T> keys;
    std::vector<std::unique_ptr<Node>> children;
    bool leaf{true};

    Node() {
      keys.reserve(2 * B - 1);
      children.reserve(2 * B);
    }
  };

  std::unique_ptr<Node> root_;
  size_t size_{0};

public:
  BTree() : root_(std::make_unique<Node>()) {}

  void insert(const T &key) {
    auto *root = root_.get();
    if (root->keys.size() == 2 * B - 1) {
      auto new_root = std::make_unique<Node>();
      new_root->leaf = false;
      new_root->children.push_back(std::move(root_));
      root_ = std::move(new_root);
      split_child(root_.get(), 0);
      insert_non_full(root_.get(), key);
    } else {
      insert_non_full(root, key);
    }
    size_++;
  }

  std::optional<T> search(const T &key) const {
    return search_internal(root_.get(), key);
  }

  size_t size() const { return size_; }

private:
  void split_child(Node *parent, size_t index) {
    auto *y = parent->children[index].get();
    auto z = std::make_unique<Node>();
    z->leaf = y->leaf;

    // Split keys
    for (size_t j = 0; j < B - 1; j++) {
      z->keys.push_back(y->keys[j + B]);
    }
    y->keys.resize(B - 1);

    // Split children if not leaf
    if (!y->leaf) {
      for (size_t j = 0; j < B; j++) {
        z->children.push_back(std::move(y->children[j + B]));
      }
      y->children.resize(B);
    }

    // Insert median key into parent
    parent->keys.insert(parent->keys.begin() + static_cast<ptrdiff_t>(index),
                        y->keys[B - 1]);
    parent->children.insert(parent->children.begin() +
                                static_cast<ptrdiff_t>(index + 1),
                            std::move(z));
  }

  void insert_non_full(Node *node, const T &key) {
    int i = static_cast<int>(node->keys.size()) - 1;

    if (node->leaf) {
      while (i >= 0 && key < node->keys[static_cast<size_t>(i)]) {
        i--;
      }
      node->keys.insert(node->keys.begin() + static_cast<ptrdiff_t>(i + 1),
                        key);
    } else {
      while (i >= 0 && key < node->keys[static_cast<size_t>(i)]) {
        i--;
      }
      i++;

      auto *child = node->children[static_cast<size_t>(i)].get();
      if (child->keys.size() == 2 * B - 1) {
        split_child(node, static_cast<size_t>(i));
        if (key > node->keys[static_cast<size_t>(i)]) {
          i++;
        }
      }
      insert_non_full(node->children[static_cast<size_t>(i)].get(), key);
    }
  }

  std::optional<T> search_internal(const Node *node, const T &key) const {
    size_t i = 0;
    while (i < node->keys.size() && key > node->keys[i]) {
      i++;
    }

    if (i < node->keys.size() && key == node->keys[i]) {
      return node->keys[i];
    }

    if (node->leaf) {
      return std::nullopt;
    }

    return search_internal(node->children[i].get(), key);
  }
};

} // namespace memory_tools
