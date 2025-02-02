#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

// This program allocates memory in known patterns and waits
// to be scanned by the process scanner

int main() {
  // Print our PID so scanner can find us
  std::cout << "Target process PID: " << getpid() << std::endl;

  // Allocate some memory in different ways
  std::vector<void *> allocations;

  // 1. Simple heap allocation
  int *heap_int = new int(42);
  allocations.push_back(heap_int);

  // 2. Array on heap
  int *heap_array = new int[100];
  for (int i = 0; i < 100; i++) {
    heap_array[i] = i;
  }
  allocations.push_back(heap_array);

  // 3. Vector of pointers
  std::vector<int *> pointer_vector;
  for (int i = 0; i < 10; i++) {
    pointer_vector.push_back(new int(i));
    allocations.push_back(pointer_vector.back());
  }

  // Print addresses for verification
  std::cout << "Known pointer addresses:\n";
  for (void *ptr : allocations) {
    std::cout << "  " << ptr << "\n";
  }
  std::cout << std::flush;

  // Wait for scan
  std::cout << "Waiting to be scanned (60 seconds)...\n" << std::flush;
  std::this_thread::sleep_for(std::chrono::seconds(60));

  // Cleanup
  delete heap_int;
  delete[] heap_array;
  for (auto ptr : pointer_vector) {
    delete ptr;
  }

  return 0;
}
