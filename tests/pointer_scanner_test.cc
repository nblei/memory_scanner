// tests/pointer_scanner_test.cc
#include "memory_tools/pointer_scanner.hh"

#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unordered_set>
#include <vector>

namespace memory_tools {
namespace {

class PointerScannerTest : public ::testing::Test {
protected:
  void SetUp() override { scanner_.RefreshMemoryMap(); }

  PointerScanner scanner_;
};

TEST_F(PointerScannerTest, DetectsNullPointerAsFalse) {
  EXPECT_FALSE(scanner_.IsLikelyPointer(0));
}

TEST_F(PointerScannerTest, DetectsUnalignedAddressAsFalse) {
  // Get a valid heap pointer and make it unaligned
  int *valid_ptr = new int(42);
  uint64_t unaligned_addr = reinterpret_cast<uint64_t>(valid_ptr) + 1;
  EXPECT_FALSE(scanner_.IsLikelyPointer(unaligned_addr));
  delete valid_ptr;
}

TEST_F(PointerScannerTest, DetectsNonCanonicalFormAsFalse) {
  // Create an address with bits 48-63 not matching bit 47
  uint64_t non_canonical = 0x0F00000000000000;
  EXPECT_FALSE(scanner_.IsLikelyPointer(non_canonical));
}

TEST_F(PointerScannerTest, RecognizesValidHeapPointer) {
  int *heap_ptr = new int(42);
  EXPECT_TRUE(scanner_.IsLikelyPointer(reinterpret_cast<uint64_t>(heap_ptr)));
  delete heap_ptr;
}

TEST_F(PointerScannerTest, RecognizesValidStackPointer) {
  volatile int stack_array[1024];
  (void)stack_array;
  int stack_var;

  // Print relevant debug info
  std::cout << "Stack variable address: " << std::hex
            << reinterpret_cast<uint64_t>(&stack_var) << std::endl;

  // Dump memory regions for debugging
  std::ifstream maps("/proc/self/maps");
  std::string line;
  std::cout << "\nMemory regions:\n";

  while (std::getline(maps, line)) {
    if (line.find("[stack]") != std::string::npos) {
      std::cout << "Stack region: " << line << std::endl;
    }
  }

  // Force memory map refresh right before the test
  scanner_.RefreshMemoryMap();
  bool result =
      scanner_.IsLikelyPointer(reinterpret_cast<uint64_t>(&stack_var));
  EXPECT_TRUE(result) << "Failed to recognize stack pointer at address "
                      << std::hex << reinterpret_cast<uint64_t>(&stack_var);
}

TEST_F(PointerScannerTest, DetectsSmallIntegerAsFalse) {
  EXPECT_FALSE(scanner_.IsLikelyPointer(1024));
}

TEST_F(PointerScannerTest, HandlesVectorOfPointers) {
  std::vector<int *> pointers;
  for (int i = 0; i < 5; ++i) {
    pointers.push_back(new int(i));
  }

  for (auto ptr : pointers) {
    EXPECT_TRUE(scanner_.IsLikelyPointer(reinterpret_cast<uint64_t>(ptr)));
  }

  for (auto ptr : pointers) {
    delete ptr;
  }
}

TEST_F(PointerScannerTest, MemoryRegionParsing) {
  // Force a refresh and verify we can read memory maps
  EXPECT_TRUE(scanner_.RefreshMemoryMap());
}

TEST_F(PointerScannerTest, ScanCallbackIsCalled) {
  // Allocate some memory and keep track of its address
  int *test_ptr = new int(42);
  uint64_t test_addr = reinterpret_cast<uint64_t>(test_ptr);
  bool found_test_ptr = false;

  scanner_.ScanForPointers([&](uint64_t addr, uint64_t value) {
    (void)addr;
    if (value == test_addr) {
      found_test_ptr = true;
    }
  });

  EXPECT_TRUE(found_test_ptr);
  delete test_ptr;
}

TEST_F(PointerScannerTest, HandlesDifferentPointerTypes) {
  // Test different pointer types
  struct TestStruct {
    int x;
    double y;
  };

  auto int_ptr = std::make_unique<int>(42);
  auto double_ptr = std::make_unique<double>(3.14);
  auto struct_ptr = std::make_unique<TestStruct>();
  auto array_ptr = std::make_unique<int[]>(10);

  EXPECT_TRUE(
      scanner_.IsLikelyPointer(reinterpret_cast<uint64_t>(int_ptr.get())));
  EXPECT_TRUE(
      scanner_.IsLikelyPointer(reinterpret_cast<uint64_t>(double_ptr.get())));
  EXPECT_TRUE(
      scanner_.IsLikelyPointer(reinterpret_cast<uint64_t>(struct_ptr.get())));
  EXPECT_TRUE(
      scanner_.IsLikelyPointer(reinterpret_cast<uint64_t>(array_ptr.get())));
}

TEST_F(PointerScannerTest, HandlesSharedMemory) {
  // Create a shared memory region
  const int shm_size = 4096; // One page
  int shm_fd = shm_open("/test_shm", O_CREAT | O_RDWR, 0666);
  ASSERT_NE(shm_fd, -1);
  ASSERT_EQ(ftruncate(shm_fd, shm_size), 0);

  void *shm_ptr =
      mmap(nullptr, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
  ASSERT_NE(shm_ptr, MAP_FAILED);

  // Refresh memory map to include new shared memory
  scanner_.RefreshMemoryMap();

  EXPECT_TRUE(scanner_.IsLikelyPointer(reinterpret_cast<uint64_t>(shm_ptr)));

  // Cleanup
  munmap(shm_ptr, shm_size);
  shm_unlink("/test_shm");
  close(shm_fd);
}

TEST_F(PointerScannerTest, StressTest) {
  constexpr size_t allocation_count = 1000;
  std::vector<void *> pointers;
  pointers.reserve(allocation_count);

  // Create many allocations of different sizes
  // std::cout << "Creating " << allocation_count << " test allocations..."
  //           << std::endl;
  for (size_t i = 0; i < allocation_count; ++i) {
    size_t size = (i % 100) + 1; // Vary sizes from 1 to 100 bytes
    void *ptr = malloc(size);
    // std::cout << "Allocated " << size << " bytes at " << ptr << std::endl;
    pointers.push_back(ptr);
    scanner_.RefreshMemoryMap();
    EXPECT_TRUE(scanner_.IsLikelyPointer(reinterpret_cast<uint64_t>(ptr)))
        << "Failed to recognize pointer: " << ptr;
  }

  // Count how many of our test pointers we find
  size_t found_count = 0;
  std::unordered_set<uint64_t> our_pointers;
  for (void *ptr : pointers) {
    our_pointers.insert(reinterpret_cast<uint64_t>(ptr));
  }

  // std::cout << "Starting memory scan..." << std::endl;
  scanner_.ScanForPointers([&](uint64_t addr, uint64_t value) {
    (void)addr;
    if (our_pointers.find(value) != our_pointers.end()) {
      found_count++;
      // std::cout << "Found one of our pointers: " << std::hex << value
      //           << " at address " << addr << std::endl;
    }
  });

  // std::cout << "Found " << found_count << " out of " << allocation_count
  //           << " test pointers" << std::endl;

  // We should find at least some of our pointers
  EXPECT_GT(found_count, 0) << "Failed to find any of our test pointers";

  // Cleanup
  for (void *ptr : pointers) {
    free(ptr);
  }
}

TEST_F(PointerScannerTest, StressTestDeterministic) {
  constexpr size_t allocation_count = 1000;
  std::vector<void *> pointers;
  pointers.reserve(allocation_count);

  // Force memory map refresh before starting
  scanner_.RefreshMemoryMap();

  // Create allocations and immediately write to them to ensure they're paged in
  for (size_t i = 0; i < allocation_count; ++i) {
    size_t size = (i % 100) + 1;
    void *ptr = malloc(size);
    // Write to the memory to ensure it's paged in
    memset(ptr, 0x42, size);
    pointers.push_back(ptr);

    // Verify each pointer is recognized immediately
    ASSERT_TRUE(scanner_.IsLikelyPointer(reinterpret_cast<uint64_t>(ptr)))
        << "Failed on pointer " << i << ": " << ptr;
  }

  // Create a second vector that points to our pointers
  std::vector<void **> pointer_locations;
  pointer_locations.reserve(allocation_count);
  for (void *ptr : pointers) {
    void **loc = new void *;
    *loc = ptr; // Store the pointer value
    pointer_locations.push_back(loc);
  }

  // Refresh memory map again after all allocations
  scanner_.RefreshMemoryMap();

  size_t found_count = 0;
  std::unordered_set<uint64_t> expected_pointers;
  for (void *ptr : pointers) {
    expected_pointers.insert(reinterpret_cast<uint64_t>(ptr));
  }

  scanner_.ScanForPointers([&](uint64_t addr, uint64_t value) {
    (void)addr;
    if (expected_pointers.find(value) != expected_pointers.end()) {
      found_count++;
    }
  });

  // We should find at least as many pointers as we have pointer_locations
  EXPECT_GE(found_count, pointer_locations.size())
      << "Only found " << found_count << " pointers out of "
      << pointer_locations.size() << " expected";

  // Cleanup in reverse order
  for (void **loc : pointer_locations) {
    delete loc;
  }
  for (void *ptr : pointers) {
    free(ptr);
  }
}

// Test fixture for death tests
class PointerScannerDeathTest : public PointerScannerTest {};

TEST_F(PointerScannerDeathTest, CrashesOnInvalidMemoryAccess) {
  // Test that accessing an invalid pointer causes a crash
  void *invalid_ptr = reinterpret_cast<void *>(0x1000); // Usually unmapped
  EXPECT_FALSE(
      scanner_.IsLikelyPointer(reinterpret_cast<uint64_t>(invalid_ptr)));
}

TEST_F(PointerScannerTest, ScanStatsAreAccurate) {
  // Allocate some test pointers
  std::vector<int *> test_ptrs;
  for (int i = 0; i < 10; i++) {
    test_ptrs.push_back(new int(i));
  }

  int pointers_found = 0;
  scanner_.ScanForPointers(
      [&pointers_found](uint64_t, uint64_t) { pointers_found++; });

  const auto &stats = scanner_.GetLastScanStats();

  std::cout << "Scan Statistics:\n"
            << "  Regions scanned: " << stats.regions_scanned << "\n"
            << "  Total bytes scanned: " << stats.total_bytes_scanned << "\n"
            << "  Bytes skipped: " << stats.bytes_skipped << "\n"
            << "  Pointers found: " << stats.pointers_found << "\n"
            << "  Scan time (ms): " << stats.scan_time_ms << std::endl;

  EXPECT_GT(stats.regions_scanned, 0);
  EXPECT_GT(stats.total_bytes_scanned, 0);
  EXPECT_GT(stats.pointers_found, 0);
  EXPECT_EQ(pointers_found, stats.pointers_found);

  // Cleanup
  for (auto ptr : test_ptrs) {
    delete ptr;
  }
}

} // namespace
} // namespace memory_tools

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
