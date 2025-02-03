### Build

```bash
mkdir build && cd build
cmake ..
make
```

### Usage

In one terminal:
```bash
./process_monitor <Program>
```

This will execute Program and periodically analyze its memory.
Results are logged to `memory_scanner.log`
