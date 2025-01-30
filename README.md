### Build

```bash
mkdir build && cd build
cmake ..
make
```

### Usage

In one terminal:
```bash
LD_PRELOAD=/path-to/libpointerscanner.so htop
```

In second terminal:
```bash
pkill -USR1 htop
```
This will cause htop to append to `memory_scan.log` (located in the same directory from which htop was launched).

htop is not needed - this will work with any single-process application which does not otherwise use SIGUSR1.
