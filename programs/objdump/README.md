1. The tested binaries are compiled into 32bit format (to compare with Vuzzer). NEUZZ can actually run on any 64bit binaries. Install some required libraies for 32bit binaries.
```sh
    sudo dpkg --add-architecture i386
    sudo apt-get update
    sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386 lib32z1
```

2. Set CPU scaling algorithm and core dump notification with root. 
```sh
    cd /sys/devices/system/cpu
    echo performance | tee cpu*/cpufreq/scaling_governor
    echo core >/proc/sys/kernel/core_pattern
```

3. Copy neuzz, nn.py, afl-showmap to this directory.

4. Create output directory
```sh  
    mkdir seeds
```

5. Open a terminal to start NN module.
```sh  
    python nn.py ./objdump -D 
```

6. Open another terminal to start NEUZZ module.
```sh
    # -l, file len is obtained by maximum file lens in the neuzz_in ( ls -lS neuzz_in|head )
    ./neuzz -i neuzz_in -o seeds -l 7377 ./objdump -D @@
```
