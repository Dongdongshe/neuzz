# NEUZZ: a neural-network assited fuzzer (S&P'19)
See S&P'19 paper [NEUZZ: Efficient Fuzzing with NeuralProgram Smoothing] for detail.
## Prerequisite
Tested on Ubuntu 16.04 and 18.04 with Tensorflow 1.8.0 and Keras 2.2.3
- Python 2.7
- Tensorflow
- Keras
## Build
```bash
    gcc -O3 -funroll-loops ./neuzz.c -o neuzz
```
## Usage
We use a sample program readelf as an example.
Open a terminal, start nn module
```bash
    #python nn.py [program [arguments]]
    python nn.py ./readelf -a
```
open another terminal, start neuzz module.
```bash
    #./neuzz -i in_dir -o out_dir -l mutation_len [program path [arguments]] @@
    ./neuzz -i neuzz_in -o seeds -l 7506 ./readelf -a @@  
```
## Sample programs
Try 10 real-world programs on NEUZZ. Check setup details at programs/[program names]/README.


