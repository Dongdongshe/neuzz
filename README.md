# NEUZZ: a neural-network-assisted fuzzer (S&P'19)
See IEEE S&P(Oakland)'19 [slides](https://drive.google.com/file/d/1_A33wucTOA2nZpKVArvsXajh-2LNrCZK/view?usp=sharing) and paper [NEUZZ: Efficient Fuzzing with Neural Program Smoothing](https://arxiv.org/abs/1807.05620) for details.
## Prerequisite
Tested on a machine with Nvidia 1080Ti, Ubuntu 16.04/18.04, Tensorflow 1.8.0 and Keras 2.2.3.<br/>
We recommend running NEUZZ on a machine with a Nvidia 1080Ti or higher for efficient NN training.
- Python 2.7
- Tensorflow
- Keras
## Build
```bash
    gcc -O3 -funroll-loops ./neuzz.c -o neuzz
```
## Usage
We use a sample program readelf as an example.<br/>
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
If you want to try NEUZZ on a new program, 
1. Compile the new program from source code using afl-gcc.
2. Collect the training data by running AFL on the binary for a while(about an hour), then copy the queue folder to neuzz_in.
3. Follow the above two steps to start NN module and NEUZZ module.

### Running with ASAN

If your binary is compiled with ASAN instrumentation, do the following to run
it properly.

Pass `--enable-asan` to `nn.py`:
```bash
    python nn.py --enable-asan ./readelf -a
```

And pass `-m none` to `./nuezz` as you would to afl:
```bash
    ./neuzz -m none -i neuzz_in -o seeds -l 7506 ./readelf -a @@
```


## Sample programs
Try 10 real-world programs on NEUZZ. Check setup details at programs/[program names]/README.

## Contact
Feel free to send me email about Neuzz. dongdong at cs.columbia.edu


