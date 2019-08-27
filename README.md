# PIN Strace

A strace implementation using
[PIN from Intel](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool).

## Build and Usage

You will need a copy of the PIN source release available
[here](https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz).

To build:
```bash
    export pinurl="https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz"
    export pinstracerepo="git@github.com:daniel-grumberg/pin_strace.git"
    wget -q "$pinurl" -O /tmp/pintree.tar.gz
    mkdir pintree
    tar -C pintree -xf /tmp/pintree.tar.gz --strip-components 1
    git clone "$pinstracerepo" pinstrace
    cd pinstrace
    PIN_ROOT="../pintree" make
```

To run:
```bash
pintree/pin -t pinstrace/obj-intel64/PinStrace.so -o /tmp/pinstrace.log -- command_to_run
```

