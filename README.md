# PING
Test the network response time.

## NOTE
This source code is for studying the RAW sockets, C++20 and CMake. The ping algorithm referenced iputils/ping, and the source code can be found at the following link:
https://github.com/iputils/iputils

## HOW TO USE
### 1. Install the prerequisites
```bash
$ sudo apt install libcap-dev
```

### 2. Clone and build
```bash
$ cd <your-workspace>
$ git clone https://github.com/danichoi737/ping.git
$ cd ping
$ mkdir build && cd build
$ cmake ..
$ make
```

### 3. Launch
```bash
$ ping <target-ip>
```
