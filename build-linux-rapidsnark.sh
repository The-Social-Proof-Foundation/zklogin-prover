#!/bin/bash

echo "Building Linux rapidsnark binary..."

# Build rapidsnark for Linux using Docker
docker run --rm -v $(pwd):/output ubuntu:22.04 bash -c '
    apt-get update && apt-get install -y \
        build-essential \
        git \
        libgmp-dev \
        libsodium-dev \
        nasm \
        curl \
        cmake \
        libomp-dev \
        nodejs \
        npm
    
    git clone https://github.com/iden3/rapidsnark.git
    cd rapidsnark
    git submodule init
    git submodule update
    
    mkdir build_linux
    cd build_linux
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../package_linux
    make -j$(nproc)
    make install
    
    cp ../package_linux/bin/prover /output/rapidsnark/rapidsnark-linux
    chmod +x /output/rapidsnark/rapidsnark-linux
'

echo "Linux binary created at rapidsnark/rapidsnark-linux" 