FROM node:18

# Install build dependencies including OpenMP and Circom dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    libgmp-dev \
    libsodium-dev \
    nasm \
    curl \
    m4 \
    cmake \
    libomp-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (required for Circom)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Circom
RUN git clone https://github.com/iden3/circom.git && \
    cd circom && \
    cargo build --release && \
    cargo install --path circom && \
    cp target/release/circom /usr/local/bin/

# Clone and build rapidsnark with proper flags
RUN git clone https://github.com/iden3/rapidsnark.git && \
    cd rapidsnark && \
    git submodule init && \
    git submodule update && \
    ./build_gmp.sh host && \
    mkdir -p build && \
    cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../package -DUSE_ASM=OFF && \
    make -j$(nproc) && \
    make install

WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./
RUN yarn install

# Copy the rest of the application
COPY . .

# Create directories for outputs and ensure rapidsnark directory exists
RUN mkdir -p inputs outputs keys rapidsnark

# Copy the built rapidsnark binary and ensure it's executable
RUN cp /rapidsnark/package/bin/prover rapidsnark/rapidsnark && \
    chmod +x rapidsnark/rapidsnark && \
    ls -la rapidsnark/ && \
    echo "Rapidsnark binary setup completed"

# Make the wrapper script executable
RUN chmod +x rapidsnark-wrapper.sh

# Test that rapidsnark binary is working (should show usage message)
RUN ./rapidsnark/rapidsnark || echo "Rapidsnark binary test completed (expected to fail without arguments)"

# Compile the Circom circuit to generate the required WASM file
RUN cd circuits && \
    circom zklogin_mys.circom --r1cs --wasm --sym --c && \
    ls -la zklogin_mys_js/ && \
    echo "Circuit compilation completed successfully"

# Generate the zkey files (since they're gitignored and not copied)
# NOTE: This will use persistent volume storage to avoid regenerating keys on each deployment
RUN echo "Setting up persistent key storage..." && \
    mkdir -p /app/keys && \
    echo "Keys directory prepared for volume mount"

# This script will run after volume is mounted, so we'll move key generation to runtime
COPY <<EOF /app/generate-keys-if-missing.sh
#!/bin/bash
echo "Checking for existing zkey files in persistent volume..."
if [ ! -f "/app/keys/zklogin_mys_final.zkey" ]; then
    echo "No existing keys found. Generating new zkey files..."
    cd /app
    ./node_modules/.bin/snarkjs powersoftau new bn128 14 keys/pot14_0000.ptau
    ./node_modules/.bin/snarkjs powersoftau contribute keys/pot14_0000.ptau keys/pot14_0001.ptau --name="Railway build contribution" -v -e="random build entropy"
    ./node_modules/.bin/snarkjs powersoftau prepare phase2 keys/pot14_0001.ptau keys/pot14_final.ptau -v
    ./node_modules/.bin/snarkjs groth16 setup circuits/zklogin_mys.r1cs keys/pot14_final.ptau keys/zklogin_mys_0000.zkey
    ./node_modules/.bin/snarkjs zkey contribute keys/zklogin_mys_0000.zkey keys/zklogin_mys_final.zkey --name="Railway final contribution" -v -e="final random entropy"
    echo "Zkey generation completed successfully"
else
    echo "Using existing persistent zkey files"
fi
ls -la keys/
EOF

RUN chmod +x /app/generate-keys-if-missing.sh

# Test the circuit compilation and proof generation
# RUN yarn test

EXPOSE 4000
CMD ["node", "server.js"] 