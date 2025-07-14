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

# Create directories for outputs
RUN mkdir -p inputs outputs keys rapidsnark

# Copy the built rapidsnark binary
RUN cp /rapidsnark/package/bin/prover rapidsnark/rapidsnark && \
    chmod +x rapidsnark/rapidsnark

# Make the wrapper script executable
RUN chmod +x rapidsnark-wrapper.sh

# Compile the Circom circuit to generate the required WASM file
RUN cd circuits && \
    circom zklogin_mys.circom --r1cs --wasm --sym --c && \
    ls -la zklogin_mys_js/ && \
    echo "Circuit compilation completed successfully"

# Test the circuit compilation and proof generation
# RUN yarn test

EXPOSE 4000
CMD ["node", "server.js"] 