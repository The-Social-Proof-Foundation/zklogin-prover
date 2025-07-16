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

# Run npm run setup to build circuit and generate all required files
RUN echo "Building circuit and generating keys..." && \
    npm run setup && \
    echo "Setup completed successfully" && \
    ls -la build/ && \
    ls -la build/zklogin_mys_js/ && \
    echo "Verifying required files:" && \
    echo "WASM: $(test -f build/zklogin_mys_js/zklogin_mys.wasm && echo 'EXISTS' || echo 'MISSING')" && \
    echo "ZKEY: $(test -f build/zklogin_mys_final.zkey && echo 'EXISTS' || echo 'MISSING')"

EXPOSE 4000
CMD ["node", "server.js"] 