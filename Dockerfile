FROM node:18

# Install build dependencies including OpenMP
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

# Copy the built rapidsnark binary
RUN cp /rapidsnark/package/bin/prover rapidsnark/rapidsnark && \
    chmod +x rapidsnark/rapidsnark

EXPOSE 4000
CMD ["node", "server.js"] 