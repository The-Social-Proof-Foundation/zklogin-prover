#!/bin/bash

echo "🔧 Building zkLogin Production Server"
echo "====================================="

# Ensure we're in the right directory
cd "$(dirname "$0")"

# 1. Clean and create build directory
echo "1. Setting up build directory..."
rm -rf build/
mkdir -p build/zklogin_myso_js

# 2. Compile the circuit
echo "2. Compiling Circom circuit..."
cd circuits
circom zklogin_myso.circom --r1cs --wasm --sym --c
if [ $? -ne 0 ]; then
    echo "❌ Circuit compilation failed"
    exit 1
fi
cd ..

# 3. Copy circuit files to build directory
echo "3. Copying circuit files to build directory..."
cp circuits/zklogin_myso_js/* build/zklogin_myso_js/
cp circuits/zklogin_myso.r1cs build/
cp circuits/zklogin_myso.sym build/

# 4. Generate zkey files if they don't exist
echo "4. Setting up zkey files..."
if [ ! -f "keys/zklogin_myso_final.zkey" ]; then
    echo "Generating new zkey files..."
    mkdir -p keys
    
    # Generate Powers of Tau
    ./node_modules/.bin/snarkjs powersoftau new bn128 22 keys/pot22_0000.ptau
    ./node_modules/.bin/snarkjs powersoftau contribute keys/pot22_0000.ptau keys/pot22_0001.ptau --name="Production build contribution" -v -e="production random entropy"
    ./node_modules/.bin/snarkjs powersoftau prepare phase2 keys/pot22_0001.ptau keys/pot22_final.ptau -v
    
    # Generate zkey files
    ./node_modules/.bin/snarkjs groth16 setup build/zklogin_myso.r1cs keys/pot22_final.ptau keys/zklogin_myso_0000.zkey
    ./node_modules/.bin/snarkjs zkey contribute keys/zklogin_myso_0000.zkey keys/zklogin_myso_final.zkey --name="Production final contribution" -v -e="final production entropy"
    
    echo "✅ Zkey generation completed"
else
    echo "Using existing zkey files"
fi

# 5. Copy zkey files to build directory
echo "5. Copying zkey files to build directory..."
cp keys/zklogin_myso_final.zkey build/zklogin_myso_final.zkey

# 6. Verify all required files exist
echo "6. Verifying build files..."
REQUIRED_FILES=(
    "build/zklogin_myso_js/zklogin_myso.wasm"
    "build/zklogin_myso_js/witness_calculator.js"
    "build/zklogin_myso_final.zkey"
    "build/zklogin_myso.r1cs"
)

ALL_FILES_EXIST=true
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "❌ Missing required file: $file"
        ALL_FILES_EXIST=false
    else
        echo "✅ Found: $file ($(du -h "$file" | cut -f1))"
    fi
done

if [ "$ALL_FILES_EXIST" = true ]; then
    echo ""
    echo "🎉 Production build completed successfully!"
    echo "All required files are present:"
    echo "  - Circuit WASM: $(du -h build/zklogin_myso_js/zklogin_myso.wasm | cut -f1)"
    echo "  - Zkey file: $(du -h build/zklogin_myso_final.zkey | cut -f1)"
    echo "  - Build directory ready for deployment"
else
    echo ""
    echo "❌ Production build failed - missing required files"
    exit 1
fi 