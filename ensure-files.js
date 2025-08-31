/**
 * Script to verify and copy required circuit files to the correct locations
 * This helps ensure that both local development and Docker environments work correctly
 */

const fs = require('fs');
const path = require('path');

console.log('Checking and ensuring circuit files are in the correct locations...');

// Define all possible paths for source files
const wasm = {
    sources: [
        path.join(__dirname, 'circuits', 'zklogin_mys_js', 'zklogin_mys.wasm'),
        path.join(__dirname, 'build', 'zklogin_mys_js', 'zklogin_mys.wasm'),
        path.join(__dirname, 'zklogin_mys.wasm')
    ],
    target: path.join(__dirname, 'build', 'zklogin_mys_js', 'zklogin_mys.wasm'),
    type: 'WASM'
};

const zkey = {
    sources: [
        path.join(__dirname, 'keys', 'zklogin_mys_final.zkey'),
        path.join(__dirname, 'zklogin_mys_final.zkey'),
        path.join(__dirname, 'build', 'zklogin_mys_final.zkey')
    ],
    target: path.join(__dirname, 'build', 'zklogin_mys_final.zkey'),
    type: 'ZKEY'
};

const generateWitness = {
    sources: [
        path.join(__dirname, 'circuits', 'zklogin_mys_js', 'generate_witness.js'),
        path.join(__dirname, 'build', 'zklogin_mys_js', 'generate_witness.js')
    ],
    target: path.join(__dirname, 'build', 'zklogin_mys_js', 'generate_witness.js'),
    type: 'JS'
};

const witnessCalculator = {
    sources: [
        path.join(__dirname, 'circuits', 'zklogin_mys_js', 'witness_calculator.js'),
        path.join(__dirname, 'build', 'zklogin_mys_js', 'witness_calculator.js')
    ],
    target: path.join(__dirname, 'build', 'zklogin_mys_js', 'witness_calculator.js'),
    type: 'JS'
};

const filesToCheck = [wasm, zkey, generateWitness, witnessCalculator];

// Ensure directories exist
function ensureDirectoryExists(dirPath) {
    if (!fs.existsSync(dirPath)) {
        console.log(`Creating directory: ${dirPath}`);
        try {
            fs.mkdirSync(dirPath, { recursive: true });
            return true;
        } catch (err) {
            console.error(`Error creating directory ${dirPath}:`, err.message);
            return false;
        }
    }
    return true;
}

// Find a file from multiple possible sources
function findFile(sources) {
    for (const source of sources) {
        if (fs.existsSync(source)) {
            return source;
        }
    }
    return null;
}

// List all files in a directory
function listDirectory(dir) {
    try {
        if (fs.existsSync(dir)) {
            console.log(`Contents of ${dir}:`);
            const files = fs.readdirSync(dir);
            if (files.length === 0) {
                console.log('  (empty directory)');
            } else {
                files.forEach(file => console.log(`  ${file}`));
            }
        } else {
            console.log(`Directory doesn't exist: ${dir}`);
        }
    } catch (err) {
        console.error(`Error listing directory ${dir}:`, err.message);
    }
}

// Main directory checks
console.log('\nChecking directories:');
ensureDirectoryExists(path.join(__dirname, 'build'));
ensureDirectoryExists(path.join(__dirname, 'build', 'zklogin_mys_js'));

// List directories for debugging
console.log('\nDirectory contents:');
listDirectory(__dirname);
listDirectory(path.join(__dirname, 'circuits'));
listDirectory(path.join(__dirname, 'build'));
listDirectory(path.join(__dirname, 'build', 'zklogin_mys_js'));
listDirectory(path.join(__dirname, 'keys'));

// Copy files if they don't exist in target location
let copiedFiles = 0;
let missingFiles = 0;

console.log('\nChecking required files:');
filesToCheck.forEach(file => {
    console.log(`\nChecking ${file.type} file: ${path.basename(file.target)}`);
    
    // Check all possible sources
    const sourcePath = findFile(file.sources);
    
    if (sourcePath) {
        console.log(`✅ Found source at: ${sourcePath}`);
        
        // Check if target exists
        const targetExists = fs.existsSync(file.target);
        
        if (!targetExists) {
            // If target directory doesn't exist, create it
            const targetDir = path.dirname(file.target);
            ensureDirectoryExists(targetDir);
            
            // Copy file
            try {
                fs.copyFileSync(sourcePath, file.target);
                console.log(`✅ Successfully copied ${file.type} file to: ${file.target}`);
                copiedFiles++;
            } catch (err) {
                console.error(`❌ Failed to copy ${file.type} file:`, err.message);
                missingFiles++;
            }
        } else {
            console.log(`✅ Target already exists: ${file.target}`);
        }
    } else {
        console.error(`❌ ${file.type} file not found in any of the checked locations`);
        console.log('  Searched in:');
        file.sources.forEach(s => console.log(`  - ${s}`));
        missingFiles++;
    }
});

// Summary
console.log('\n=== Summary ===');
console.log(`Total files checked: ${filesToCheck.length}`);
console.log(`Files copied: ${copiedFiles}`);
console.log(`Missing files: ${missingFiles}`);

if (missingFiles > 0) {
    console.log('\n⚠️ Warning: Some files were not found, but we will continue anyway.');
    console.log('The server will try multiple paths at runtime.');
    // Exit with success even if files are missing
    process.exit(0);
} else {
    console.log('\n✅ All required files are available.');
    process.exit(0);
}