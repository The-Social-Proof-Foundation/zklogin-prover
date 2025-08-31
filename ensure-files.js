/**
 * Script to verify and copy required circuit files to the correct locations
 * This helps ensure that both local development and Docker environments work correctly
 */

const fs = require('fs');
const path = require('path');

console.log('Checking and ensuring circuit files are in the correct locations...');

// Define file paths to check and copy if needed
const filesToCheck = [
    {
        source: path.join(__dirname, 'circuits', 'zklogin_mys_js', 'zklogin_mys.wasm'),
        target: path.join(__dirname, 'build', 'zklogin_mys_js', 'zklogin_mys.wasm'),
        type: 'WASM'
    },
    {
        source: path.join(__dirname, 'keys', 'zklogin_mys_final.zkey'),
        target: path.join(__dirname, 'build', 'zklogin_mys_final.zkey'),
        type: 'ZKEY'
    },
    {
        source: path.join(__dirname, 'circuits', 'zklogin_mys_js', 'generate_witness.js'),
        target: path.join(__dirname, 'build', 'zklogin_mys_js', 'generate_witness.js'),
        type: 'JS'
    },
    {
        source: path.join(__dirname, 'circuits', 'zklogin_mys_js', 'witness_calculator.js'),
        target: path.join(__dirname, 'build', 'zklogin_mys_js', 'witness_calculator.js'),
        type: 'JS'
    }
];

// Ensure directories exist
function ensureDirectoryExists(dirPath) {
    if (!fs.existsSync(dirPath)) {
        console.log(`Creating directory: ${dirPath}`);
        fs.mkdirSync(dirPath, { recursive: true });
        return true;
    }
    return false;
}

// Main directory checks
ensureDirectoryExists(path.join(__dirname, 'build'));
ensureDirectoryExists(path.join(__dirname, 'build', 'zklogin_mys_js'));
ensureDirectoryExists(path.join(__dirname, 'inputs'));
ensureDirectoryExists(path.join(__dirname, 'outputs'));

// Copy files if they don't exist in target location
let copiedFiles = 0;
let missingFiles = 0;

filesToCheck.forEach(file => {
    console.log(`Checking ${file.type} file: ${path.basename(file.source)}`);
    
    if (fs.existsSync(file.source)) {
        console.log(`✅ Source exists: ${file.source}`);
        
        if (!fs.existsSync(file.target)) {
            console.log(`⚠️ Target missing, copying to: ${file.target}`);
            try {
                fs.copyFileSync(file.source, file.target);
                console.log(`✅ Successfully copied ${file.type} file`);
                copiedFiles++;
            } catch (err) {
                console.error(`❌ Failed to copy ${file.type} file:`, err.message);
                missingFiles++;
            }
        } else {
            console.log(`✅ Target already exists: ${file.target}`);
        }
    } else {
        console.error(`❌ Source ${file.type} file missing: ${file.source}`);
        missingFiles++;
    }
    
    console.log('---');
});

// Summary
console.log('\n=== Summary ===');
console.log(`Total files checked: ${filesToCheck.length}`);
console.log(`Files copied: ${copiedFiles}`);
console.log(`Missing files: ${missingFiles}`);

if (missingFiles > 0) {
    console.log('\n⚠️ Some required files are missing. You may need to run:');
    console.log('npm run build-production');
    process.exit(1);
} else {
    console.log('\n✅ All required files are available.');
    process.exit(0);
}
