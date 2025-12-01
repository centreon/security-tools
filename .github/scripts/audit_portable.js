const fs = require('fs');
const path = require('path');
const https = require('https'); // Added https module
const { execSync } = require('child_process');

// --- COLORS FOR CONSOLE ---
const RESET = "\x1b[0m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const MAGENTA = "\x1b[35m";
const WHITE_BOLD = "\x1b[1m";

// --- CONFIGURATION ---

// [ACTION REQUIRED] Paste your CSV URL inside the quotes below
const CSV_URL = "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/main/shai-hulud-2.0/consolidated_iocs.csv";

const SENSITIVE_FILES = [
    'cloud.json',
    'contents.json',
    'environment.json',
    'truffleSecrets.json',
    'setup_bun.js',
    'bun_environment.js'
];

// --- HELPERS ---

function cleanVersion(ver) {
    if (!ver) return '0.0.0';
    // Remove all non-numeric characters from the start (e.g. ">= 1.2.3" -> "1.2.3")
    let cleaned = ver.replace(/^[^\d]+/, '');
    // Extract the first valid version sequence (x.x.x)
    const match = cleaned.match(/(\d+(\.\d+)*)/);
    return match ? match[0] : '0.0.0';
}

function fetchCSV(url) {
    return new Promise((resolve, reject) => {
        if (!url) return reject(new Error("CSV_URL is empty. Please configure it in the script."));

        console.log(`${CYAN}Fetching CSV rules from: ${url}...${RESET}`);

        https.get(url, (res) => {
            if (res.statusCode < 200 || res.statusCode > 299) {
                return reject(new Error(`Failed to download CSV. Status Code: ${res.statusCode}`));
            }

            const data = [];
            res.on('data', chunk => data.push(chunk));
            res.on('end', () => resolve(Buffer.concat(data).toString()));
        }).on('error', (err) => {
            reject(new Error(`Network Error: ${err.message}`));
        });
    });
}

// --- CORE LOGIC ---

function parseCSV(content) {
    const packages = [];
    let hasErrors = false;

    content.split('\n').forEach((line, index) => {
        const trimmed = line.trim();
        if (!trimmed) return; // Skip empty lines

        const parts = trimmed.split(',');

        if (parts.length < 2) {
            console.error(`${RED}[CSV Error] Line ${index + 1}: Invalid format. Expected "PackageName, CompromisedVersion".${RESET}`);
            hasErrors = true;
            return;
        }

        let pkgName = parts[0].trim();
        let rawVersionString = parts[1].trim();

        if (!pkgName || !rawVersionString) {
            hasErrors = true;
            return;
        }

        // Split by '||' to handle multiple compromised versions
        // Example: "= 0.1.18 || = 0.1.19" -> ["0.1.18", "0.1.19"]
        const compromisedList = rawVersionString
            .split('||')
            .map(v => cleanVersion(v.trim()))
            .filter(v => v !== '0.0.0');

        if (compromisedList.length === 0) {
            console.log(`${YELLOW}Warning: No valid versions found on line ${index + 1} for ${pkgName}.${RESET}`);
            return;
        }

        packages.push({
            name: pkgName,
            compromisedVersions: compromisedList, // Array of versions
            rawString: rawVersionString
        });
    });

    if (hasErrors) console.log(`${YELLOW}Warning: Some CSV lines were malformed and skipped.${RESET}`);
    return packages;
}

/**
 * Step 1: Find Projects
 * Recursively find all directories containing pnpm-lock.yaml
 */
function findProjectRoots(startDir) {
    let results = [];
    try {
        const list = fs.readdirSync(startDir);
        if (list.includes('pnpm-lock.yaml')) results.push(startDir);

        list.forEach(file => {
            const fullPath = path.join(startDir, file);
            try {
                const stat = fs.statSync(fullPath);
                if (stat && stat.isDirectory()) {
                    if (file !== 'node_modules' && !file.startsWith('.')) {
                        results = results.concat(findProjectRoots(fullPath));
                    }
                }
            } catch (e) { }
        });
    } catch (e) {
        console.error(`${RED}Error reading directory ${startDir}: ${e.message}${RESET}`);
    }
    return results;
}

/**
 * Step 2: Sensitive File Scanner
 */
function scanForSensitiveFiles(dir, isInsideNodeModules = false) {
    let results = [];
    try {
        const list = fs.readdirSync(dir);
        list.forEach(file => {
            const fullPath = path.join(dir, file);
            try {
                const stat = fs.lstatSync(fullPath);
                if (stat.isDirectory()) {
                    if (stat.isSymbolicLink()) return;
                    if (file === 'node_modules') {
                        results = results.concat(scanForSensitiveFiles(fullPath, true));
                    } else if (file.startsWith('.') && file !== '.pnpm') {
                        return;
                    } else {
                        results = results.concat(scanForSensitiveFiles(fullPath, isInsideNodeModules));
                    }
                } else if (stat.isFile()) {
                    if (isInsideNodeModules && SENSITIVE_FILES.includes(file)) {
                        results.push(fullPath);
                    }
                }
            } catch (err) { }
        });
    } catch (e) { }
    return results;
}

function getInstalledVersions(projectDir, targetPackages) {
    const BATCH_SIZE = 20;
    const installedMap = new Map();
    const targetNames = targetPackages.map(t => t.name);

    for (let i = 0; i < targetNames.length; i += BATCH_SIZE) {
        const chunk = targetNames.slice(i, i + BATCH_SIZE);
        if (chunk.length === 0) continue;

        try {
            const cmd = `pnpm list ${chunk.join(' ')} --depth Infinity --json --quiet`;
            const output = execSync(cmd, {
                cwd: projectDir,
                encoding: 'utf-8',
                maxBuffer: 1024 * 1024 * 1024, // 1GB Buffer
                stdio: ['ignore', 'pipe', 'pipe']
            });

            // Robust JSON Parsing
            let cleanOutput = output.trim();
            const firstBracket = cleanOutput.indexOf('[');
            const firstBrace = cleanOutput.indexOf('{');
            let startIndex = -1;
            if (firstBracket !== -1 && (firstBrace === -1 || firstBracket < firstBrace)) startIndex = firstBracket;
            else if (firstBrace !== -1) startIndex = firstBrace;

            if (startIndex !== -1) {
                cleanOutput = cleanOutput.substring(startIndex);
                const parsed = JSON.parse(cleanOutput);
                const roots = Array.isArray(parsed) ? parsed : [parsed];

                const traverse = (deps) => {
                    if (!deps) return;
                    for (const [key, val] of Object.entries(deps)) {
                        if (chunk.includes(key) && val.version) {
                            installedMap.set(key, val.version);
                        }
                        if (val.dependencies) traverse(val.dependencies);
                    }
                };

                roots.forEach(project => {
                    if (project.dependencies) traverse(project.dependencies);
                    if (project.devDependencies) traverse(project.devDependencies);
                });
            }
        } catch (e) { }
    }
    return { success: true, map: installedMap };
}

// --- MAIN EXECUTION ---

async function run() {
    const args = process.argv.slice(2);

    // We only need the target directory now
    if (args.length < 1) {
        console.log(`${YELLOW}Usage: node audit_scanner.js <target_directory>${RESET}`);
        process.exit(1);
    }

    const targetRoot = path.resolve(args[0]);

    // 1. Fetch Rules from URL
    let targets;
    try {
        const csvContent = await fetchCSV(CSV_URL);
        targets = parseCSV(csvContent);
    } catch (e) {
        console.error(`${RED}Critical Error fetching CSV:${RESET} ${e.message}`);
        console.error(`${YELLOW}Please ensure 'CSV_URL' is set correctly in the script.${RESET}`);
        process.exit(1);
    }

    if (targets.length === 0) {
        console.error(`${RED}No valid rules found in CSV.${RESET}`);
        process.exit(1);
    }

    // --- STEP 1: BREACH AUDIT ---
    console.log(`\n${MAGENTA}=== STEP 1: Security Breach Audit ===${RESET}`);
    console.log(`${CYAN}Scanning projects in: ${targetRoot}...${RESET}`);
    const projectDirs = findProjectRoots(targetRoot);

    let breaches = 0;
    let warnings = 0;

    if (projectDirs.length === 0) {
        console.log(`${YELLOW}No projects found (no folders contained pnpm-lock.yaml).${RESET}`);
    } else {
        console.log(`${CYAN}Found ${projectDirs.length} projects.${RESET}\n`);

        projectDirs.forEach(projDir => {
            const relativeName = path.relative(targetRoot, projDir) || 'Root';
            console.log(`${WHITE_BOLD}📂 Project: ${relativeName}${RESET}`);

            const result = getInstalledVersions(projDir, targets);

            if (!result.success) {
                console.log(`   ${RED}Skipping: Internal audit error.${RESET}`);
                return;
            }

            const installed = result.map;

            targets.forEach(target => {
                const installedVersion = installed.get(target.name);

                if (!installedVersion) {
                    // Safe: Not installed
                } else {
                    const installedClean = cleanVersion(installedVersion);
                    console.log(`     ${DEBUG}[Scanning]${RESET} ${target.name}`);

                    // CHECK: Does installed version match ANY of the compromised versions?
                    if (target.compromisedVersions.includes(installedClean)) {
                        // CRITICAL: Exact match with compromised version
                        console.log(`   ❌ ${RED}[BREACH DETECTED]${RESET} ${target.name}`);
                        console.log(`       Installed: ${installedVersion}`);
                        console.log(`       Status:    ${RED}MATCHES COMPROMISED LIST: ${target.rawString}${RESET}`);
                        breaches++;
                    } else {
                        // WARNING: Library in use, but version differs
                        console.log(`   ⚠️  ${YELLOW}[WARNING]${RESET}         ${target.name}`);
                        console.log(`       Installed: ${installedVersion}`);
                        console.log(`       Alert:     Library is in use. Compromised list: ${target.rawString}. Verify manually.`);
                        warnings++;
                    }
                }
            });
            console.log(''); // New line between projects
        });
    }

    // --- STEP 2: FILE SCAN ---
    console.log(`${MAGENTA}=== STEP 2: Sensitive File Scan ===${RESET}`);
    console.log(`${CYAN}Scanning node_modules for sensitive files...${RESET}`);
    const foundFiles = scanForSensitiveFiles(targetRoot);

    if (foundFiles.length > 0) {
        console.log(`\n${RED}⚠️  Security Warning: Found ${foundFiles.length} sensitive files:${RESET}`);
        foundFiles.forEach(f => {
            console.log(`   - ${path.relative(targetRoot, f)}`);
        });
    } else {
        console.log(`${GREEN}No sensitive files found.${RESET}`);
    }

    // --- FINAL SUMMARY ---
    console.log(`\n${MAGENTA}=== Audit Summary ===${RESET}`);
    if (breaches > 0) {
        console.log(`${RED}CRITICAL FAILED: ${breaches} confirmed breaches detected.${RESET}`);
        console.log(`${YELLOW}Warnings: ${warnings} libraries require manual verification.${RESET}`);
        if (foundFiles.length > 0) console.log(`${RED}Sensitive Files: ${foundFiles.length} found.${RESET}`);
        process.exit(1);
    } else if (foundFiles.length > 0) {
        console.log(`${RED}FAILED: Sensitive files detected.${RESET}`);
        console.log(`${YELLOW}Warnings: ${warnings} libraries require manual verification.${RESET}`);
        process.exit(1);
    } else if (warnings > 0) {
        console.log(`${YELLOW}PASSED WITH WARNINGS: No direct breaches, but ${warnings} affected libraries are in use.${RESET}`);
        process.exit(0);
    } else {
        console.log(`${GREEN}SUCCESS: System clean.${RESET}`);
        process.exit(0);
    }
}

run();
