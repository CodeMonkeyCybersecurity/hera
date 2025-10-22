#!/usr/bin/env node

/**
 * Hera Extension Validation Script
 * Catches common errors before loading in Chrome
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..');

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

const errors = [];
const warnings = [];
let checksRun = 0;

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function error(message) {
  errors.push(message);
  log(`❌ ERROR: ${message}`, 'red');
}

function warn(message) {
  warnings.push(message);
  log(`⚠️  WARNING: ${message}`, 'yellow');
}

function success(message) {
  log(`✅ ${message}`, 'green');
}

function section(title) {
  log(`\n${'='.repeat(60)}`, 'cyan');
  log(title, 'cyan');
  log('='.repeat(60), 'cyan');
}

/**
 * Check 1: Validate manifest.json
 */
function validateManifest() {
  section('Validating manifest.json');
  checksRun++;

  try {
    const manifestPath = path.join(rootDir, 'manifest.json');
    const manifestContent = fs.readFileSync(manifestPath, 'utf8');
    const manifest = JSON.parse(manifestContent);

    // Check required fields
    const requiredFields = ['manifest_version', 'name', 'version'];
    for (const field of requiredFields) {
      if (!manifest[field]) {
        error(`manifest.json missing required field: ${field}`);
      }
    }

    // Check manifest version
    if (manifest.manifest_version !== 3) {
      warn('Not using Manifest V3');
    }

    // Check background script exists
    if (manifest.background?.service_worker) {
      const bgPath = path.join(rootDir, manifest.background.service_worker);
      if (!fs.existsSync(bgPath)) {
        error(`Background script not found: ${manifest.background.service_worker}`);
      } else {
        success('Background script exists');
      }
    }

    // Check content scripts exist
    if (manifest.content_scripts) {
      for (const cs of manifest.content_scripts) {
        for (const script of cs.js || []) {
          const scriptPath = path.join(rootDir, script);
          if (!fs.existsSync(scriptPath)) {
            error(`Content script not found: ${script}`);
          }
        }
      }
      success('All content scripts exist');
    }

    // Check icons exist
    if (manifest.icons) {
      for (const [size, iconPath] of Object.entries(manifest.icons)) {
        const fullPath = path.join(rootDir, iconPath);
        if (!fs.existsSync(fullPath)) {
          error(`Icon not found: ${iconPath}`);
        }
      }
      success('All icons exist');
    }

    success('manifest.json is valid');
  } catch (err) {
    error(`Failed to parse manifest.json: ${err.message}`);
  }
}

/**
 * Check 2: Validate imports/exports
 */
function validateImports() {
  section('Validating ES6 Imports/Exports');
  checksRun++;

  const jsFiles = findJSFiles(rootDir);
  const exportedModules = new Map();
  const importedModules = [];

  // First pass: collect all exports
  for (const file of jsFiles) {
    if (file.includes('node_modules') || file.includes('.backup.') || file.includes('-backup.')) {
      continue;
    }

    const content = fs.readFileSync(file, 'utf8');
    const relativePath = path.relative(rootDir, file);

    // Find exports
    const exportMatches = content.matchAll(/export\s+(?:class|function|const|let|var|{)\s+(\w+)/g);
    const exports = [];
    for (const match of exportMatches) {
      exports.push(match[1]);
    }

    const defaultExportMatch = content.match(/export\s+default\s+(\w+)/);
    if (defaultExportMatch) {
      exports.push('default');
    }

    if (exports.length > 0) {
      exportedModules.set(relativePath, exports);
    }
  }

  // Second pass: validate imports
  for (const file of jsFiles) {
    if (file.includes('node_modules') || file.includes('.backup.') || file.includes('-backup.')) {
      continue;
    }

    const content = fs.readFileSync(file, 'utf8');
    const relativePath = path.relative(rootDir, file);

    // Skip commented out imports
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      // Skip comments
      if (line.startsWith('//') || line.startsWith('/*') || line.startsWith('*')) {
        continue;
      }

      // Find import statements
      const importMatch = line.match(/import\s+(?:{([^}]+)}|(\w+))\s+from\s+['"]([^'"]+)['"]/);
      if (!importMatch) continue;

      const namedImports = importMatch[1] ? importMatch[1].split(',').map(s => s.trim()) : [];
      const defaultImport = importMatch[2];
      const importPath = importMatch[3];

      // Skip external imports
      if (!importPath.startsWith('.') && !importPath.startsWith('/')) {
        continue;
      }

      // Resolve import path
      const fileDir = path.dirname(file);
      let resolvedPath = path.resolve(fileDir, importPath);

      // Add .js if not present
      if (!resolvedPath.endsWith('.js')) {
        resolvedPath += '.js';
      }

      const resolvedRelative = path.relative(rootDir, resolvedPath);

      // Check if file exists
      if (!fs.existsSync(resolvedPath)) {
        error(`Import file not found: ${importPath} (in ${relativePath}:${i + 1})`);
        continue;
      }

      // Check if exports exist
      const exports = exportedModules.get(resolvedRelative) || [];

      if (defaultImport && !exports.includes('default')) {
        warn(`Default import "${defaultImport}" but no default export in ${resolvedRelative} (${relativePath}:${i + 1})`);
      }

      for (const namedImport of namedImports) {
        if (!exports.includes(namedImport)) {
          error(`Import "${namedImport}" not exported from ${resolvedRelative} (${relativePath}:${i + 1})`);
        }
      }
    }
  }

  if (errors.filter(e => e.includes('Import')).length === 0) {
    success('All imports are valid');
  }
}

/**
 * Check 3: Find syntax errors
 */
function validateSyntax() {
  section('Checking JavaScript Syntax');
  checksRun++;

  const jsFiles = findJSFiles(rootDir);
  let syntaxErrors = 0;

  for (const file of jsFiles) {
    if (file.includes('node_modules') || file.includes('.backup.') || file.includes('-backup.')) {
      continue;
    }

    try {
      const content = fs.readFileSync(file, 'utf8');
      // Try to detect obvious syntax errors

      // Check for unmatched braces
      const openBraces = (content.match(/{/g) || []).length;
      const closeBraces = (content.match(/}/g) || []).length;
      if (openBraces !== closeBraces) {
        error(`Unmatched braces in ${path.relative(rootDir, file)}: ${openBraces} open, ${closeBraces} close`);
        syntaxErrors++;
      }

      // Check for unmatched parentheses
      const openParens = (content.match(/\(/g) || []).length;
      const closeParens = (content.match(/\)/g) || []).length;
      if (openParens !== closeParens) {
        error(`Unmatched parentheses in ${path.relative(rootDir, file)}: ${openParens} open, ${closeParens} close`);
        syntaxErrors++;
      }

      // Check for unmatched brackets
      const openBrackets = (content.match(/\[/g) || []).length;
      const closeBrackets = (content.match(/\]/g) || []).length;
      if (openBrackets !== closeBrackets) {
        error(`Unmatched brackets in ${path.relative(rootDir, file)}: ${openBrackets} open, ${closeBrackets} close`);
        syntaxErrors++;
      }

    } catch (err) {
      error(`Failed to read ${path.relative(rootDir, file)}: ${err.message}`);
      syntaxErrors++;
    }
  }

  if (syntaxErrors === 0) {
    success('No obvious syntax errors found');
  }
}

/**
 * Check 4: Find commented-out imports that might cause issues
 */
function findProblematicComments() {
  section('Checking for Problematic Commented Code');
  checksRun++;

  const jsFiles = findJSFiles(rootDir);
  let issues = 0;

  for (const file of jsFiles) {
    if (file.includes('node_modules') || file.includes('.backup.') || file.includes('-backup.')) {
      continue;
    }

    const content = fs.readFileSync(file, 'utf8');
    const lines = content.split('\n');
    const relativePath = path.relative(rootDir, file);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check for commented imports that are still referenced
      if (line.trim().startsWith('// import')) {
        const importMatch = line.match(/\/\/\s*import.*from\s+['"]([^'"]+)['"]/);
        if (importMatch) {
          const modulePath = importMatch[1];

          // Check if this module is used elsewhere in the file (not commented)
          const moduleUsed = lines.some((l, idx) =>
            idx !== i &&
            !l.trim().startsWith('//') &&
            !l.trim().startsWith('/*') &&
            l.includes(modulePath.split('/').pop().replace('.js', ''))
          );

          if (moduleUsed) {
            warn(`Commented import still referenced: ${modulePath} in ${relativePath}:${i + 1}`);
            issues++;
          }
        }
      }
    }
  }

  if (issues === 0) {
    success('No problematic commented code found');
  }
}

/**
 * Helper: Find all JS files recursively
 */
function findJSFiles(dir, files = []) {
  const items = fs.readdirSync(dir);

  for (const item of items) {
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);

    if (stat.isDirectory()) {
      if (!item.startsWith('.') && item !== 'node_modules') {
        findJSFiles(fullPath, files);
      }
    } else if (item.endsWith('.js') && !item.includes('.backup.') && !item.includes('-backup.')) {
      files.push(fullPath);
    }
  }

  return files;
}

/**
 * Main
 */
function main() {
  log('\n🔍 Hera Extension Validator\n', 'blue');

  validateManifest();
  validateImports();
  validateSyntax();
  findProblematicComments();

  // Summary
  section('Validation Summary');
  log(`\nChecks run: ${checksRun}`, 'cyan');
  log(`Errors: ${errors.length}`, errors.length > 0 ? 'red' : 'green');
  log(`Warnings: ${warnings.length}`, warnings.length > 0 ? 'yellow' : 'green');

  if (errors.length > 0) {
    log('\n❌ Validation FAILED - Fix errors before loading extension', 'red');
    process.exit(1);
  } else if (warnings.length > 0) {
    log('\n⚠️  Validation passed with warnings', 'yellow');
    process.exit(0);
  } else {
    log('\n✅ Validation PASSED - Extension ready to load!', 'green');
    process.exit(0);
  }
}

main();
