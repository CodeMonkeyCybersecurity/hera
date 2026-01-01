// Tests for ESLint configuration validation
// See ADR-001 for rationale on flat config format
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { execSync } from 'child_process';

const PROJECT_ROOT = join(import.meta.dirname, '../..');

describe('ESLint Configuration', () => {
  describe('Config File Validation', () => {
    it('should have eslint.config.js (flat config format)', () => {
      const configPath = join(PROJECT_ROOT, 'eslint.config.js');
      expect(existsSync(configPath)).toBe(true);
    });

    it('should NOT have legacy .eslintrc.json (invalid JSON with comments)', () => {
      const legacyPath = join(PROJECT_ROOT, '.eslintrc.json');
      expect(existsSync(legacyPath)).toBe(false);
    });

    it('should NOT have legacy .eslintrc.js', () => {
      const legacyPath = join(PROJECT_ROOT, '.eslintrc.js');
      expect(existsSync(legacyPath)).toBe(false);
    });

    it('should NOT have legacy .eslintrc.yaml', () => {
      const legacyPath = join(PROJECT_ROOT, '.eslintrc.yaml');
      expect(existsSync(legacyPath)).toBe(false);
    });

    it('eslint.config.js should be valid JavaScript module', async () => {
      // Dynamic import to validate syntax
      const configPath = join(PROJECT_ROOT, 'eslint.config.js');
      const config = await import(configPath);

      expect(config.default).toBeDefined();
      expect(Array.isArray(config.default)).toBe(true);
      expect(config.default.length).toBeGreaterThan(0);
    });

    it('eslint.config.js should have ignores configuration', async () => {
      const configPath = join(PROJECT_ROOT, 'eslint.config.js');
      const config = await import(configPath);

      const ignoresConfig = config.default.find(c => c.ignores);
      expect(ignoresConfig).toBeDefined();
      expect(ignoresConfig.ignores).toContain('node_modules/**');
    });
  });

  describe('ESLint Execution', () => {
    it('should run eslint without TypeScript plugin errors', () => {
      try {
        // Run eslint on a single file to verify config works
        const result = execSync('npx eslint --max-warnings 1000 background.js', {
          cwd: PROJECT_ROOT,
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe']
        });
        // If we get here without throwing, no fatal errors
        expect(true).toBe(true);
      } catch (error) {
        // ESLint returns exit code 1 for lint errors, which is expected
        // We only care about TypeScript plugin loading errors
        const stderr = error.stderr || '';
        const stdout = error.stdout || '';
        const output = stderr + stdout;

        expect(output).not.toContain('@typescript-eslint');
        expect(output).not.toContain('TypeError: Error while loading rule');
      }
    });

    it('should not use deprecated --ext flag', () => {
      const packageJson = JSON.parse(
        readFileSync(join(PROJECT_ROOT, 'package.json'), 'utf-8')
      );

      const lintScript = packageJson.scripts.lint;
      expect(lintScript).not.toContain('--ext');
    });
  });

  describe('Package.json Configuration', () => {
    it('should have @eslint/js as devDependency', () => {
      const packageJson = JSON.parse(
        readFileSync(join(PROJECT_ROOT, 'package.json'), 'utf-8')
      );

      expect(packageJson.devDependencies['@eslint/js']).toBeDefined();
    });

    it('should have globals as devDependency', () => {
      const packageJson = JSON.parse(
        readFileSync(join(PROJECT_ROOT, 'package.json'), 'utf-8')
      );

      expect(packageJson.devDependencies.globals).toBeDefined();
    });

    it('should have lint-staged configured for eslint', () => {
      const packageJson = JSON.parse(
        readFileSync(join(PROJECT_ROOT, 'package.json'), 'utf-8')
      );

      expect(packageJson['lint-staged']).toBeDefined();
      expect(packageJson['lint-staged']['*.js']).toContain('eslint --fix');
    });
  });

  describe('Pre-commit Hook', () => {
    it('should have pre-commit hook file', () => {
      const hookPath = join(PROJECT_ROOT, '.husky/pre-commit');
      expect(existsSync(hookPath)).toBe(true);
    });

    it('pre-commit hook should run lint-staged', () => {
      const hookPath = join(PROJECT_ROOT, '.husky/pre-commit');
      const hookContent = readFileSync(hookPath, 'utf-8');

      expect(hookContent).toContain('lint-staged');
    });

    it('pre-commit hook should validate config exists', () => {
      const hookPath = join(PROJECT_ROOT, '.husky/pre-commit');
      const hookContent = readFileSync(hookPath, 'utf-8');

      expect(hookContent).toContain('eslint.config.js');
    });
  });

  describe('Rule Configuration', () => {
    it('should configure service worker restrictions for background.js', async () => {
      const configPath = join(PROJECT_ROOT, 'eslint.config.js');
      const config = await import(configPath);

      const backgroundConfig = config.default.find(c =>
        c.files && c.files.some(f => f.includes('background.js'))
      );

      expect(backgroundConfig).toBeDefined();
      expect(backgroundConfig.rules).toBeDefined();
      expect(backgroundConfig.rules['no-restricted-globals']).toBeDefined();
    });

    it('should allow DOM globals in content scripts', async () => {
      const configPath = join(PROJECT_ROOT, 'eslint.config.js');
      const config = await import(configPath);

      const contentConfig = config.default.find(c =>
        c.files && c.files.some(f => f.includes('content-script.js'))
      );

      expect(contentConfig).toBeDefined();
      expect(contentConfig.languageOptions.globals.document).toBe('readonly');
      expect(contentConfig.languageOptions.globals.window).toBe('readonly');
    });

    it('should configure test environment for test files', async () => {
      const configPath = join(PROJECT_ROOT, 'eslint.config.js');
      const config = await import(configPath);

      const testConfig = config.default.find(c =>
        c.files && c.files.some(f => f.includes('test'))
      );

      expect(testConfig).toBeDefined();
      expect(testConfig.languageOptions.globals.describe).toBe('readonly');
      expect(testConfig.languageOptions.globals.it).toBe('readonly');
      expect(testConfig.languageOptions.globals.expect).toBe('readonly');
    });
  });
});
