# 🔍 ChainWatch

**Supply chain attack detection tool** — scan your project dependencies for potential security risks.

## Features

- 🎯 **Typosquatting Detection** — Find packages with names suspiciously similar to popular packages (npm + PyPI)
- 👤 **Suspicious Maintainer Detection** — Identify packages published by new or low-activity accounts
- 🔄 **Dependency Confusion Detection** — Detect potential private package name hijacking
- 🛡️ **Known Vulnerability Scanning** — Check against GitHub Advisory Database (OSV API)
- 🔒 **Lockfile Analysis** — Detect missing integrity hashes and unpinned dependencies
- 📋 **Multi-ecosystem** — Supports npm, PyPI, Go, Ruby gems
- 🌐 **Web Interface** — Visual scanning via drag-and-drop web UI

## Quick Start

```bash
# Install globally
npm install -g chainwatch

# Scan your project
chainwatch scan

# Or use npx
npx chainwatch scan
```

## Usage

```bash
# Scan current directory (auto-detects dependency files)
chainwatch scan

# Scan a specific file
chainwatch scan --file requirements.txt

# Verbose output with all details
chainwatch scan --verbose

# JSON output for CI/CD integration
chainwatch scan --json

# Check a single package
chainwatch check <package-name>
```

## Supported Ecosystems

| Ecosystem | File Types | Typosquatting DB | Maintainer Check |
|-----------|-----------|-----------------|-----------------|
| npm | package.json | ✅ (500+ packages) | ✅ |
| PyPI | requirements.txt, pyproject.toml, Pipfile | ✅ (100+ packages) | ✅ |
| Go | go.mod | 🔜 | 🔜 |
| Ruby | Gemfile | 🔜 | 🔜 |

## Example Output

```
🔍 ChainWatch v1.0.0 — Supply Chain Security Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📦 Scanning requirements.txt... (23 packages found)

⚠️  RISKS FOUND: 2

🔴 HIGH: Typosquatting detected
   requets → similar to requests (91% match, edit distance: 1)

🟡 MEDIUM: Suspicious package
   fake-auth → Only 1 version published, account is 5 days old

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Summary:
   Total dependencies: 23
   🔴 HIGH: 1
   🟡 MEDIUM: 1
   ✅ CLEAN: 21
```

## Web Interface

```bash
# Open the web UI
open web/index.html
```

Features:
- Drag & drop package.json or requirements.txt
- Paste dependencies directly
- Visual risk dashboard with severity levels
- Client-side scanning (no server required)

## CI/CD Integration

### GitHub Actions

```yaml
- name: Supply Chain Security Scan
  run: |
    npm install -g chainwatch
    chainwatch scan --fail-high --json > scan-results.json
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
npx chainwatch scan --quiet || exit 1
```

## Risk Levels

| Level | Description |
|-------|-------------|
| 🔴 HIGH | Critical risk — likely malicious package |
| 🟡 MEDIUM | Suspicious — investigate further |
| 🔵 LOW | Minor concern — informational |
| ✅ CLEAN | No issues detected |

## How It Works

### Typosquatting Detection
Compares package names against a database of popular packages using:
- Levenshtein distance (edit distance)
- Common typo patterns (missing/extra characters)
- Homoglyph detection (visually similar characters)
- Normalization (removing `-`, `_`, `.` for comparison)

### Maintainer Analysis
Checks registries (npm/PyPI) for:
- Account creation date (< 30 days = suspicious)
- Number of published packages
- Release history patterns

### Vulnerability Scanning
Queries the [OSV (Open Source Vulnerabilities)](https://osv.dev/) API for:
- Known CVEs in your dependency tree
- Security advisories
- Unpatched vulnerabilities

## Contributing

Contributions welcome! Please open an issue first to discuss what you'd like to change.

## License

MIT © Brain Agent
