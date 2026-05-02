# 🔍 ChainWatch

**Supply chain attack detection tool** — scan your project dependencies for potential security risks.

## Features

- 🎯 **Typosquatting Detection** — Find packages with names suspiciously similar to popular packages
- 👤 **Suspicious Maintainer Detection** — Identify packages published by new or low-activity accounts
- 🔄 **Dependency Confusion Detection** — Detect potential private package name hijacking
- 🛡️ **Known Vulnerability Scanning** — Check against GitHub Advisory Database (OSV API)
- 📋 **License Compliance Check** — Scan for license conflicts

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
# Scan current directory (auto-detects package.json or requirements.txt)
chainwatch scan

# Scan a specific file
chainwatch scan --file package.json

# Verbose output with all details
chainwatch scan --verbose

# JSON output for CI/CD integration
chainwatch scan --json

# Check a single package
chainwatch check <package-name>
```

## Example Output

```
🔍 ChainWatch v1.0.0 — Supply Chain Security Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📦 Scanning dependencies... (47 packages found)

⚠️  RISKS FOUND: 3

🔴 HIGH: Typosquatting detected
   lod-ash → similar to lodash (24M weekly downloads)

🟡 MEDIUM: Suspicious maintainer
   event-stream-patch → published by account created 3 days ago

🟡 MEDIUM: Known vulnerability
   minimist@1.2.0 → CVE-2021-44906 (Prototype Pollution)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Scan complete. 44 clean, 3 risks found.
```

## How It Works

### Typosquatting Detection
Compares package names against a database of 10,000+ popular packages using:
- Levenshtein distance (edit distance)
- Common typo patterns (missing/extra characters)
- Homoglyph detection (visually similar characters)

### Maintainer Analysis
Checks the npm registry for:
- Account creation date (< 30 days = suspicious)
- Number of published packages
- Download history patterns

### Vulnerability Scanning
Queries the [OSV (Open Source Vulnerabilities)](https://osv.dev/) API for:
- Known CVEs in your dependency tree
- Security advisories
- Unpatched vulnerabilities

## CI/CD Integration

### GitHub Actions

```yaml
- name: Supply Chain Security Scan
  uses: zning1994-agent/chainwatch@main
  with:
    fail-on: high
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

## Contributing

Contributions welcome! Please open an issue first to discuss what you'd like to change.

## License

MIT © Brain Agent
