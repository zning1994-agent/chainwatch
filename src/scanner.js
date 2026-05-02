const fs = require("fs");
const path = require("path");
const { detectTyposquatting } = require("./detectors/typosquatting");
const { analyzeMaintainer } = require("./detectors/maintainer");
const { scanVulnerabilities } = require("./detectors/vulnerability");
const { detectDependencyConfusion } = require("./detectors/confusion");

async function scanProject(options) {
  const filePath = resolveDependencyFile(options.file);
  const deps = parseDependencyFile(filePath);
  
  console.log(`\n📦 Scanning ${path.basename(filePath)}... (${deps.length} dependencies found)\n`);
  
  const risks = [];
  
  // Run all detectors
  const [typosquatResults, maintainerResults, vulnResults, confusionResults] = 
    await Promise.all([
      detectTyposquatting(deps),
      analyzeMaintainer(deps),
      scanVulnerabilities(deps),
      detectDependencyConfusion(deps)
    ]);
  
  risks.push(...typosquatResults, ...maintainerResults, ...vulnResults, ...confusionResults);
  
  return {
    file: filePath,
    totalDeps: deps.length,
    risks,
    timestamp: new Date().toISOString()
  };
}

function resolveDependencyFile(customPath) {
  if (customPath) {
    if (fs.existsSync(customPath)) return customPath;
    throw new Error(`File not found: ${customPath}`);
  }
  
  // Auto-detect
  const candidates = [
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "Pipfile",
    "pyproject.toml"
  ];
  
  for (const candidate of candidates) {
    const fullPath = path.join(process.cwd(), candidate);
    if (fs.existsSync(fullPath)) return fullPath;
  }
  
  throw new Error("No dependency file found. Use --file to specify one.");
}

function parseDependencyFile(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  const deps = [];
  
  if (filePath.endsWith("package.json")) {
    const pkg = JSON.parse(content);
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.peerDependencies
    };
    for (const [name, version] of Object.entries(allDeps || {})) {
      deps.push({ name, version, source: "npm" });
    }
  } else if (filePath.endsWith("requirements.txt")) {
    const lines = content.split("\n").filter(l => l.trim() && !l.startsWith("#"));
    for (const line of lines) {
      const match = line.match(/^([a-zA-Z0-9_-]+)/);
      if (match) {
        deps.push({ name: match[1], version: "*", source: "pip" });
      }
    }
  }
  
  return deps;
}

module.exports = { scanProject };
