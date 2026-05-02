const fs = require("fs");
const path = require("path");
const { detectTyposquatting } = require("./detectors/typosquatting");
const { analyzeMaintainer } = require("./detectors/maintainer");
const { scanVulnerabilities } = require("./detectors/vulnerability");
const { detectDependencyConfusion } = require("./detectors/confusion");
const { detectPyPITyposquatting } = require("./detectors/pypi-typosquatting");
const { analyzePyPIMaintainer } = require("./detectors/pypi-maintainer");
const { analyzeLockfile } = require("./detectors/lockfile");

async function scanProject(options) {
  const filePath = resolveDependencyFile(options.file);
  const deps = parseDependencyFile(filePath);
  
  console.log(`\n📦 Scanning ${path.basename(filePath)}... (${deps.length} dependencies found)\n`);
  
  const risks = [];
  
  // Run all detectors
  const [typosquatResults, maintainerResults, vulnResults, confusionResults, 
         pypiTyposquatResults, pypiMaintainerResults, lockfileResults] = 
    await Promise.all([
      detectTyposquatting(deps),
      analyzeMaintainer(deps),
      scanVulnerabilities(deps),
      detectDependencyConfusion(deps),
      detectPyPITyposquatting(deps),
      analyzePyPIMaintainer(deps),
      analyzeLockfile(deps, filePath)
    ]);
  
  risks.push(...typosquatResults, ...maintainerResults, ...vulnResults, ...confusionResults,
             ...pypiTyposquatResults, ...pypiMaintainerResults, ...lockfileResults);
  
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
      ...pkg.peerDependencies,
      ...pkg.optionalDependencies
    };
    for (const [name, version] of Object.entries(allDeps || {})) {
      deps.push({ name, version, source: "npm" });
    }
  } else if (filePath.endsWith("requirements.txt") || filePath.endsWith("requirements-dev.txt") || filePath.endsWith("requirements-prod.txt")) {
    const lines = content.split("\n").filter(l => l.trim() && !l.startsWith("#") && !l.startsWith("-"));
    for (const line of lines) {
      // Handle: package==1.0.0, package>=1.0, package~=1.0, package[extra]>=1.0
      const match = line.match(/^([a-zA-Z0-9_.-]+)(?:\[.*?\])?\s*[=~><!]/);
      if (match) {
        deps.push({ name: match[1], version: "*", source: "pypi" });
      } else {
        const simple = line.match(/^([a-zA-Z0-9_.-]+)\s*$/);
        if (simple) deps.push({ name: simple[1], version: "*", source: "pypi" });
      }
    }
  } else if (filePath.endsWith("pyproject.toml")) {
    // Parse [project.dependencies] section
    const depSection = content.match(/\[project\.dependencies\]([\s\S]*?)(?=\n\[|$)/);
    if (depSection) {
      const lines = depSection[1].split("\n").filter(l => l.trim() && !l.startsWith("#"));
      for (const line of lines) {
        const match = line.match(/^"?([a-zA-Z0-9_.-]+)"?\s*[=~><!]/);
        if (match) deps.push({ name: match[1], version: "*", source: "pypi" });
      }
    }
    // Also check [project.optional-dependencies]
    const optSection = content.match(/\[project\.optional-dependencies\]([\s\S]*?)(?=\n\[|$)/);
    if (optSection) {
      const lines = optSection[1].split("\n").filter(l => l.trim() && !l.startsWith("#"));
      for (const line of lines) {
        const match = line.match(/^"?([a-zA-Z0-9_.-]+)"?\s*[=~><!]/);
        if (match) deps.push({ name: match[1], version: "*", source: "pypi" });
      }
    }
  } else if (filePath.endsWith("Pipfile")) {
    // Simple Pipfile parser
    const depSection = content.match(/\[packages\]([\s\S]*?)(?=\n\[|$)/);
    if (depSection) {
      const lines = depSection[1].split("\n").filter(l => l.trim() && !l.startsWith("#"));
      for (const line of lines) {
        const match = line.match(/^([a-zA-Z0-9_.-]+)\s*=/);
        if (match) deps.push({ name: match[1], version: "*", source: "pypi" });
      }
    }
  } else if (filePath.endsWith("go.mod")) {
    // Parse Go modules
    const requireSection = content.match(/require \(([\s\S]*?)\)/);
    if (requireSection) {
      const lines = requireSection[1].split("\n").filter(l => l.trim());
      for (const line of lines) {
        const match = line.match(/^([\w./-]+)\s+v/);
        if (match) deps.push({ name: match[1], version: "*", source: "go" });
      }
    }
  } else if (filePath.endsWith("Gemfile")) {
    const lines = content.split("\n").filter(l => l.trim().startsWith("gem "));
    for (const line of lines) {
      const match = line.match(/gem\s+['"]([^'"]+)['"]/);
      if (match) deps.push({ name: match[1], version: "*", source: "rubygems" });
    }
  }
  
  return deps;
}

module.exports = { scanProject };
