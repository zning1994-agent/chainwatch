const fs = require("fs");
const path = require("path");

// Detect inconsistencies between lockfile and manifest
async function analyzeLockfile(deps, manifestPath) {
  const risks = [];
  
  // Check if lockfile exists
  const dir = path.dirname(manifestPath);
  const lockfiles = [
    "package-lock.json",
    "yarn.lock", 
    "pnpm-lock.yaml",
    "Pipfile.lock",
    "poetry.lock"
  ];
  
  let lockfilePath = null;
  let lockfileContent = null;
  
  for (const lf of lockfiles) {
    const fullPath = path.join(dir, lf);
    if (fs.existsSync(fullPath)) {
      lockfilePath = fullPath;
      lockfileContent = fs.readFileSync(fullPath, "utf8");
      break;
    }
  }
  
  if (!lockfilePath) {
    risks.push({
      level: "LOW",
      type: "missing_lockfile",
      package: "(project)",
      message: "No lockfile found — dependency versions are not pinned, increasing supply chain risk",
      details: { lockfiles_checked: lockfiles }
    });
    return risks;
  }
  
  // Parse package-lock.json
  if (lockfilePath.endsWith("package-lock.json")) {
    try {
      const lock = JSON.parse(lockfileContent);
      const lockPkgs = lock.packages || {};
      
      for (const dep of deps) {
        const lockEntry = lockPkgs[`node_modules/${dep.name}`];
        if (lockEntry) {
          // Check for integrity hash
          if (!lockEntry.integrity && !lockEntry.resolved) {
            risks.push({
              level: "MEDIUM",
              type: "missing_integrity",
              package: dep.name,
              message: "No integrity hash in lockfile — package could be tampered with",
              details: { lockfile: "package-lock.json" }
            });
          }
        }
      }
    } catch (e) {
      // Invalid lockfile
    }
  }
  
  return risks;
}

module.exports = { analyzeLockfile };
