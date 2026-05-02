const https = require("https");

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { "User-Agent": "chainwatch/1.0" } }, (res) => {
      let data = "";
      res.on("data", (chunk) => data += chunk);
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve(null);
        }
      });
    }).on("error", reject);
  });
}

// Heuristic: detect if a package might be a confusion target
// - Very low download count
// - No description
// - Recently published
// - Name matches common corporate internal patterns
const INTERNAL_NAME_PATTERNS = [
  /@corp\//,
  /@internal\//,
  /@private\//,
  /@company\//,
  /@org\//,
  /@internal-/,
  /-internal$/,
  /-corp$/,
  /-private$/,
];

async function detectDependencyConfusion(deps) {
  const risks = [];
  
  for (const dep of deps) {
    // Check if name matches internal package patterns
    for (const pattern of INTERNAL_NAME_PATTERNS) {
      if (pattern.test(dep.name)) {
        try {
          const data = await fetchJSON(`https://registry.npmjs.org/${dep.name}`);
          
          if (data && data.name) {
            // Package exists on public npm — potential confusion attack
            risks.push({
              level: "HIGH",
              type: "dependency_confusion",
              package: dep.name,
              message: `Package "${dep.name}" matches internal naming pattern but exists on public npm — potential dependency confusion attack`,
              details: {
                pattern: pattern.toString(),
                published: data.time?.created,
                maintainer: data.maintainers?.[0]?.name
              }
            });
          }
        } catch (err) {
          // Package not found — this is expected and safe
        }
      }
    }
  }
  
  return risks;
}

module.exports = { detectDependencyConfusion };
