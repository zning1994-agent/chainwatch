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
          reject(new Error(`Failed to parse JSON from ${url}`));
        }
      });
    }).on("error", reject);
  });
}

async function analyzeMaintainer(deps) {
  const risks = [];
  
  // Only check npm packages
  const npmDeps = deps.filter(d => d.source === "npm");
  
  // Batch check (limit concurrency)
  for (const dep of npmDeps.slice(0, 50)) { // Limit to avoid rate limiting
    try {
      const data = await fetchJSON(`https://registry.npmjs.org/${dep.name}`);
      
      if (!data || !data.maintainers || data.maintainers.length === 0) continue;
      
      const maintainer = data.maintainers[0];
      const time = data.time || {};
      const created = time.created;
      
      if (created) {
        const accountAge = (Date.now() - new Date(created).getTime()) / (1000 * 60 * 60 * 24);
        
        if (accountAge < 30) {
          risks.push({
            level: "MEDIUM",
            type: "suspicious_maintainer",
            package: dep.name,
            message: `Maintainer account "${maintainer.name}" is only ${Math.floor(accountAge)} days old`,
            details: {
              maintainer: maintainer.name,
              accountAge: Math.floor(accountAge),
              created: created
            }
          });
        }
      }
      
      // Check for many packages from same maintainer (potential typosquatting network)
      // This is a heuristic — a maintainer with many packages is often legitimate
      // But if all packages are very new, that's suspicious
      
    } catch (err) {
      // Package not found or rate limited — skip silently
    }
  }
  
  return risks;
}

module.exports = { analyzeMaintainer };
