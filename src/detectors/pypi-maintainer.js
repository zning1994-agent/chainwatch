const https = require("https");

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { "User-Agent": "chainwatch/1.0" } }, (res) => {
      let data = "";
      res.on("data", (chunk) => data += chunk);
      res.on("end", () => {
        try { resolve(JSON.parse(data)); } 
        catch (e) { resolve(null); }
      });
    }).on("error", reject);
  });
}

async function analyzePyPIMaintainer(deps) {
  const risks = [];
  const pypiDeps = deps.filter(d => d.source === "pypi");
  
  for (const dep of pypiDeps.slice(0, 30)) {
    try {
      const data = await fetchJSON(`https://pypi.org/pypi/${dep.name}/json`);
      if (!data) continue;
      
      const info = data.info || {};
      const releases = data.releases || {};
      const versions = Object.keys(releases);
      
      // Check: only 1 version ever published (suspicious)
      if (versions.length === 1) {
        const release = releases[versions[0]];
        const uploadTime = release?.[0]?.upload_time_iso_8601;
        
        if (uploadTime) {
          const ageDays = (Date.now() - new Date(uploadTime).getTime()) / (1000 * 60 * 60 * 24);
          
          if (ageDays < 30) {
            risks.push({
              level: "MEDIUM",
              type: "suspicious_package",
              package: dep.name,
              ecosystem: "pypi",
              message: `Only 1 version published, account is ${Math.floor(ageDays)} days old`,
              details: { versions: 1, ageDays: Math.floor(ageDays), created: uploadTime }
            });
          }
        }
      }
      
      // Check: very new package with high similarity to popular name
      if (versions.length <= 2) {
        const firstRelease = releases[versions[0]]?.[0];
        if (firstRelease?.upload_time_iso_8601) {
          const ageDays = (Date.now() - new Date(firstRelease.upload_time_iso_8601).getTime()) / (1000 * 60 * 60 * 24);
          if (ageDays < 60) {
            risks.push({
              level: "LOW",
              type: "new_package",
              package: dep.name,
              ecosystem: "pypi",
              message: `Relatively new package (${Math.floor(ageDays)} days old, ${versions.length} version(s))`,
              details: { versions: versions.length, ageDays: Math.floor(ageDays) }
            });
          }
        }
      }
    } catch (err) {
      // Skip silently
    }
  }
  
  return risks;
}

module.exports = { analyzePyPIMaintainer };
