const https = require("https");
const { detectTyposquatting } = require("./detectors/typosquatting");
const { analyzeMaintainer } = require("./detectors/maintainer");
const { scanVulnerabilities } = require("./detectors/vulnerability");

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

async function checkPackage(packageName, options) {
  console.log(`\n🔍 Checking package: ${packageName}\n`);
  
  // Check if package exists on npm
  let pkgData;
  try {
    pkgData = await fetchJSON(`https://registry.npmjs.org/${packageName}`);
  } catch (err) {
    return {
      level: "INFO",
      type: "not_found",
      package: packageName,
      message: `Package "${packageName}" not found on npm registry`,
      details: {}
    };
  }
  
  const risks = [];
  
  // 1. Typosquatting check
  const typosquatResults = await detectTyposquatting([{ name: packageName, version: "*", source: "npm" }]);
  risks.push(...typosquatResults);
  
  // 2. Maintainer check
  const maintainerResults = await analyzeMaintainer([{ name: packageName, version: "*", source: "npm" }]);
  risks.push(...maintainerResults);
  
  // 3. Basic info
  const version = pkgData["dist-tags"]?.latest || "unknown";
  const time = pkgData.time?.created || "unknown";
  const maintainers = pkgData.maintainers || [];
  
  console.log(`📦 Package: ${packageName}`);
  console.log(`   Latest version: ${version}`);
  console.log(`   Published: ${time}`);
  console.log(`   Maintainers: ${maintainers.map(m => m.name).join(", ") || "none"}`);
  
  if (risks.length === 0) {
    console.log(`\n✅ No risks detected for ${packageName}`);
  }
  
  return {
    level: risks.length > 0 ? risks[0].level : "CLEAN",
    type: "package_check",
    package: packageName,
    message: risks.length > 0 ? `${risks.length} risk(s) found` : "No risks detected",
    details: {
      version,
      created: time,
      maintainers: maintainers.map(m => m.name),
      risks
    }
  };
}

module.exports = { checkPackage };
