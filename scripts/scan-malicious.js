#!/usr/bin/env node

/**
 * ChainWatch - Supply Chain Security Scanner
 * Scans npm and PyPI for new malicious/suspicious packages
 */

const https = require("https");
const fs = require("fs");
const path = require("path");

// Known malicious package patterns
const MALICIOUS_PATTERNS = [
  // Typosquatting of popular packages
  { pattern: /^lod-?ash/i, target: "lodash", ecosystem: "npm" },
  { pattern: /^react-?dom/i, target: "react-dom", ecosystem: "npm" },
  { pattern: /^axios-?util/i, target: "axios", ecosystem: "npm" },
  { pattern: /^express-?util/i, target: "express", ecosystem: "npm" },
  { pattern: /^chalk-?type/i, target: "chalk", ecosystem: "npm" },
  { pattern: /^webpack-?cli/i, target: "webpack-cli", ecosystem: "npm" },
  { pattern: /^typescript-?type/i, target: "typescript", ecosystem: "npm" },
  { pattern: /^eslint-?config/i, target: "eslint", ecosystem: "npm" },
  { pattern: /^jest-?config/i, target: "jest", ecosystem: "npm" },
  { pattern: /^dotenv-?cli/i, target: "dotenv", ecosystem: "npm" },
  { pattern: /^uuid-?gen/i, target: "uuid", ecosystem: "npm" },
  { pattern: /^cors-?any/i, target: "cors", ecosystem: "npm" },
  { pattern: /^helmet-?sec/i, target: "helmet", ecosystem: "npm" },
  { pattern: /^multer-?file/i, target: "multer", ecosystem: "npm" },
  { pattern: /^socket-?io-?client/i, target: "socket.io", ecosystem: "npm" },
  { pattern: /^mongoose-?db/i, target: "mongoose", ecosystem: "npm" },
  { pattern: /^sequelize-?orm/i, target: "sequelize", ecosystem: "npm" },
  
  // PyPI typosquatting
  { pattern: /^reques?ts/i, target: "requests", ecosystem: "pypi" },
  { pattern: /^fla?sk/i, target: "flask", ecosystem: "pypi" },
  { pattern: /^dja?ngo/i, target: "django", ecosystem: "pypi" },
  { pattern: /^num?py/i, target: "numpy", ecosystem: "pypi" },
  { pattern: /^panda?s/i, target: "pandas", ecosystem: "pypi" },
  { pattern: /^scik-?it/i, target: "scikit-learn", ecosystem: "pypi" },
  { pattern: /^beauti?ful/i, target: "beautifulsoup4", ecosystem: "pypi" },
  { pattern: /^seleni?um/i, target: "selenium", ecosystem: "pypi" },
  { pattern: /^fasta?pi/i, target: "fastapi", ecosystem: "pypi" },
  { pattern: /^sqlalch?emy/i, target: "sqlalchemy", ecosystem: "pypi" },
  { pattern: /^celer?y/i, target: "celery", ecosystem: "pypi" },
  { pattern: /^pyte?st/i, target: "pytest", ecosystem: "pypi" },
  { pattern: /^boto?3/i, target: "boto3", ecosystem: "pypi" },
  
  // Suspicious naming patterns
  { pattern: /^@corp\//, ecosystem: "npm" },
  { pattern: /^@internal\//, ecosystem: "npm" },
  { pattern: /^@private\//, ecosystem: "npm" },
  { pattern: /-corp$/, ecosystem: "npm" },
  { pattern: /-internal$/, ecosystem: "npm" },
  { pattern: /-private$/, ecosystem: "npm" },
];

// Popular packages database
const POPULAR_PACKAGES = {
  npm: [
    "lodash", "react", "axios", "express", "vue", "angular", "webpack",
    "babel", "typescript", "eslint", "prettier", "jest", "moment",
    "commander", "debug", "semver", "uuid", "colors", "dotenv", "cors",
    "body-parser", "morgan", "helmet", "multer", "socket.io", "mongoose",
    "sequelize", "next", "nuxt", "gatsby", "svelte", "jquery", "d3",
    "three", "redux", "tailwindcss", "bootstrap", "storybook", "cypress",
    "playwright", "puppeteer", "sharp", "bcrypt", "jsonwebtoken", "passport",
    "winston", "pino", "nodemailer", "twilio", "stripe", "eslint", "vite",
    "rollup", "prisma", "typeorm", "knex", "graphql", "fastify", "electron"
  ],
  pypi: [
    "requests", "flask", "django", "numpy", "pandas", "scipy", "matplotlib",
    "tensorflow", "torch", "keras", "scikit-learn", "pillow", "beautifulsoup4",
    "selenium", "scrapy", "fastapi", "uvicorn", "sqlalchemy", "celery", "redis",
    "pymongo", "psycopg2", "boto3", "pytest", "black", "flake8", "pylint",
    "mypy", "ipython", "jupyter", "pyspark", "airflow", "pydantic", "click",
    "rich", "cryptography", "httpx", "aiohttp", "pyyaml", "loguru", "pyarrow",
    "dask", "polars", "networkx", "opencv-python", "transformers", "langchain"
  ]
};

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { 
      headers: { "User-Agent": "chainwatch-scanner/1.0" },
      timeout: 10000
    }, (res) => {
      let data = "";
      res.on("data", (chunk) => data += chunk);
      res.on("end", () => {
        try { resolve(JSON.parse(data)); } 
        catch (e) { resolve(null); }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Timeout")); });
  });
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0)
      );
    }
  }
  return dp[m][n];
}

async function scanNpmRegistry() {
  const alerts = [];
  const seen = new Set();
  
    process.stderr.write("🔍 Scanning npm registry...\n");
  
  // Check recent packages via npm search API
  try {
    // Search for packages with common typosquatting patterns
    const searchTerms = [
      "lodash", "react", "axios", "express", "typescript", "webpack",
      "eslint", "jest", "prettier", "moment", "uuid", "dotenv"
    ];
    
    for (const term of searchTerms.slice(0, 5)) { // Limit to avoid rate limiting
      try {
        const result = await fetchJSON(
          `https://registry.npmjs.org/-/v1/search?text=${term}&size=20`
        );
        
        if (result && result.objects) {
          for (const obj of result.objects) {
            const pkg = obj.package;
            if (!pkg || seen.has(pkg.name)) continue;
            seen.add(pkg.name);
            
            const name = pkg.name.toLowerCase();
            const popular = POPULAR_PACKAGES.npm.find(p => {
              const dist = levenshtein(name, p.toLowerCase());
              return dist > 0 && dist <= 2 && dist < p.length * 0.4;
            });
            
            if (popular) {
              const dist = levenshtein(name, popular.toLowerCase());
              const sim = Math.round((1 - dist / Math.max(name.length, popular.length)) * 100);
              
              alerts.push({
                level: sim > 85 ? "HIGH" : "MEDIUM",
                type: "typosquatting",
                package: pkg.name,
                ecosystem: "npm",
                message: `Similar to "${popular}" (${sim}% match, edit distance: ${dist})`,
                version: pkg.version,
                publisher: pkg.publisher?.username || "unknown",
                date: pkg.date || new Date().toISOString()
              });
            }
          }
        }
      } catch (err) {
        process.stderr.write(`  ⚠️  Error searching npm for "${term}": ${err.message}\n`);
      }
      
      // Rate limiting
      await new Promise(r => setTimeout(r, 500));
    }
  } catch (err) {
    process.stderr.write(`  ⚠️  npm scan error: ${err.message}\n`);
  }
  
  return alerts;
}

async function scanPyPIRegistry() {
  const alerts = [];
  const seen = new Set();
  
  process.stderr.write("🔍 Scanning PyPI registry...\n");
  
  try {
    // Get recent packages from PyPI
    const data = await fetchJSON("https://pypi.org/simple/");
    
    if (data && data.packages) {
      for (const pkg of data.packages.slice(0, 500)) { // Check recent packages
        const name = pkg.name?.toLowerCase();
        if (!name || seen.has(name)) continue;
        seen.add(name);
        
        const popular = POPULAR_PACKAGES.pypi.find(p => {
          const pNorm = p.toLowerCase().replace(/[-_\.]/g, "");
          const nameNorm = name.replace(/[-_\.]/g, "");
          const dist = levenshtein(nameNorm, pNorm);
          return dist > 0 && dist <= 2 && dist < pNorm.length * 0.4;
        });
        
        if (popular) {
          const nameNorm = name.replace(/[-_\.]/g, "");
          const popNorm = popular.toLowerCase().replace(/[-_\.]/g, "");
          const dist = levenshtein(nameNorm, popNorm);
          const sim = Math.round((1 - dist / Math.max(nameNorm.length, popNorm.length)) * 100);
          
          alerts.push({
            level: sim > 85 ? "HIGH" : "MEDIUM",
            type: "typosquatting",
            package: pkg.name,
            ecosystem: "pypi",
            message: `Similar to "${popular}" (${sim}% match, edit distance: ${dist})`,
            version: pkg.version,
            date: new Date().toISOString()
          });
        }
      }
    }
  } catch (err) {
    process.stderr.write(`  ⚠️  PyPI scan error: ${err.message}\n`);
  }
  
  return alerts;
}

async function checkKnownMalicious() {
  const alerts = [];
  
  process.stderr.write("🔍 Checking known malicious packages...\n");
  
  // Check against known malicious package lists
  const knownMalicious = [
    // npm malicious packages (2024-2026)
    { name: "event-stream-patch", ecosystem: "npm", reason: "Credential stealer" },
    { name: "flatmap-stream", ecosystem: "npm", reason: "Backdoor" },
    { name: "cross-env-shadow", ecosystem: "npm", reason: "Data exfiltration" },
    { name: "crossenv", ecosystem: "npm", reason: "Dependency confusion" },
    { name: "mongose", ecosystem: "npm", reason: "Typosquatting" },
    { name: "node-ipc", ecosystem: "npm", reason: "Wiper malware" },
    { name: "peacenotwar", ecosystem: "npm", reason: "Wiper malware" },
    { name: "ua-parser-js", ecosystem: "npm", reason: "Crypto miner" },
    { name: "coa", ecosystem: "npm", reason: "Ransomware" },
    { name: "rc", ecosystem: "npm", reason: "Ransomware" },
    { name: "colors", ecosystem: "npm", reason: "Protestware" },
    { name: "faker", ecosystem: "npm", reason: "Protestware" },
    
    // PyPI malicious packages
    { name: "python-dateutilshadow", ecosystem: "pypi", reason: "Typosquatting" },
    { name: "jeIlyfish", ecosystem: "pypi", reason: "Homoglyph attack" },
    { name: "colourama", ecosystem: "pypi", reason: "Typosquatting" },
    { name: "requesocks", ecosystem: "pypi", reason: "Data exfiltration" },
  ];
  
  for (const pkg of knownMalicious) {
    try {
      let exists = false;
      
      if (pkg.ecosystem === "npm") {
        const data = await fetchJSON(`https://registry.npmjs.org/${pkg.name}`);
        exists = !!data && !!data.name;
      } else if (pkg.ecosystem === "pypi") {
        const data = await fetchJSON(`https://pypi.org/pypi/${pkg.name}/json`);
        exists = !!data && !!data.info;
      }
      
      if (exists) {
        alerts.push({
          level: "HIGH",
          type: "known_malicious",
          package: pkg.name,
          ecosystem: pkg.ecosystem,
          message: `Known malicious package: ${pkg.reason}`,
          reason: pkg.reason,
          date: new Date().toISOString()
        });
      }
    } catch (err) {
      // Skip
    }
  }
  
  return alerts;
}

async function main() {
  process.stderr.write("🔍 ChainWatch Supply Chain Security Scanner\n");
  process.stderr.write("━".repeat(50) + "\n");
  process.stderr.write(`⏰ Scan time: ${new Date().toISOString()}\n`);
  process.stderr.write("\n");
  
  // Run all scans in parallel
  const [npmAlerts, pypiAlerts, maliciousAlerts] = await Promise.all([
    scanNpmRegistry(),
    scanPyPIRegistry(),
    checkKnownMalicious()
  ]);
  
  // Combine and deduplicate
  const allAlerts = [...npmAlerts, ...pypiAlerts, ...maliciousAlerts];
  const seen = new Set();
  const uniqueAlerts = allAlerts.filter(a => {
    const key = `${a.package}-${a.type}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  
  // Sort by severity
  uniqueAlerts.sort((a, b) => {
    const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    return (order[a.level] || 3) - (order[b.level] || 3);
  });
  
  // Build report
  const report = {
    scanTime: new Date().toISOString(),
    summary: {
      total: uniqueAlerts.length,
      high: uniqueAlerts.filter(a => a.level === "HIGH").length,
      medium: uniqueAlerts.filter(a => a.level === "MEDIUM").length,
      low: uniqueAlerts.filter(a => a.level === "LOW").length
    },
    alerts: uniqueAlerts,
    ecosystems: {
      npm: npmAlerts.length,
      pypi: pypiAlerts.length
    }
  };
  
  // Output clean JSON (for piping to file)
  console.log(JSON.stringify(report, null, 2));
  
  // Also output summary to stderr (for display)
  process.stderr.write("\n" + "━".repeat(50) + "\n");
  process.stderr.write(`✅ Scan complete: ${report.summary.total} alerts found\n`);
  process.stderr.write(`   🔴 HIGH: ${report.summary.high}\n`);
  process.stderr.write(`   🟡 MEDIUM: ${report.summary.medium}\n`);
  process.stderr.write(`   🔵 LOW: ${report.summary.low}\n`);
}

main().catch(err => {
  console.error("❌ Scan failed:", err.message);
  process.exit(1);
});
