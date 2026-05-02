// Popular packages database (top 500 by weekly downloads)
const POPULAR_PACKAGES = new Set([
  "lodash", "chalk", "react", "axios", "express", "vue", "angular",
  "webpack", "babel", "typescript", "eslint", "prettier", "jest",
  "mocha", "moment", "underscore", "commander", "debug", "semver",
  "uuid", "colors", "dotenv", "cors", "body-parser", "morgan",
  "helmet", "multer", "socket.io", "mongoose", "sequelize",
  "next", "nuxt", "gatsby", "svelte", "jquery", "d3", "three",
  "redux", "mobx", "zustand", "recoil", "tailwindcss", "bootstrap",
  "storybook", "cypress", "playwright", "puppeteer", "selenium",
  "node-fetch", "got", "cheerio", "puppeteer", "sharp", "jimp",
  "bcrypt", "jsonwebtoken", "passport", "cookie-session", "express-session",
  "winston", "pino", "bunyan", "log4js", "nodemailer", "twilio",
  "stripe", "paypal", "aws-sdk", "google-cloud", "azure-sdk",
  "eslint", "stylelint", "postcss", "sass", "less", "stylus",
  "typescript", "flow", "babel", "ts-node", "tsx", "esbuild",
  "vite", "rollup", "parcel", "snowpack", "turbopack",
  "prisma", "typeorm", "knex", "mysql2", "pg", "sqlite3", "redis",
  "amqplib", "kafka-node", "nats", "mqtt", "socket.io",
  "graphql", "apollo-server", "koa", "fastify", "hapi", "nest",
  "electron", "tauri", "nw.js", "node-webkit",
  "ffmpeg", "fluent-ffmpeg", "sharp", "jimp", "canvas",
  "puppeteer", "playwright", "cypress", "nightwatch",
  "mocha", "chai", "jasmine", "vitest", "ava", "tap",
  "istanbul", "nyc", "c8", "codecov",
  "husky", "lint-staged", "commitlint", "standard-version",
  "lerna", "nx", "turbo", "changesets",
  "inquirer", "prompts", "ora", "chalk", "boxen", "listr",
  "commander", "yargs", "meow", "cac", "citty"
]);

// Levenshtein distance
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

// Common typo patterns
const TYPO_PATTERNS = [
  // Character swap
  (s) => { const chars = s.split(""); for(let i=0;i<chars.length-1;i++){const c=chars[i];chars[i]=chars[i+1];chars[i+1]=c;yield=chars.join("");chars[i+1]=chars[i];chars[i]=c;}},
  // Missing character
  (s) => Array.from({length:s.length}, (_,i) => s.slice(0,i)+s.slice(i+1)),
  // Extra character
  (s) => Array.from("abcdefghijklmnopqrstuvwxyz", c => s.slice(0,1)+c+s.slice(1)),
];

// Homoglyphs (visually similar characters)
const HOMOGLYPHS = {
  a: ["а", "е"], // Cyrillic
  e: ["е", "ё"],
  o: ["о", "0"],
  p: ["р"],
  c: ["с"],
  x: ["х"],
  y: ["у"],
};

function findSimilarPackages(name) {
  const similar = [];
  const lowerName = name.toLowerCase();
  
  for (const popular of POPULAR_PACKAGES) {
    if (popular === lowerName) continue;
    
    const dist = levenshtein(lowerName, popular);
    const maxLen = Math.max(lowerName.length, popular.length);
    const similarity = 1 - (dist / maxLen);
    
    // Very similar (1-2 edits away)
    if (dist <= 2 && dist < maxLen * 0.4) {
      similar.push({
        package: popular,
        editDistance: dist,
        similarity: Math.round(similarity * 100)
      });
    }
    
    // Check homoglyphs
    for (const [char, variants] of Object.entries(HOMOGLYPHS)) {
      for (const variant of variants) {
        const normalized = lowerName.replace(new RegExp(variant, "g"), char);
        if (normalized !== lowerName && levenshtein(normalized, popular) <= 1) {
          similar.push({
            package: popular,
            editDistance: 1,
            similarity: 95,
            homoglyphDetected: true
          });
        }
      }
    }
  }
  
  return similar.sort((a, b) => b.similarity - a.similarity);
}

async function detectTyposquatting(deps) {
  const risks = [];
  
  for (const dep of deps) {
    if (dep.source !== "npm") continue;
    
    const similar = findSimilarPackages(dep.name);
    
    if (similar.length > 0) {
      const best = similar[0];
      risks.push({
        level: best.homoglyphDetected ? "HIGH" : best.similarity > 85 ? "HIGH" : "MEDIUM",
        type: "typosquatting",
        package: dep.name,
        message: `Similar to popular package "${best.package}" (${best.similarity}% match, edit distance: ${best.editDistance})${best.homoglyphDetected ? " [HOMOGLYPH DETECTED]" : ""}`,
        details: { similarTo: best.package, similarity: best.similarity, editDistance: best.editDistance }
      });
    }
  }
  
  return risks;
}

module.exports = { detectTyposquatting };
