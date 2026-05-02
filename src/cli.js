#!/usr/bin/env node

const { Command } = require("commander");
const { scanProject } = require("./scanner");
const { checkPackage } = require("./checker");
const { printResults, printHeader, printSummary } = require("./utils/format");

const program = new Command();

program
  .name("chainwatch")
  .description("🔍 Supply chain attack detection tool")
  .version("1.0.0");

program
  .command("scan")
  .description("Scan project dependencies for supply chain risks")
  .option("-f, --file <path>", "Path to dependency file")
  .option("-v, --verbose", "Show detailed output")
  .option("-j, --json", "Output in JSON format")
  .option("--fail-high", "Exit with error code if HIGH risks found")
  .action(async (options) => {
    printHeader();
    try {
      const results = await scanProject(options);
      if (options.json) {
        console.log(JSON.stringify(results, null, 2));
      } else {
        printResults(results, options.verbose);
        printSummary(results);
      }
      if (options.failHigh && results.risks.some(r => r.level === "HIGH")) {
        process.exit(1);
      }
    } catch (err) {
      console.error("\n❌ Error:", err.message);
      process.exit(1);
    }
  });

program
  .command("check <package>")
  .description("Check a single npm package for risks")
  .option("-v, --verbose", "Show detailed output")
  .option("-j, --json", "Output in JSON format")
  .action(async (packageName, options) => {
    printHeader();
    try {
      const result = await checkPackage(packageName, options);
      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printResults({ risks: [result] }, options.verbose);
        printSummary({ risks: [result] });
      }
    } catch (err) {
      console.error("\n❌ Error:", err.message);
      process.exit(1);
    }
  });

program.parse();
