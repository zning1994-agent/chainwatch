const chalk = require("chalk");

function printHeader() {
  console.log("");
  console.log(chalk.bold.cyan("🔍 ChainWatch v1.0.0 — Supply Chain Security Scanner"));
  console.log(chalk.gray("━".repeat(55)));
}

function printResults(results, verbose = false) {
  const { risks } = results;
  
  if (risks.length === 0) {
    console.log(chalk.green("✅ No supply chain risks detected!"));
    return;
  }
  
  console.log(chalk.yellow(`\n⚠️  RISKS FOUND: ${risks.length}\n`));
  
  for (const risk of risks) {
    const icon = risk.level === "HIGH" ? chalk.red("🔴") : 
                 risk.level === "MEDIUM" ? chalk.yellow("🟡") : chalk.blue("🔵");
    
    const levelLabel = chalk.bold(
      risk.level === "HIGH" ? chalk.red(risk.level) :
      risk.level === "MEDIUM" ? chalk.yellow(risk.level) : chalk.blue(risk.level)
    );
    
    console.log(`${icon} ${levelLabel}: ${risk.type}`);
    console.log(chalk.white(`   Package: ${risk.package}`));
    console.log(chalk.gray(`   ${risk.message}`));
    
    if (verbose && risk.details) {
      console.log(chalk.gray(`   Details: ${JSON.stringify(risk.details, null, 2).split("\n").join("\n          ")}`));
    }
    console.log("");
  }
}

function printSummary(results) {
  const { totalDeps, risks } = results;
  const high = risks.filter(r => r.level === "HIGH").length;
  const medium = risks.filter(r => r.level === "MEDIUM").length;
  const low = risks.filter(r => r.level === "LOW").length;
  
  console.log(chalk.gray("━".repeat(55)));
  
  if (risks.length === 0) {
    console.log(chalk.green(`\n✅ Scan complete. ${totalDeps} dependencies checked, all clean.`));
  } else {
    console.log(chalk.white(`\n📊 Summary:`));
    console.log(chalk.gray(`   Total dependencies: ${totalDeps}`));
    if (high > 0) console.log(chalk.red(`   🔴 HIGH: ${high}`));
    if (medium > 0) console.log(chalk.yellow(`   🟡 MEDIUM: ${medium}`));
    if (low > 0) console.log(chalk.blue(`   🔵 LOW: ${low}`));
    console.log("");
  }
}

module.exports = { printResults, printHeader, printSummary };
