const https = require("https");

// Popular PyPI packages
const POPULAR_PYPI = new Set([
  "requests", "flask", "django", "numpy", "pandas", "scipy", "matplotlib",
  "tensorflow", "torch", "keras", "scikit-learn", "sklearn", "pillow",
  "beautifulsoup4", "bs4", "selenium", "scrapy", "fastapi", "uvicorn",
  "sqlalchemy", "celery", "redis", "pymongo", "psycopg2", "boto3",
  "pytest", "coverage", "tox", "black", "flake8", "pylint", "mypy",
  "ipython", "jupyter", "notebook", "pyspark", "airflow", "mlflow",
  "pydantic", "marshmallow", "click", "typer", "rich", "colorama",
  "cryptography", "paramiko", "pyjwt", "oauthlib", "authlib",
  "httpx", "aiohttp", "websockets", "grpcio", "protobuf",
  "lxml", "html5lib", "markdown", "pyyaml", "toml", "json5",
  "celery", " dramatiq", "huey", "rq", "dramatiq",
  "gunicorn", "waitress", "uvicorn", "hypercorn",
  "python-dateutil", "pytz", "arrow", "pendulum",
  "loguru", "structlog", "sentry-sdk", "newrelic",
  "python-dotenv", "hydra-core", "omegaconf",
  "pyarrow", "dask", "polars", "modin",
  "networkx", "sympy", "statsmodels",
  "opencv-python", "opencv-contrib-python", "torchvision", "transformers",
  "langchain", "openai", "anthropic", "llama-index"
]);

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

function findSimilarPyPI(name) {
  const similar = [];
  const lowerName = name.toLowerCase().replace(/[-_\.]/g, "");
  
  for (const popular of POPULAR_PYPI) {
    const normalizedPopular = popular.toLowerCase().replace(/[-_\.]/g, "");
    if (normalizedPopular === lowerName) continue;
    
    const dist = levenshtein(lowerName, normalizedPopular);
    const maxLen = Math.max(lowerName.length, normalizedPopular.length);
    const similarity = 1 - (dist / maxLen);
    
    if (dist <= 2 && dist < maxLen * 0.4) {
      similar.push({
        package: popular,
        editDistance: dist,
        similarity: Math.round(similarity * 100)
      });
    }
  }
  
  return similar.sort((a, b) => b.similarity - a.similarity);
}

async function detectPyPITyposquatting(deps) {
  const risks = [];
  const pypiDeps = deps.filter(d => d.source === "pypi");
  
  for (const dep of pypiDeps) {
    const similar = findSimilarPyPI(dep.name);
    if (similar.length > 0) {
      const best = similar[0];
      risks.push({
        level: best.similarity > 85 ? "HIGH" : "MEDIUM",
        type: "typosquatting",
        package: dep.name,
        ecosystem: "pypi",
        message: `Similar to popular package "${best.package}" (${best.similarity}% match, edit distance: ${best.editDistance})`,
        details: { similarTo: best.package, similarity: best.similarity, editDistance: best.editDistance }
      });
    }
  }
  
  return risks;
}

module.exports = { detectPyPITyposquatting };
