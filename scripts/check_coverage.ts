const denoStr = await Deno.readTextFile("./deno.json");
const thresholds = Object.assign(
  { branches: 0, lines: 0 },
  JSON.parse(denoStr).coverageThreshold || {},
);

const lcovData = await Deno.readTextFile("./.coverage/coverage.lcov");
const lines = lcovData.split("\n");

const targets: {
  type: string;
  totalCode: string;
  coveredCode: string;
  coverage: number;
}[] = [
  {
    type: "branches",
    totalCode: "BRF:",
    coveredCode: "BRH:",
    coverage: thresholds.branches || 0,
  },
  {
    type: "lines",
    totalCode: "LF:",
    coveredCode: "LH:",
    coverage: thresholds.lines || 0,
  },
];

function estimateCoverage(
  lines: string[],
  totalCode: string,
  coveredCode: string,
) {
  let total = 0;
  let covered = 0;

  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith(totalCode)) {
      total += parseInt(lines[i].substring(totalCode.length));
    } else if (lines[i].startsWith(coveredCode)) {
      covered += parseInt(lines[i].substring(coveredCode.length));
    }
  }

  if (total === 0) return 100; // Se não houver código para testar, consideramos 100% de cobertura
  return (covered / total) * 100;
}

console.log("🏁 Checking coverage thresholds");

let overallCoverage = true;

for (const target of targets) {
  const coveragePercent = estimateCoverage(
    lines,
    target.totalCode,
    target.coveredCode,
  );
  const formattedPercent = coveragePercent.toFixed(2);

  if (coveragePercent < target.coverage) {
    console.error(
      `❌ ${target.type} coverage: ${formattedPercent}% (below threshold of ${target.coverage}%)`,
    );
    overallCoverage = false;
  } else {
    console.log(
      `✅ ${target.type} coverage: ${formattedPercent}% (above threshold of ${target.coverage}%)`,
    );
  }
}

if (!overallCoverage) {
  console.log("🛑 Failed coverage");
  Deno.exit(1);
}

console.log("🎉 All coverage thresholds met");
Deno.exit(0);
