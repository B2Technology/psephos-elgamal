import { build, emptyDir } from "https://deno.land/x/dnt/mod.ts";

await emptyDir("./dist");

// REF: https://deno.com/blog/publish-esm-cjs-module-dnt

const infoDeno = JSON.parse(Deno.readTextFileSync("deno.json"));
const test = Deno.args.includes("--test");
const version = Deno.args[0] || infoDeno.version;

console.log("Building ESM module", { test, version });

await build({
  entryPoints: ["./src/main.ts", "./src/demo2.ts"],
  outDir: "./dist",
  shims: {
    deno: true,
  },
  package: {
    name: infoDeno.name,
    version,
    description: infoDeno.description,
    license: infoDeno.license,
    repository: {
      type: "git",
      url: "git+https://github.com/B2Technology/psephos-elgamal.git",
    },
    bugs: {
      url: "https://github.com/B2Technology/psephos-elgamal/issues",
    },
  },
  test,
  typeCheck: "both",
  postBuild() {
    Deno.copyFileSync("LICENSE", "dist/LICENSE");
    Deno.copyFileSync("README.md", "dist/README.md");
  },
});
