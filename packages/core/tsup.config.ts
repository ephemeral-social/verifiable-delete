import { defineConfig } from "tsup";

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/crypto/index.ts",
    "src/threshold/index.ts",
    "src/receipts/index.ts",
    "src/log/index.ts",
    "src/scan/index.ts",
    "src/smt/index.ts",
  ],
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  target: "es2022",
  outDir: "dist",
});
