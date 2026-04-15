import { defineConfig } from "vitest/config";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "verifiable-delete",
          root: __dirname,
          include: [
            "packages/*/src/**/*.test.ts",
            "tests/**/*.test.ts",
          ],
          globals: false,
        },
        resolve: {
          alias: {
            "@ephemeral-social/verifiable-delete": resolve(__dirname, "packages/core/src/index.ts"),
            "cloudflare:workers": resolve(__dirname, "packages/cloudflare/src/__mocks__/cloudflare-workers.ts"),
          },
        },
      },
    ],
  },
});
