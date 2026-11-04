import { existsSync } from "node:fs";

// Cloudflare Pages deploys the committed index.html directly.
// Keep the compressed archive for backup; do not overwrite the current page during build.
if (!existsSync("index.html")) {
  throw new Error("index.html is missing from the deployment.");
}
console.log("Cat Lawyer: using the committed index.html.");
