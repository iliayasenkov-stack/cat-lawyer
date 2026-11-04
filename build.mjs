import { readFileSync, writeFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";

const encoded = readFileSync("site.html.gz.b64", "utf8").trim();
const html = gunzipSync(Buffer.from(encoded, "base64"));
writeFileSync("index.html", html);
console.log("Restored index.html (" + html.length + " bytes)");
