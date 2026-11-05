import backend from "./src/index.js";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      return backend.fetch(request, env, ctx);
    }
    return env.ASSETS.fetch(request);
  }
};
