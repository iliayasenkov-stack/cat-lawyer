export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      const target = new URL("https://cat-lawyer.iliyasenkov.workers.dev" + url.pathname + url.search);
      const headers = new Headers(request.headers);
      headers.delete("host");
      const upstream = await fetch(new Request(target, {
        method: request.method,
        headers,
        body: ["GET","HEAD"].includes(request.method) ? undefined : request.body,
        redirect: "manual"
      }));
      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: upstream.headers
      });
    }
    return env.ASSETS.fetch(request);
  }
};
