/**
 * Network helpers for Keel's V8 harness.
 *
 * `keelFetch` always uses the loopback proxy selected by the runtime. The
 * trusted broker still resolves the destination, applies policy, injects real
 * credentials, and records the action.
 */

function requiredEnvironment(name: string): string {
  const value = Deno.env.get(name);
  if (!value) {
    throw new Error(`Keel did not provide ${name}`);
  }
  return value;
}

const certificate = await Deno.readTextFile(requiredEnvironment("SSL_CERT_FILE"));
const proxy = Deno.env.get("HTTPS_PROXY") ?? Deno.env.get("HTTP_PROXY");
if (!proxy) {
  throw new Error("Keel did not provide its egress proxy");
}
// The proxy URL carries a per-run credential; the loopback proxy refuses
// connections from any other local process.
const proxyUrl = new URL(proxy);
const basicAuth = {
  username: decodeURIComponent(proxyUrl.username),
  password: decodeURIComponent(proxyUrl.password),
};
proxyUrl.username = "";
proxyUrl.password = "";
const client = Deno.createHttpClient({
  caCerts: [certificate],
  proxy: { url: proxyUrl.href, basicAuth },
});

/** Fetches a URL through Keel's policy-enforcing egress broker. */
export function keelFetch(
  input: string | URL | Request,
  init: RequestInit = {},
): Promise<Response> {
  return fetch(input, { ...init, client });
}

/**
 * Returns the non-secret placeholder headers expected by Keel's model proxy.
 * The trusted proxy replaces the placeholder only for the admitted endpoint.
 */
export function modelHeaders(
  headers: HeadersInit = {},
): Headers {
  const result = new Headers(headers);
  const sentinel = requiredEnvironment("KEEL_MODEL_SENTINEL");
  if (Deno.env.get("KEEL_MODEL_PROVIDER") === "bedrock") {
    result.set("authorization", `Bearer ${sentinel}`);
  } else {
    result.set("x-api-key", sentinel);
    if (!result.has("anthropic-version")) {
      result.set("anthropic-version", "2023-06-01");
    }
  }
  return result;
}

/** Stable SDK surface suitable for dependency injection in an eval harness. */
export const keel = Object.freeze({
  fetch: keelFetch,
  modelHeaders,
});
