/**
 * Keel's in-VM V8 SDK. The module is preloaded and exposes `globalThis.Keel`.
 * It creates no direct upstream connection: every request is sent through the
 * loopback proxy and the trusted kernel broker supplies the authorized socket.
 */

import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";

function requiredEnvironment(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Keel did not provide ${name}`);
  return value;
}

const proxy = new URL(
  process.env.HTTPS_PROXY ?? process.env.HTTP_PROXY ??
    "http://127.0.0.1:18081",
);
const ca = fs.readFileSync(requiredEnvironment("SSL_CERT_FILE"), "utf8");

function bodyBytes(body) {
  if (body === undefined || body === null) return undefined;
  if (typeof body === "string" || Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body);
  throw new TypeError("Keel.fetch body must be a string or Uint8Array");
}

function collect(response, resolve, reject) {
  const chunks = [];
  response.on("data", (chunk) => chunks.push(chunk));
  response.on("error", reject);
  response.on("end", () => {
    const headers = new Headers();
    for (const [name, value] of Object.entries(response.headers)) {
      if (Array.isArray(value)) {
        for (const item of value) headers.append(name, item);
      } else if (value !== undefined) {
        headers.set(name, value);
      }
    }
    resolve(
      new Response(Buffer.concat(chunks), {
        status: response.statusCode,
        statusText: response.statusMessage,
        headers,
      }),
    );
  });
}

function requestThroughTunnel(url, options, resolve, reject) {
  const socket = net.connect(Number(proxy.port || 80), proxy.hostname);
  socket.once("error", reject);
  socket.once("connect", () => {
    socket.write(
      `CONNECT ${url.hostname}:${url.port || 443} HTTP/1.1\r\n` +
        `Host: ${url.hostname}:${url.port || 443}\r\n` +
        "Connection: close\r\n\r\n",
    );
  });
  let response = Buffer.alloc(0);
  const onData = (chunk) => {
    response = Buffer.concat([response, chunk]);
    const end = response.indexOf("\r\n\r\n");
    if (end < 0) return;
    socket.off("data", onData);
    if (!response.subarray(0, end).toString().startsWith("HTTP/1.1 200")) {
      socket.destroy();
      reject(new Error("Keel egress proxy refused the tunnel"));
      return;
    }
    const secure = tls.connect({
      socket,
      servername: url.hostname,
      ca,
    });
    secure.once("error", reject);
    secure.once("secureConnect", () => {
      const request = https.request(url, {
        ...options,
        agent: false,
        createConnection: () => secure,
      });
      request.once("error", reject);
      request.once("response", (value) => collect(value, resolve, reject));
      if (options.body !== undefined) request.write(options.body);
      request.end();
    });
  };
  socket.on("data", onData);
}

/** Fetches HTTP(S) through Keel's trusted egress path. */
export function keelFetch(input, init = {}) {
  const url = new URL(input instanceof Request ? input.url : input);
  const body = bodyBytes(init.body);
  const headers = new Headers(init.headers);
  if (body !== undefined && !headers.has("content-length")) {
    headers.set("content-length", String(Buffer.byteLength(body)));
  }
  const options = {
    method: init.method ?? "GET",
    headers: Object.fromEntries(headers),
    body,
  };
  return new Promise((resolve, reject) => {
    if (url.protocol === "https:") {
      requestThroughTunnel(url, options, resolve, reject);
      return;
    }
    if (url.protocol !== "http:") {
      reject(new TypeError("Keel.fetch supports only HTTP and HTTPS"));
      return;
    }
    const request = http.request({
      hostname: proxy.hostname,
      port: Number(proxy.port || 80),
      path: url.href,
      method: options.method,
      headers: { ...options.headers, host: url.host },
    });
    request.once("error", reject);
    request.once("response", (value) => collect(value, resolve, reject));
    if (body !== undefined) request.write(body);
    request.end();
  });
}

/** Returns the non-secret model placeholder headers Keel expects. */
export function modelHeaders(headers = {}) {
  const result = new Headers(headers);
  const sentinel = requiredEnvironment("KEEL_MODEL_SENTINEL");
  if (process.env.KEEL_MODEL_PROVIDER === "bedrock") {
    result.set("authorization", `Bearer ${sentinel}`);
  } else {
    result.set("x-api-key", sentinel);
    if (!result.has("anthropic-version")) {
      result.set("anthropic-version", "2023-06-01");
    }
  }
  return result;
}

export const keel = Object.freeze({ fetch: keelFetch, modelHeaders });
globalThis.Keel = keel;
