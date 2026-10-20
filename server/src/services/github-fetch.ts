import { HttpError, unprocessable } from "../errors.js";
import { parseRemoteHttpEndpoint } from "./remote-http-endpoint-guard.js";
import { guardedRemoteHttpFetch } from "./remote-http-fetch.js";

/**
 * Operators who run GitHub Enterprise (or host skill files) on a private
 * network list the exact origins here, comma separated, for example
 * `https://ghe.internal.example,https://10.0.0.42:8443`. Every other private,
 * loopback, and reserved address is refused, and link-local addresses (cloud
 * metadata) are refused even for a listed origin.
 */
const PRIVATE_ENDPOINT_ALLOWLIST_ENV = "PAPERCLIP_GITHUB_PRIVATE_ENDPOINT_ALLOWLIST";
const MAX_REDIRECTS = 5;

/**
 * Hosts GitHub itself operates and that the helpers below build URLs for.
 * They are public services whose DNS an attacker cannot answer, so they keep
 * the platform `fetch` path. Anything else, including a redirect that leaves
 * these hosts, goes through the guarded transport.
 */
const GITHUB_OWNED_HOSTS = new Set([
  "github.com",
  "www.github.com",
  "api.github.com",
  "raw.githubusercontent.com",
]);

export function isGitHubDotCom(hostname: string) {
  const h = hostname.toLowerCase();
  return h === "github.com" || h === "www.github.com";
}

export function gitHubApiBase(hostname: string) {
  return isGitHubDotCom(hostname) ? "https://api.github.com" : `https://${hostname}/api/v3`;
}

export function resolveRawGitHubUrl(hostname: string, owner: string, repo: string, ref: string, filePath: string) {
  const p = filePath.replace(/^\/+/, "");
  return isGitHubDotCom(hostname)
    ? `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${p}`
    : `https://${hostname}/raw/${owner}/${repo}/${ref}/${p}`;
}

function sourceError(message: string, code: string) {
  return unprocessable(
    message
      .replaceAll("Remote MCP connection", "Skill source")
      .replaceAll("Remote MCP endpoint", "Skill source")
      .replaceAll("Remote MCP approved", "Skill source approved"),
    { code },
  );
}

function normalizeAllowlistedOrigin(value: string): string | null {
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    return null;
  }
  if (endpoint.protocol !== "http:" && endpoint.protocol !== "https:") return null;
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) return null;
  if (endpoint.pathname !== "/") return null;
  return endpoint.origin.toLowerCase();
}

export function gitHubPrivateEndpointAllowlist(
  raw = process.env[PRIVATE_ENDPOINT_ALLOWLIST_ENV] ?? "",
): ReadonlySet<string> {
  return new Set(
    raw
      .split(",")
      .map((entry) => normalizeAllowlistedOrigin(entry.trim()))
      .filter((entry): entry is string => entry !== null),
  );
}

function isGitHubOwnedEndpoint(url: URL) {
  return url.protocol === "https:"
    && url.port === ""
    && !url.username
    && !url.password
    && GITHUB_OWNED_HOSTS.has(url.hostname.toLowerCase());
}

function isRedirectStatus(status: number) {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

async function discardBody(response: Response) {
  try {
    await response.body?.cancel();
  } catch {
    // The body is not needed; a failure to cancel it changes nothing.
  }
}

async function fetchHop(
  url: URL,
  init: RequestInit | undefined,
  allowlist: ReadonlySet<string>,
): Promise<Response> {
  try {
    if (isGitHubOwnedEndpoint(url)) {
      return await fetch(url.toString(), { ...init, redirect: "manual" });
    }
    return await guardedRemoteHttpFetch(url, init ?? {}, {
      allowPrivateNetwork: allowlist.has(url.origin.toLowerCase()),
      error: sourceError,
    });
  } catch (error) {
    // Guard rejections already carry a message that says why.
    if (error instanceof HttpError) throw error;
    throw unprocessable(`Could not connect to ${url.hostname} — ensure the URL points to a GitHub or GitHub Enterprise instance`);
  }
}

function dropCrossOriginCredentials(init: RequestInit | undefined): RequestInit | undefined {
  if (!init?.headers) return init;
  const headers = new Headers(init.headers);
  headers.delete("authorization");
  headers.delete("cookie");
  headers.delete("proxy-authorization");
  return { ...init, headers };
}

/**
 * Fetch a skill or repository source over HTTP(S).
 *
 * The URL can come from a company member, so every hop is checked against the
 * same network guard that protects remote MCP and webhook calls: loopback,
 * private, and reserved addresses are refused, link-local (cloud metadata)
 * addresses are always refused, hostnames are resolved once and the socket is
 * pinned to the approved address, and redirects are followed here, one hop at
 * a time, with the guard run again on each `Location`.
 */
export async function ghFetch(url: string, init?: RequestInit): Promise<Response> {
  const allowlist = gitHubPrivateEndpointAllowlist();
  let current = parseRemoteHttpEndpoint(url, sourceError);
  let requestInit = init;

  for (let redirects = 0; ; redirects += 1) {
    const response = await fetchHop(current, requestInit, allowlist);
    if (!isRedirectStatus(response.status)) return response;
    const location = response.headers.get("location");
    if (!location) return response;
    await discardBody(response);
    if (redirects >= MAX_REDIRECTS) {
      throw unprocessable(`Too many redirects while fetching ${current.hostname}`);
    }

    let next: URL;
    try {
      next = parseRemoteHttpEndpoint(new URL(location, current).toString(), sourceError);
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw unprocessable(`Skill source redirected ${current.hostname} to an invalid location`);
    }

    const method = (requestInit?.method ?? "GET").toUpperCase();
    if (
      response.status === 303
      || ((response.status === 301 || response.status === 302) && method !== "GET" && method !== "HEAD")
    ) {
      requestInit = { ...requestInit, method: "GET", body: undefined };
    }
    if (next.origin !== current.origin) {
      requestInit = dropCrossOriginCredentials(requestInit);
    }
    current = next;
  }
}
