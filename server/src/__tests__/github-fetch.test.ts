import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockDnsLookup = vi.hoisted(() => vi.fn());

vi.mock("node:dns/promises", () => ({
  lookup: mockDnsLookup,
}));

import { ghFetch, gitHubPrivateEndpointAllowlist } from "../services/github-fetch.js";

const ALLOWLIST_ENV = "PAPERCLIP_GITHUB_PRIVATE_ENDPOINT_ALLOWLIST";

function redirectTo(location: string, status = 302) {
  return new Response(null, { status, headers: { location } });
}

describe("ghFetch", () => {
  let upstream: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    delete process.env[ALLOWLIST_ENV];
    mockDnsLookup.mockReset();
    upstream = vi.fn(async () => new Response("# Skill\n", { status: 200 }));
    vi.stubGlobal("fetch", upstream);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env[ALLOWLIST_ENV];
  });

  describe("direct URLs", () => {
    it.each([
      ["cloud metadata", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
      ["loopback address", "http://127.0.0.1:3100/api/health"],
      ["loopback name", "http://localhost:3100/api/health"],
      ["loopback IPv6", "http://[::1]:3100/api/health"],
      ["RFC 1918 address", "http://10.0.0.5/internal.md"],
      ["IPv4-mapped IPv6 loopback", "http://[::ffff:7f00:1]/"],
    ])("refuses %s without making a request", async (_label, url) => {
      await expect(ghFetch(url)).rejects.toMatchObject({
        status: 422,
        message: expect.stringContaining("Skill source"),
      });
      expect(upstream).not.toHaveBeenCalled();
    });

    it("refuses a hostname that resolves to a private address", async () => {
      mockDnsLookup.mockResolvedValue([{ address: "10.0.0.5", family: 4 }]);

      await expect(ghFetch("https://skills.internal.example/SKILL.md")).rejects.toMatchObject({
        status: 422,
        message: "Skill source URL cannot resolve to private or reserved network addresses",
      });
      expect(upstream).not.toHaveBeenCalled();
    });

    it("refuses a hostname that resolves to a link-local metadata address", async () => {
      mockDnsLookup.mockResolvedValue([{ address: "169.254.169.254", family: 4 }]);

      await expect(ghFetch("https://metadata.example/SKILL.md")).rejects.toMatchObject({ status: 422 });
      expect(upstream).not.toHaveBeenCalled();
    });

    it.each(["file:///etc/passwd", "ftp://example.com/SKILL.md", "not a url"])(
      "refuses %s",
      async (url) => {
        await expect(ghFetch(url)).rejects.toMatchObject({ status: 422 });
        expect(upstream).not.toHaveBeenCalled();
      },
    );

    it("does not word guard errors as remote MCP errors", async () => {
      await expect(ghFetch("http://127.0.0.1/")).rejects.toMatchObject({
        message: expect.not.stringContaining("MCP"),
      });
    });
  });

  describe("GitHub-owned hosts", () => {
    it("uses the platform fetch and never lets it follow redirects", async () => {
      const response = await ghFetch("https://raw.githubusercontent.com/acme/skills/main/SKILL.md", {
        headers: { accept: "text/plain" },
      });

      expect(await response.text()).toBe("# Skill\n");
      expect(upstream).toHaveBeenCalledTimes(1);
      expect(upstream).toHaveBeenCalledWith(
        "https://raw.githubusercontent.com/acme/skills/main/SKILL.md",
        expect.objectContaining({ redirect: "manual", headers: { accept: "text/plain" } }),
      );
    });

    it("does not treat a lookalike host or a non-default port as GitHub", async () => {
      mockDnsLookup.mockResolvedValue([{ address: "10.0.0.5", family: 4 }]);

      await expect(ghFetch("https://api.github.com.evil.example/x")).rejects.toMatchObject({ status: 422 });
      await expect(ghFetch("https://api.github.com:8443/x")).rejects.toMatchObject({ status: 422 });
      expect(upstream).not.toHaveBeenCalled();
    });
  });

  describe("redirects", () => {
    it("refuses a redirect to the cloud metadata address and does not follow it", async () => {
      upstream.mockResolvedValueOnce(redirectTo("http://169.254.169.254/latest/meta-data/"));

      await expect(ghFetch("https://raw.githubusercontent.com/acme/skills/main/SKILL.md")).rejects.toMatchObject({
        status: 422,
      });
      expect(upstream).toHaveBeenCalledTimes(1);
    });

    it("refuses a redirect to a loopback service", async () => {
      upstream.mockResolvedValueOnce(redirectTo("http://127.0.0.1:3100/api/health", 301));

      await expect(ghFetch("https://api.github.com/repos/acme/skills")).rejects.toMatchObject({ status: 422 });
      expect(upstream).toHaveBeenCalledTimes(1);
    });

    it("refuses a redirect to a hostname that resolves to a private address", async () => {
      mockDnsLookup.mockResolvedValue([{ address: "192.168.1.10", family: 4 }]);
      upstream.mockResolvedValueOnce(redirectTo("https://files.attacker.example/SKILL.md"));

      await expect(ghFetch("https://raw.githubusercontent.com/acme/skills/main/SKILL.md")).rejects.toMatchObject({
        status: 422,
      });
      expect(upstream).toHaveBeenCalledTimes(1);
    });

    it("refuses a redirect to a non-HTTP scheme", async () => {
      upstream.mockResolvedValueOnce(redirectTo("file:///etc/passwd"));

      await expect(ghFetch("https://raw.githubusercontent.com/acme/skills/main/SKILL.md")).rejects.toMatchObject({
        status: 422,
      });
      expect(upstream).toHaveBeenCalledTimes(1);
    });

    it("follows a redirect between GitHub-owned hosts, including a relative Location", async () => {
      upstream
        .mockResolvedValueOnce(redirectTo("/repositories/42/git/trees/main", 301))
        .mockResolvedValueOnce(redirectTo("https://raw.githubusercontent.com/acme/skills/main/SKILL.md"))
        .mockResolvedValueOnce(new Response("# Moved\n", { status: 200 }));

      const response = await ghFetch("https://api.github.com/repos/acme/skills/git/trees/main");

      expect(await response.text()).toBe("# Moved\n");
      expect(upstream.mock.calls.map(([url]) => url)).toEqual([
        "https://api.github.com/repos/acme/skills/git/trees/main",
        "https://api.github.com/repositories/42/git/trees/main",
        "https://raw.githubusercontent.com/acme/skills/main/SKILL.md",
      ]);
    });

    it("stops after too many redirects", async () => {
      upstream.mockImplementation(async () => redirectTo("https://api.github.com/loop"));

      await expect(ghFetch("https://api.github.com/loop")).rejects.toMatchObject({
        status: 422,
        message: expect.stringContaining("Too many redirects"),
      });
      expect(upstream).toHaveBeenCalledTimes(6);
    });

    it("returns a redirect response that has no Location header", async () => {
      upstream.mockResolvedValueOnce(new Response(null, { status: 302 }));

      const response = await ghFetch("https://api.github.com/x");

      expect(response.status).toBe(302);
    });
  });

  describe("private endpoint allowlist", () => {
    it("refuses a private address that is not listed", async () => {
      await expect(ghFetch("https://10.0.0.42:8443/raw/acme/skills/main/SKILL.md")).rejects.toMatchObject({
        status: 422,
      });
      expect(upstream).not.toHaveBeenCalled();
    });

    it("allows a private origin the operator listed, still without following redirects", async () => {
      process.env[ALLOWLIST_ENV] = "https://10.0.0.42:8443";

      const response = await ghFetch("https://10.0.0.42:8443/raw/acme/skills/main/SKILL.md");

      expect(await response.text()).toBe("# Skill\n");
      expect(upstream).toHaveBeenCalledWith(
        "https://10.0.0.42:8443/raw/acme/skills/main/SKILL.md",
        expect.objectContaining({ redirect: "manual" }),
      );
    });

    it("does not extend a listed origin to other private addresses", async () => {
      process.env[ALLOWLIST_ENV] = "https://10.0.0.42:8443";

      await expect(ghFetch("https://10.0.0.43:8443/raw/acme/skills/main/SKILL.md")).rejects.toMatchObject({
        status: 422,
      });
      await expect(ghFetch("https://10.0.0.42:9443/raw/acme/skills/main/SKILL.md")).rejects.toMatchObject({
        status: 422,
      });
      expect(upstream).not.toHaveBeenCalled();
    });

    it("refuses the cloud metadata address even when the operator lists it", async () => {
      process.env[ALLOWLIST_ENV] = "http://169.254.169.254";

      await expect(ghFetch("http://169.254.169.254/latest/meta-data/")).rejects.toMatchObject({ status: 422 });
      expect(upstream).not.toHaveBeenCalled();
    });

    it("keeps checking redirects from a listed origin", async () => {
      process.env[ALLOWLIST_ENV] = "https://10.0.0.42:8443";
      upstream.mockResolvedValueOnce(redirectTo("http://169.254.169.254/latest/meta-data/"));

      await expect(ghFetch("https://10.0.0.42:8443/raw/acme/skills/main/SKILL.md")).rejects.toMatchObject({
        status: 422,
      });
      expect(upstream).toHaveBeenCalledTimes(1);
    });
  });
});

describe("gitHubPrivateEndpointAllowlist", () => {
  it("keeps exact origins and drops anything else", () => {
    const allowlist = gitHubPrivateEndpointAllowlist(
      [
        "https://ghe.internal.example",
        " http://10.0.0.42:8080 ",
        "https://ghe.internal.example/path",
        "https://user:pass@ghe.internal.example",
        "https://ghe.internal.example/?q=1",
        "ftp://ghe.internal.example",
        "ghe.internal.example",
        "",
      ].join(","),
    );

    expect([...allowlist].sort()).toEqual(["http://10.0.0.42:8080", "https://ghe.internal.example"]);
  });

  it("is empty when the variable is unset", () => {
    expect(gitHubPrivateEndpointAllowlist("").size).toBe(0);
  });
});
