import { describe, expect, it } from "vitest";
import express from "express";
import request from "supertest";
import { baselineSecurityHeaders } from "../middleware/security-headers.js";

function createApp() {
  const app = express();
  app.use(baselineSecurityHeaders());
  app.get("/api/health", (_req, res) => {
    res.status(200).json({ status: "ok" });
  });
  app.get("/callback", (_req, res) => {
    res.set("Referrer-Policy", "no-referrer");
    res.status(200).send("ok");
  });
  return app;
}

describe("baselineSecurityHeaders", () => {
  it("sets nosniff, same-origin framing, and a referrer policy on every response", async () => {
    const res = await request(createApp()).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["x-frame-options"]).toBe("SAMEORIGIN");
    expect(res.headers["referrer-policy"]).toBe("strict-origin-when-cross-origin");
  });

  it("lets a route override the default with a stricter value", async () => {
    const res = await request(createApp()).get("/callback");
    expect(res.status).toBe(200);
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
  });
});
