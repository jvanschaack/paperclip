# Security Assessment: jvanschaack/paperclip

| | |
|---|---|
| Date | 2026-10-20 |
| Repository | `jvanschaack/paperclip` (fork of `paperclipai/paperclip`) |
| Commit assessed | `96824a71d18a4b744b1b5c94b005fd80c7b0533e` (`master`) |
| Assessment branch | `security/assessment-2026-10-20` |
| Method | Defender-side code review of the full working tree, full-history secret scan, dependency audit, static analysis, targeted test runs. Nothing was run against any deployed instance. No credentials were tested, rotated, or revoked. |
| Author | Claude (Mythos 5.1), autonomous session on behalf of the repository owner |

## 1. Executive summary

Paperclip is a mature, deliberately hardened codebase. Company scoping is enforced through a central `assertCompanyAccess` convention, every inbound webhook verifies a provider signature in constant time and fails closed, the public MCP OAuth server is a correct PKCE implementation, outbound HTTP has a strong SSRF guard, HTML artifacts are rendered in an opaque-origin sandbox, markdown is never rendered raw, and CI never executes pull-request code with secrets. No live credential exists in the working tree or in any of the 5,442 commits of history. No evidence of an active compromise or backdoor was found.

The real risk sits at the two places where the product's own trust model is thin: the boundary between an **agent (which may be prompt-injected by content from Slack, email, or GitHub)** and the control plane, and the **`local_trusted` single-operator mode** that the quickstart installs by default.

### Counts by severity

| Severity | Count | Fixed on the branch |
|---|---|---|
| Critical | 0 | 0 |
| High | 3 | 2 |
| Medium | 13 | 1 partial |
| Low | 22 | 3 |
| Informational | 12 | 2 |
| **Total** | **50** | **8** |

### Top three risks

1. **An agent API key could run arbitrary shell on the Paperclip host (H-02).** `POST /api/routines/:id/run` accepted `executionWorkspaceSettings.workspaceStrategy.provisionCommand` from agent callers, bypassing the guard that issues, projects, and agents already apply. A prompt-injected agent only needs a routine assigned to itself. **Fixed on the branch.**
2. **DNS rebinding could take over a `local_trusted` instance (H-01).** The private-hostname guard, the only cross-site defense in local mode, trusted a client-supplied `X-Forwarded-Host` header. A malicious web page could then drive the implicit instance-admin API. **Fixed on the branch.**
3. **Agents can widen their own blast radius without a human (M-02, M-03, H-03).** By default a CEO-role agent can rewrite a peer agent's trust preset, any standard agent can create new active agents, and skill import performs an unguarded server-side fetch of any URL including the cloud metadata endpoint. These are behavior-changing fixes and are described, not applied.

Secondary: the dependency tree carries 56 advisories (1 critical, 21 high), nearly all transitive and almost all resolvable by a lockfile-only `pnpm update` within the existing semver ranges (M-13).

## 2. Stack and threat model as established

### Stack

| Layer | Facts from the code |
|---|---|
| Language / build | TypeScript (ESM), pnpm 9.15.4 workspace, Node `>=24.11.0` policy, Vitest 5, Vite 8, Rust runner under `packages/paperclip-runner` |
| API | Express 5.2.1 in `server/src` (`app.ts`, `index.ts`); routes under `server/src/routes/*` (about 95 files), services under `server/src/services` |
| UI | React 19 + Vite SPA in `ui/src`, served by the API server; plugin UIs loaded same-origin |
| Data | Postgres via Drizzle (`packages/db`), embedded PGlite/embedded-postgres in dev; file storage on local disk or S3 (`server/src/storage`) |
| Auth: humans | Better Auth 1.7.2 (`server/src/auth/better-auth.ts`), cookie session `HttpOnly; SameSite=Lax; Secure` unless disabled; roles `instance_admin` plus company `owner > admin > operator > viewer` |
| Auth: agents | Bearer API keys (SHA-256 hashed at rest, `agent_api_keys`), per-run HS256 JWTs with per-instance/per-company derived keys, runtime-tools HMAC tokens, board API keys |
| Deployment modes | `local_trusted` (no login, loopback only, implicit instance-admin actor) and `authenticated` with `private` or `public` exposure (`server/src/config.ts`, `doc/DEPLOYMENT-MODES.md`); Docker image defaults to `authenticated` + `private` |
| Unauthenticated ingress | `/api/liveness`, `/api/health`, Better Auth, chat webhooks (Slack, Discord, Telegram, Teams, GitHub, AgentMail, voice), public MCP + OAuth, runtime connection intents, customer-success permits, muse transport, cloud control (Ed25519 JWS), public routine triggers, `/api/openapi.json` |
| External services | Model providers (Anthropic, OpenAI, Google, xAI, Bedrock, OpenRouter), chat platforms, GitHub, AWS Secrets Manager, S3, Daytona and other sandbox providers, Browser-Use, Sentry (opt-in), first-party telemetry (opt-out) |
| Secrets | `local_encrypted` provider: AES-256-GCM, random IV, master key `randomBytes(32)` in a 0600 file; AWS Secrets Manager provider; strict mode default in authenticated deployments |
| CI/CD | 22 GitHub Actions workflows; PR CI runs without secrets via a reusable workflow pinned to `@master`; `commitperclip-review.yml` uses `pull_request_target` but only checks out `master`; npm publishing via OIDC trusted publishing; GHCR images attested; lockfile refreshes owned by CI |
| Containers / IaC | Root `Dockerfile` (multi-stage, `node:24-trixie-slim`, drops to `node` via tini + gosu, exposes 3100); `docker/docker-compose.yml`, quickstart and untrusted-review compose files; Podman quadlets; ECS task definition; no Terraform, Helm, Kubernetes manifests, or Cloudflare config |

### Threat model used

| Attacker | Reaches |
|---|---|
| Unauthenticated internet attacker | Webhook and OAuth ingress, health, Better Auth sign-up/sign-in, static UI, any `authenticated + public` instance, and DNS-rebinding against a `local_trusted` instance via the operator's browser |
| Authenticated low-privilege user | A company member (non-owner) or an agent API key holder; can reach every company-scoped route |
| Compromised dependency | npm packages installed at build or publish time, GitHub Actions, base images, `@latest` agent CLIs baked into images |
| Malicious content reaching an AI step | Slack/Discord/Telegram/Teams messages, inbound email, GitHub issue and PR bodies, web pages visited by Browser-Use, files in repositories, all of which become agent prompt input |

### AI trust boundary (server-enforced, verified)

An agent **cannot** approve or reject approvals (including its own hire approvals), approve tool-action requests, change budgets, manage secret definitions or providers, set process or host-command adapter settings, invite users, or act in another company. These are enforced in route handlers, not by prompt instructions. Untrusted text is fenced and labelled before it enters a prompt (`server/src/services/heartbeat/task-markdown.ts`).

An agent **can**, without a human, create and update issues, assign tasks, manage tool connections, read secret values bound to it, propose secrets, run shell commands inside its workspace (unrestricted outbound HTTP from local adapters), create active agents unless `requireBoardApprovalForNewAgents` is set (M-03), and, if it holds the CEO role, rewrite peer agents' permissions and trust presets (M-02). In `local_trusted` mode every one of the "cannot" items above is self-approvable because any host-local process is the implicit instance admin (M-04).

## 3. Findings table

Ordered by severity. "Applied" means the fix is committed on `security/assessment-2026-10-20`.

| ID | Severity | Title | Location | Applied |
|---|---|---|---|---|
| H-01 | High | Private-hostname guard trusts client-supplied `X-Forwarded-Host` (DNS-rebinding bypass of `local_trusted`) | `server/src/middleware/private-hostname-guard.ts:8-19` | Yes |
| H-02 | High | Agent API key can set host-executed workspace commands through `POST /routines/:id/run` | `server/src/routes/routines.ts:629-640` | Yes |
| H-03 | High | SSRF with response read-back via skill import (`ghFetch` bypasses the SSRF guard) | `server/src/services/github-fetch.ts:19-25`, `company-skills.ts:1732` | No |
| M-01 | Medium | Member role update does not bound the new role by the actor's rank; grants written unfiltered | `server/src/routes/access.ts:4471-4530` | No |
| M-02 | Medium | CEO-role agent can rewrite any same-company agent's trust preset and permissions | `server/src/routes/agents.ts:4799-4815` | No |
| M-03 | Medium | Standard agents create immediately active agents by default (no board approval) | `server/src/routes/agents.ts:4614-4631`, `packages/db/src/schema/companies.ts:19-21` | No |
| M-04 | Medium | `local_trusted`: every host-local process is an implicit instance admin; mutation guard skips it (CSRF for body-less and multipart routes) | `server/src/middleware/auth.ts:241-256`, `board-mutation-guard.ts:88-101` | No |
| M-05 | Medium | Agent subprocesses inherit control-plane secrets (`BETTER_AUTH_SECRET`, `DATABASE_URL`, `AWS_*`) | `packages/adapter-utils/src/server-utils.ts:3516-3533`; `packages/adapters/claude-local/src/server/execute.ts:319` | No |
| M-06 | Medium | Open self-registration is the default in `authenticated` mode; first-admin claim is first-come-first-served | `server/src/config.ts:231-235`, `routes/access.ts:2756-2783` | No |
| M-07 | Medium | AI-connection `routing.baseUrl` reaches an unguarded server-side fetch | `server/src/services/fast-response-provider.ts:139-158`, `decision-model-provider.ts:47` | No |
| M-08 | Medium | Compose stack publishes Postgres on all interfaces with password `paperclip` | `docker/docker-compose.yml:2-16` | No |
| M-09 | Medium | No baseline security headers on the SPA and API (clickjacking, sniffing, referrer leak) | `server/src/app.ts` (no global middleware) | Partial |
| M-10 | Medium | Release publishes resolve dependencies at publish time (`--no-frozen-lockfile`); canary ships on every master push | `.github/workflows/release.yml:462,769,1058,1449,1514` | No |
| M-11 | Medium | `@latest` agent CLIs installed as root into shipped images; `curl \| bash` NodeSource bootstrap | `Dockerfile:174-181`, `docker/agent-runtime/Dockerfile.base:31` | No |
| M-12 | Medium | Any `v*` tag push republishes `ghcr.io/paperclipai/paperclip:latest` with no environment gate | `.github/workflows/docker.yml:3-15,280-292` | No |
| M-13 | Medium | 56 known-vulnerable dependency versions in the lockfile (1 critical, 21 high); Express 5.2.1 in the server carries `proxy-addr`, `qs`, `body-parser`, `path-to-regexp` advisories; `sharp` 0.35.4 librsvg CVE | `pnpm-lock.yaml`, `server/package.json` | No |
| L-01 | Low | Instance-admin environment PATCH/probe resolves another company's secrets from unchecked `?companyId=` | `server/src/routes/environments.ts:524-545` | No |
| L-02 | Low | Plugin webhook ingress persists unauthenticated payloads and all headers before verification | `server/src/routes/plugins.ts:2692-2800` | No |
| L-03 | Low | Documented placeholder secrets accepted in `authenticated`/`public` deployments | `.env.example:4-5`, `server/src/auth/better-auth.ts:246-250` | No |
| L-04 | Low | Legacy raw-secret agent-JWT fallback on by default; agent key defaults to `BETTER_AUTH_SECRET` | `server/src/agent-auth-jwt.ts:38,218-226` | No |
| L-05 | Low | `/api/openapi.json` served unauthenticated in `authenticated` mode | `server/src/routes/openapi.ts:12575-12581` | No |
| L-06 | Low | Public routine triggers have no rate limit; `signingMode: "none"` is URL-only | `server/src/routes/routines.ts:656-677`, `services/routines.ts:3032` | No |
| L-07 | Low | Webhook and OAuth limiters key on `req.ip` while `TRUST_PROXY` is unset by default | `server/src/routes/chat-channels.ts:716-738`, `voice-sessions.ts:93-96`, `public-mcp.ts:24-38` | No |
| L-08 | Low | `baseRef` reaches git argv positionally without validation or `--` | `packages/shared/src/validators/issue.ts:173`; `server/src/services/workspace-runtime.ts:1038,1082,4051` | No |
| L-09 | Low | Agent-settable `worktreeParentDir` accepts absolute and `~` paths | `packages/shared/src/validators/issue.ts:183`; `workspace-runtime.ts:801-806` | No |
| L-10 | Low | `window.open(src, "_blank")` without `noopener` on markdown images (reverse tabnabbing) | `ui/src/pages/IssueDetail.tsx:5926` | Yes |
| L-11 | Low | Remote images in agent-authored markdown leak the full instance URL via `Referer` | `ui/src/components/MarkdownBody.tsx:1017-1032` | Partial |
| L-12 | Low | `text/html` issue attachments lack a `sandbox` CSP; hand-built `Content-Disposition` can throw on CR/LF | `server/src/routes/issues.ts:19577-19600`, `assets.ts:370`, `access.ts:3478` | No |
| L-13 | Low | Plugin UI bundles served unauthenticated with `Access-Control-Allow-Origin: *` | `server/src/routes/plugin-ui-static.ts:207-300,489` | No |
| L-14 | Low | Mermaid SVG injected with `dangerouslySetInnerHTML`, trusting only mermaid's sanitizer | `ui/src/components/MarkdownBody.tsx:728-767` | No |
| L-15 | Low | Sandboxed HTML artifact can navigate itself to an external site (in-frame phishing) | `ui/src/components/HtmlArtifactPreview.tsx:12` | No |
| L-16 | Low | `${{ inputs.stable_date }}` interpolated into `run:` in release jobs | `.github/workflows/release.yml:1456-1457,1545-1546` | No |
| L-17 | Low | Mutable action tags in jobs holding `packages:write`, `contents:write`, or `id-token:write` | `docker.yml`, `agent-runtime-images.yml`, `release.yml`, `refresh-lockfile.yml`, `storybook-visual.yml` | No |
| L-18 | Low | `persist-credentials` left at default on the `pull_request_target` checkout and other privileged checkouts | `.github/workflows/commitperclip-review.yml:20-23`; `docker.yml:81-86,291-294` | Partial |
| L-19 | Low | Lockfile-edit policy exemption keyed only on a PR-controlled branch name | `.github/workflows/pr-trusted.yml:56-68` | No |
| L-20 | Low | `agent-runtime-images.yml` dispatch can overwrite and re-sign any existing version tag | `.github/workflows/agent-runtime-images.yml:10-24,54-58` | No |
| L-21 | Low | `.dockerignore` does not exclude `.env*` or key files while the build does `COPY . .` | `.dockerignore`, `Dockerfile:130` | Yes |
| L-22 | Low | CLI-auth approval URL built from client `X-Forwarded-Host` when no public URL is configured | `server/src/routes/access.ts:148-162` | No |
| I-01 | Info | Board-claim token and code compared with `!==` | `server/src/board-claim.ts:35-37,155` | Yes |
| I-02 | Info | GCM decrypt did not pin the auth tag length | `server/src/secrets/local-encrypted-provider.ts:220` | Yes |
| I-03 | Info | `PATCH /api/auth/profile` mounted before `boardMutationGuard` | `server/src/app.ts:669` vs `:751` | No |
| I-04 | Info | Anonymous `/api/health` discloses mode, exposure, commit, bootstrap state, cloud slug | `server/src/routes/health.ts:395-427` | No |
| I-05 | Info | 10 MB JSON bodies parsed before authentication on every non-webhook path | `server/src/app.ts:593-594` | No |
| I-06 | Info | Cloud-tenant trusted-header path is a single shared secret that conveys any user and role | `server/src/middleware/auth.ts:619-790` | No |
| I-07 | Info | Plugin code runs with full origin privileges in the browser and in a `node:vm` context on the server | `ui/src/plugins/slots.tsx:427,446`; `server/src/services/plugin-runtime-sandbox.ts:156` | No |
| I-08 | Info | `LIKE`/`ILIKE` patterns not wildcard-escaped (parameterized; no injection) | `server/src/routes/cases.ts:705-708`, `tool-gateway.ts:813-840` | No |
| I-09 | Info | Zip reader builds `files` as a plain object (`__proto__` entry sets the local prototype) | `packages/shared/src/portability-zip.ts:294-308` | No |
| I-10 | Info | Master key accepts a raw 32-character passphrase; Better Auth instance selection reads `x-forwarded-proto`; `http://` variants of allowed hostnames are trusted origins; tool-action signing secret defaults to empty in compose (fail-closed) | `local-encrypted-provider.ts:42-45`; `better-auth.ts:170-203`; `docker-compose.yml:44` | No |
| I-11 | Info | Lockfile refresh PRs auto-merge with `GITHUB_TOKEN`; canary/nightly retry publishes with `--provenance=false`; ECS task definition pins `:latest` | `refresh-lockfile.yml:40,55-98`; `scripts/release-lib.sh:385-407`; `docker/ecs-task-definition.json:12` | No |
| I-12 | Info | Documentation drift: rate limiting is on for all `authenticated` deployments while `doc/DEPLOYMENT-MODES.md` says private is off by default; `.env.example` placeholder text appears in a server error message | `server/src/auth/better-auth.ts:73-84`; `doc/DEPLOYMENT-MODES.md` | No |

## 4. Detailed findings

### H-01: Private-hostname guard trusts client-supplied `X-Forwarded-Host`

- **Severity:** High. In `local_trusted` mode (the quickstart default) this header is the only thing standing between a malicious web page and the implicit instance-admin API.
- **Location:** `server/src/middleware/private-hostname-guard.ts:8-19` (`extractHostname`); enablement `server/src/app.ts:308-317`; mutation-guard exemption for `local_implicit` actors at `server/src/middleware/board-mutation-guard.ts:92-101`.
- **Attack path:** Unauthenticated internet attacker. The operator runs Paperclip locally (`127.0.0.1:3100`) and visits `attacker.example`, served on port 3100, whose DNS record then flips to `127.0.0.1`. The page issues same-origin `fetch("/api/...")` calls carrying `X-Forwarded-Host: localhost`. Custom headers on a same-origin request need no CORS preflight. The guard reads the forwarded header first, sees `localhost`, and passes. The actor middleware installs the `local_implicit` instance-admin actor (`auth.ts:245-251`), which `boardMutationGuard` exempts from the Origin check. Every `/api` route is now reachable with full board privilege: agents, secrets bound to agents, shell-capable runtimes, approvals. In `authenticated + private` the same header bypasses the hostname allowlist, but a rebinding page lacks the session cookie, so impact there is reconnaissance only.
- **Evidence (before the fix):**
  ```ts
  const forwardedHost = req.header("x-forwarded-host")?.split(",")[0]?.trim();
  const hostHeader = req.header("host")?.trim();
  const raw = forwardedHost || hostHeader;
  ```
  The sibling guard already does this correctly (`board-mutation-guard.ts:25-41`): it consults `req.app.get("trust proxy fn")` before honoring the forwarded header, and `board-mutation-guard.test.ts:106` names the header as untrusted from a direct client. `private-hostname-guard.test.ts` had no forwarded-host case. The live-events WebSocket upgrade (`server/src/realtime/live-events-ws.ts:148-156`) never passes this guard and, in `local_trusted`, accepts any `Origin`.
- **Fix:** Honor `X-Forwarded-Host` only when Express's compiled `trust proxy fn` trusts the immediate peer, mirroring `requestHost()` in the mutation guard. Add tests for the untrusted and trusted cases. Separately (not applied): validate `Host`/`Origin` on the live-events WebSocket upgrade against the same allow-set.
- **Applied:** Yes. Behavior is unchanged for direct clients and for deployments with `TRUST_PROXY` set. A deployment proxied without `TRUST_PROXY` that relied on the proxy's `X-Forwarded-Host` to pass the allowlist will now be checked on the real `Host` header; the documented contract (`doc/CLI.md:28`, `doc/public-mcp.md:33`) already requires `TRUST_PROXY` behind a proxy.

### H-02: Agent API key can set host-executed workspace commands through `POST /routines/:id/run`

- **Severity:** High. A low-privilege agent bearer key, including one driven by prompt injection, obtains `sh -c` execution on the Paperclip host as the server user. The repository already has a guard for exactly this on every other route.
- **Location:** `server/src/routes/routines.ts:629-640` (route, before the fix); schema `packages/shared/src/validators/routine.ts:182` (`executionWorkspaceSettings: issueExecutionWorkspaceSettingsSchema`); `packages/shared/src/validators/issue.ts:245-253` (`workspaceStrategy.provisionCommand`, `runtimeProvisionCommand`, `teardownCommand`, `workspaceRuntime.commands[]`); settings copied verbatim onto the dispatched issue at `server/src/services/routines.ts:1800-1802,1944-1946`; sinks `server/src/services/workspace-runtime.ts:3066-3080` (`executeProcess({ command: shell, args: ["-c", ...] })`) and `server/src/services/environment-run-orchestrator.ts:484-490` (`bash -lc provisionCommand`). The existing guard `assertNoAgentHostWorkspaceCommandMutation` (`server/src/routes/workspace-command-authz.ts:70-75`) is applied on issues (`routes/issues.ts:12183,12721,12996,13628`), projects, execution workspaces, and agents, but was not applied on routines.
- **Attack path:** Authenticated low-privilege user (any agent API key). The agent creates a routine assigned to itself (`assertBoardCanAssignTasks` returns early for agents, `routines.ts:91`; `assertCanManageCompanyRoutine` only requires self-assignment), then calls `POST /api/routines/:id/run` with `{"executionWorkspaceSettings":{"workspaceStrategy":{"type":"git_worktree","provisionCommand":"<anything>"}}}`. The run creates an issue carrying those settings; when the heartbeat provisions the worktree the command runs on the host with the server's environment. Precondition: the company has a project with a git workspace, which is the normal case.
- **Evidence (before the fix):**
  ```ts
  router.post("/routines/:id/run", validateIssueMutationBody(runRoutineSchema), async (req, res) => {
    const routine = await assertCanManageExistingRoutine(req, req.params.id as string);
    ...
    await assertBoardCanAssignTasks(req, routine.companyId);
    const run = await svc.runRoutine(routine.id, req.body, { agentId: ..., userId: ... });
  ```
  Compare `routes/issues.ts:12183`: `assertNoAgentHostWorkspaceCommandMutation(req, collectIssueWorkspaceCommandPaths(req.body));`.
- **Fix:** Call the existing guard with `collectIssueWorkspaceCommandPaths(req.body)` before `runRoutine`. Board users are unaffected; agent callers that attach host commands receive the same 403 they already receive on issue routes. Defense in depth (not applied): strip the command fields in `dispatchRoutineRun` when the actor is an agent.
- **Applied:** Yes, with two route tests (agent rejected, board allowed).

### H-03: SSRF with response read-back via skill import

- **Severity:** High. A company member, or an agent allowed by company skill policy, makes the server fetch any `http://` or `https://` URL, including `http://169.254.169.254/...`, with redirects followed, and the response body is persisted into the skill inventory where it can be read back.
- **Location:** `server/src/services/github-fetch.ts:19-25` (`ghFetch` is a bare `fetch(url, init)`); `server/src/services/company-skills.ts:755-770` (`fetchText`/`fetchJson`), `:1630-1671` (`gitHubApiBase(hostname)` builds `https://${hostname}/api/v3` for any host), `:1732-1733` (`if (url.startsWith("http://") || url.startsWith("https://")) { const markdown = await fetchText(url); ... }`); route `server/src/routes/company-skills.ts:1393-1405` (`POST /companies/:companyId/skills/import`, authorized by `assertCanMutateCompanySkills(..., "skills.import")`). The same pattern exists on board-only paths in `server/src/services/company-portability.ts:2888-2922,3795-3830` and `server/src/services/skills-catalog.ts:222-223`.
- **Attack path:** Authenticated low-privilege user. `POST /api/companies/:id/skills/import {"source":"http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>"}` stores the metadata response as skill markdown. Alternatively `source: "https://attacker.example/o/r"` makes the server call `https://attacker.example/api/v3/repos/o/r` and raw files; the attacker's server answers with a 302 to an internal `http://` target, which undici follows across schemes.
- **Evidence:**
  ```ts
  export async function ghFetch(url: string, init?: RequestInit): Promise<Response> {
    try { return await fetch(url, init); } catch { throw unprocessable(`Could not connect to ${new URL(url).hostname} ...`); }
  }
  ```
  Contrast the hardened path `server/src/services/remote-http-fetch.ts` (DNS pinned, link-local always denied, `redirect: "manual"`), used by remote MCP, webhooks, plugin HTTP, and GitHub attachments.
- **Fix:** Implement `ghFetch` on top of `guardedRemoteHttpFetch(parseRemoteHttpEndpoint(url, err), init, { allowPrivateNetwork: false, error: err })`, re-guard each redirect hop (max 3), and require `https:` for non-`github.com` hosts. Give operators with GitHub Enterprise on a private network the same explicit origin allowlist that `server/src/adapters/http/remote-fetch.ts:41-77` already provides. Apply the same wrapper in `company-portability.ts` and `skills-catalog.ts`.
- **Applied:** No. The change alters behavior for operators importing from private-network GitHub Enterprise hosts, so it needs an allowlist decision.

### M-01: Member role update does not bound the new role by the actor's rank

- **Severity:** Medium. Needs a non-default delegation (`users:manage_permissions` granted to a non-owner), but then lets that user mint owners and hand out any permission key, defeating the rank model enforced on invites.
- **Location:** `server/src/routes/access.ts:4471-4530` (`PATCH /companies/:companyId/members/:memberId` and `/role-and-grants`); rank check `access.ts:1292-1328`; service `server/src/services/access.ts:516-610,1086-1130`.
- **Attack path:** Authenticated low-privilege user holding `users:manage_permissions` creates or uses a second account (sign-up is open by default, M-06), then `PATCH .../members/:id {"membershipRole":"owner"}` and on `/role-and-grants` `grants:[{permissionKey:"users:manage_permissions"},{permissionKey:"joins:approve"}]`. `getProtectedMemberReason` checks only the target's current rank, never `req.body.membershipRole` or the grant keys. The invite path does guard this (`access.ts:3046-3053`).
- **Fix:** After `assertCanManageCompanyMember`, resolve the actor's role and reject when the requested role ranks at or above it (unless instance admin or local implicit). On `/role-and-grants`, reject any `permissionKey` the actor does not hold, reusing the invite path's pattern. Behavior-changing for delegated managers who currently promote peers, so described only.

### M-02: CEO-role agent can rewrite any same-company agent's trust preset and permissions

- **Severity:** Medium. A prompt-injected CEO agent can lift `low_trust_review` containment on another agent or grant `canCreateAgents`, server-side, with no human in the loop.
- **Location:** `server/src/routes/agents.ts:4799-4815`; `packages/shared/src/validators/agent.ts:293-299` (`updateAgentPermissionsSchema` accepts `trustPreset`, `authorizationPolicy`); `server/src/services/agents.ts:48-62`.
- **Attack path:** `PATCH /api/agents/<contained-reviewer>/permissions {"canCreateAgents":true,"canAssignTasks":true,"trustPreset":"standard"}` with the CEO's agent key. The route checks only `actorAgent.role === "ceo"` and then calls `svc.updatePermissions(id, req.body)` with no self-trust check and no approval.
- **Fix:** For agent actors, reject trust-widening `trustPreset`/`authorizationPolicy` values and `canCreateAgents: true`, or route them through an approval like `hire_agent`; apply `resolveAgentSelfTrustPreset` to the CEO actor. Behavior-changing but narrow.

### M-03: Standard agents create immediately active agents by default

- **Severity:** Medium. `requireBoardApprovalForNewAgents` defaults to `false` and standard agents default to `canCreateAgents: true`, so one injected instruction expands the autonomous workforce unattended.
- **Location:** `packages/db/src/schema/companies.ts:19-21`; `server/src/routes/agents.ts:4614-4631`; defaults in `agents.ts:1398-1414` and `services/authorization.ts:2609`; `doc/agent-permission-defaults.md`.
- **Attack path:** `POST /api/companies/<id>/agents` with an agent key creates an active agent with attacker-chosen instructions and default grants. Hard limits that still hold: process adapter and host commands are blocked for agents (`agents.ts:4304-4308`), the budget hard-stop, and low-trust callers are blocked.
- **Fix:** Default the flag to `true` for new companies (migration leaves existing rows), or always route agent-actor creation through `agent-hires` (which the skill documentation already describes). Behavior-changing with low blast radius.

### M-04: `local_trusted` makes every host-local process an implicit instance admin

- **Severity:** Medium. Documented single-operator model and the default of `quickstart --yes`, but it makes "governed actions require human approval" advisory against a prompt-injected agent that omits its bearer token, and it leaves body-less and multipart board mutations open to cross-site requests.
- **Location:** `server/src/middleware/auth.ts:241-256` (default actor), `server/src/services/authorization.ts:1971-1976` (`allow_local_board`), `server/src/middleware/board-mutation-guard.ts:85-101` (`local_implicit` exempt from the Origin check), `routes/approvals.ts:296-297,412-413`, `routes/tool-gateway.ts:605-615`.
- **Attack path:** (a) An agent spawned by a local adapter reads an injected instruction and sends `POST http://127.0.0.1:3100/api/approvals/<id>/approve` without `Authorization`; it is the board. (b) A web page the operator visits submits a top-level `<form method=POST enctype=multipart/form-data>` or a `no-cors` fetch to a body-less `POST /api/...` route; JSON routes are protected only because `application/json` forces a preflight that no CORS middleware answers.
- **Fix:** Document the limitation in `doc/DEPLOYMENT-MODES.md` and `doc/LOW-TRUST-PRESETS.md`. Add an opt-in flag under which bearer-less non-GET requests resolve to `none` (the UI keeps its session or a local board key). Short term: refuse `local_implicit` when `x-paperclip-run-id` is present, and in `boardMutationGuard` reject `local_implicit` mutations that carry `Sec-Fetch-Site: cross-site` or an untrusted `Origin` (CLI and agent callers send neither). Behavior-changing; ship behind a flag.

### M-05: Agent subprocesses inherit control-plane secrets

- **Severity:** Medium rather than High because local adapters already run as the server's OS user, so this is the most discoverable of several equivalent paths rather than a new boundary break.
- **Location:** `packages/adapter-utils/src/server-utils.ts:3516-3533` (`sanitizeInheritedPaperclipEnv` removes only `PAPERCLIP_*` and three identity keys), `:4722-4725`; `packages/adapters/claude-local/src/server/execute.ts:319-335` (`{...process.env, ...env}` passed to the runtime-command install path with no sanitizer); same pattern in `codex-local`, `cursor-local`, `gemini-local`, `opencode-local`, `pi-local`, `kimi-local`, `grok-local`; `server/src/routes/board-chat.ts:259`; `server/src/routes/execution-workspaces.ts:719`.
- **Attack path:** In an `authenticated` deployment such as the compose stack, an agent processing injected content runs `env`, obtains `DATABASE_URL` and `BETTER_AUTH_SECRET`, reaches the database (published on the host, M-08), reads `auth_sessions.token`, signs a cookie, and with the legacy JWT fallback (L-04) mints agent JWTs for any company.
- **Fix:** Extend the sanitizer with an explicit denylist (`BETTER_AUTH_SECRET`, `DATABASE_URL`, `DATABASE_MIGRATION_URL`, `SENTRY_DSN*`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and generically `*_TOKEN`/`*_SECRET` unless an adapter opts in) and route every adapter's `runtimeEnv` through it. Document that local adapters share the server's OS identity and recommend sandbox or remote execution targets for multi-user deployments. The denylist is low risk for agents, but adapters may legitimately rely on provider-specific `*_TOKEN` variables, so it was not applied without an inventory of those.

### M-06: Open self-registration is the default in `authenticated` mode

- **Severity:** Medium. Anyone who can reach a `public` instance can create an account. Such an account has no company membership but is a `board` actor for routes guarded only by `assertBoard`, receives full `/api/health` details, can call `POST /api/health/dev-server/restart`, and on a freshly provisioned `private` instance the first network user to sign up and call `POST /api/bootstrap/claim` becomes instance admin.
- **Location:** `server/src/config.ts:231-235` (`authDisableSignUp` defaults `false`); `server/src/auth/better-auth.ts:273-277`; `server/src/routes/health.ts:46-50,146-150,423-443`; `server/src/routes/access.ts:2756-2783`. `PAPERCLIP_AUTH_DISABLE_SIGN_UP` is not mentioned in `doc/`, `README.md`, the compose files, or the ECS template.
- **Fix:** Default `disableSignUp` to `true` when exposure is `public`, and automatically once an `instance_admin` exists (invites already cover onboarding). Gate full health details and `dev-server/restart` on company access or instance-admin rather than bare `board`. Document the variable in `doc/DOCKER.md`, both compose files, and the ECS template. The defaults are behavior-changing; the documentation change is not.

### M-07: AI-connection `routing.baseUrl` reaches an unguarded server-side fetch

- **Severity:** Medium. Any company member can point a `gateway` AI connection at an arbitrary `https://` host, including names resolving to private addresses, and the server POSTs chat completions to it with the user-supplied credential; `kind: "local"` deliberately allows `http://localhost:*`.
- **Location:** `packages/shared/src/ai-provider-routing.ts:8,53-70` (schema checks only credentials, query, hash, scheme); `server/src/services/fast-response-provider.ts:139-158` (`globalThis.fetch` with only `redirect: "error"`); `server/src/services/decision-model-provider.ts:47`; route authorization `server/src/routes/ai-connections.ts:291-300`.
- **Fix:** Pass a `fetch` built on `guardedRemoteHttpFetch` into the SDK provider factories, with `allowPrivateNetwork` only for `kind: "local"` or an operator allowlist; at minimum call `assertPublicRemoteHttpEndpoint` on create/update for `kind: "gateway"`. Behavior-changing for private gateways.

### M-08: Compose stack publishes Postgres on all interfaces with password `paperclip`

- **Severity:** Medium. The reference compose for the "server + PostgreSQL" deployment binds `5432` on every host interface with a fixed credential. Docker bypasses `ufw` on many hosts, so a VPS following `doc/DOCKER.md` exposes the whole database (encrypted secret material, session tokens, agent key hashes).
- **Location:** `docker/docker-compose.yml:2-16` (`POSTGRES_PASSWORD: paperclip`, `ports: - "5432:5432"`), `:38`.
- **Fix:** Remove the `ports:` block (the server reaches `db` over the compose network) or bind to loopback (`"127.0.0.1:5432:5432"`), and source the password from `${POSTGRES_PASSWORD:?...}` as `BETTER_AUTH_SECRET` already is. The quadlet variant already does this correctly. Not applied because operators who connect to Postgres from other hosts would see a change.

### M-09: No baseline security headers on the SPA and API

- **Severity:** Medium. The UI could be framed by any site (clickjacking of approve, pause, and budget actions; fully exploitable in `local_trusted` where no cookie is needed, mitigated by `SameSite=Lax` in authenticated mode), responses could be content-sniffed, and agent-authored remote images received the full instance URL as `Referer`.
- **Location:** `server/src/app.ts` had no global header middleware; headers were set only on specific routes (`public-mcp.ts:56-58`, `assets.ts:362-364`, `announcements.ts:33-44`, `file-transfers.ts:123-124`).
- **Fix applied:** New `server/src/middleware/security-headers.ts` mounted first in `createApp`, setting `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and `Referrer-Policy: strict-origin-when-cross-origin` on every response. Plugin UIs are framed same-origin and HTML artifacts use `srcdoc`, so neither is affected; routes that set stricter values override these. Every served asset already carries an explicit content type (`plugin-ui-static.ts:73-92` MIME map, `express.static`, the asset and attachment routes).
- **Not applied:** `Strict-Transport-Security` when exposure is `public` and the public URL is `https:` (depends on TLS termination), `Permissions-Policy` (voice features may need microphone), and a full `Content-Security-Policy`. A full CSP is behavior-changing: `ui/index.html` has two inline scripts, `ui/src/plugins/slots.tsx:446` imports plugin modules from `blob:` URLs, and mermaid and Tailwind inject inline styles. Start with `Content-Security-Policy-Report-Only`.

### M-10: Release publishes resolve dependencies at publish time

- **Severity:** Medium. Published npm artifacts (including the CLI-bundled `acpx` and `embedded-postgres`) are built from whatever semver resolution npm returns at publish time, not from the reviewed lockfile. A malicious upstream patch release reaches a public canary within hours with no human review; the same applies to nightly, beta, and stable.
- **Location:** `.github/workflows/release.yml:462,769,1058,1449,1514` (`pnpm install --no-frozen-lockfile` followed by `git checkout -- pnpm-lock.yaml`); caret ranges throughout `server/package.json`.
- **Fix:** Publish from the committed lockfile (`--frozen-lockfile`, failing closed, with the refresh PR as the unblock); pin `acpx` and `embedded-postgres` exactly; consider a minimum release age for freshly published upstream versions. Behavior-changing for the release process.

### M-11: `@latest` agent CLIs installed as root into shipped images

- **Severity:** Medium. The public production image, the five agent-runtime images (cosign-signed), and the untrusted-review image install `@anthropic-ai/claude-code`, `@openai/codex`, `opencode-ai`, `@google/gemini-cli`, `@moonshot-ai/kimi-code`, and `@mariozechner/pi-coding-agent` at `@latest` at build time; CI stamps an ISO week so the layer intentionally re-pulls weekly. `docker/agent-runtime/Dockerfile.base:31` runs `curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -` as root, unpinned and unverified, while `docker/Dockerfile.onboard-smoke:22` and `scripts/install.sh` already do the same step with GPG or SHA-256 verification.
- **Location:** `Dockerfile:174-181`; `docker/agent-runtime/Dockerfile.{claude,codex,gemini,opencode,pi}`; `docker/agent-runtime/Dockerfile.base:31`; `docker/untrusted-review/Dockerfile:21`.
- **Fix:** Pin exact versions (as `docker/daytona-runner/Dockerfile:67-70` already does) and let Dependabot bump them; replace the pipe-to-bash with the GPG-verified apt recipe. Behavior-changing (tools stop auto-updating).

### M-12: Any `v*` tag push republishes the public `:latest` image with no gate

- **Severity:** Medium. Any account with push rights can move `ghcr.io/paperclipai/paperclip:latest`, `:<semver>`, `:beta`, and `:nightly` by pushing a git tag, bypassing the `npm-stable` environment review that protects the npm side of the same release. Tag-protection rulesets cannot be verified from the repository.
- **Location:** `.github/workflows/docker.yml:3-15` (triggers), `:212-226,324-343` (tag mapping), `:280-292` (`merge-and-push` has `packages:write`, no `environment:`).
- **Fix:** Add a repository ruleset protecting `v*`, `beta/v*`, `nightly/v*`, `canary/v*` (bypass list including the Actions app, since `release.yml` pushes tags), and/or put the retag step behind `environment: docker-release` for tag refs. The ruleset is behavior-preserving; the environment gate adds an approval step.

### M-13: Known-vulnerable dependency versions in the lockfile

- **Severity:** Medium. `pnpm audit` reports 56 advisories: 1 critical, 21 high, 25 moderate, 9 low. Most are transitive and many are reachable only in dev tooling (`vitest`/`jsdom` undici 8, `supertest` form-data, storybook `brace-expansion`), but several sit on the request path of the server itself.
- **Reachable ones:** The server's Express 5.2.1 resolves `proxy-addr@2.0.7` (critical: IP spoofing via IPv4-mapped IPv6 trust subnet; reachable only when `TRUST_PROXY` lists subnets, which is off by default), `qs@6.15.0` (two DoS advisories), `body-parser@2.2.2` (limit bypass), `path-to-regexp@8.3.0` (ReDoS). `sharp@0.35.4` (high, librsvg CVE-2026-96889) processes uploaded images and SVG logos. `svix@1.76.1` pulls `uuid@10` (moderate). `pino-pretty` pulls `fast-copy@4.0.2` (moderate). The `cli` advisory is a false positive: it matches the workspace package name `cli` against the unrelated npm package `cli`.
- **Evidence:** `pnpm audit --json` on the committed lockfile (counts above). A simulation in a scratch worktree showed that `pnpm update --recursive --lockfile-only` with **no manifest changes** (all fixes are already inside the declared semver ranges, for example `express ^5.1.0` resolves to 5.3.0 with `proxy-addr ^2.0.8`, `qs ^6.16.0`, `body-parser ^2.3.0`, `router ^2.2.0` with `path-to-regexp` 8.4.x) reduces the audit to 4 advisories: 0 critical, 0 high, 3 moderate (`esbuild` 0.18 under `drizzle-kit`, `uuid@10` under `svix`, `postcss-selector-parser@6` under `@tailwindcss/typography`), 1 low (the `cli` false positive). The repository's own `pnpm install --resolution-only` refresh, which `refresh-lockfile.yml` runs, does **not** move these because existing resolutions still satisfy the ranges.
- **Fix:** Run `pnpm update --recursive --lockfile-only` through the repository's lockfile-owning process (`chore/refresh-lockfile` branch; PR CI rejects lockfile edits from other branches, `pr-trusted.yml:56-68`), then bump `svix` to 2.x and `@tailwindcss/typography` for the remaining moderates. Not applied on the assessment branch because the CI policy forbids lockfile changes in ordinary pull requests and the fix-bearing branch could not be installed with `--frozen-lockfile` otherwise.

### L-01: Instance-admin environment edits resolve another company's secrets from an unchecked `?companyId=`

- **Location:** `server/src/routes/environments.ts:524-545` (`resolveEnvironmentSecretContextCompanyId`), callers `:1133-1240` and `:1388-1410`. The sibling `resolveCustomImageCompanyId` (`:479-486`) asserts access on the query value; this one returns `routeCompanyId` without `assertCompanyAccess`.
- **Attack path:** Instance admin who is not a member of company B sends `PATCH /api/environments/:id?companyId=<B>` with secret references belonging to B; the bindings resolve under B. Secrets are not returned in plaintext but become usable by agents in that environment. The codebase otherwise deliberately denies instance admins non-member company access.
- **Fix:** `assertCompanyAccess(req, routeCompanyId)` (or `hasCompanyAccess` + 404) before returning. Changes behavior for instance admins, so described.

### L-02: Plugin webhook ingress persists unauthenticated payloads and headers before verification

- **Location:** `server/src/routes/plugins.ts:2692-2800` (`POST /api/plugins/:pluginId/webhooks/:endpointKey`), rows inserted at `:2745-2770` before `handleWebhook` verifies anything.
- **Impact:** Unauthenticated write amplification and retention of real providers' signature and authorization headers at rest. No privilege gain.
- **Fix:** Verify before persisting (worker-first or manifest-declared HMAC), redact `authorization`, `cookie`, and `x-*-signature*` headers, add per-plugin rate limiting. Behavior-changing for plugins that inspect rejected deliveries.

### L-03: Documented placeholder secrets are accepted in `authenticated` deployments

- **Location:** `.env.example:4-5` (`BETTER_AUTH_SECRET=paperclip-dev-secret`, `PAPERCLIP_TOOL_ACTION_SIGNING_SECRET=...change-me`); `server/src/auth/better-auth.ts:246-250` (error text recommends the placeholder); `cli/src/checks/deployment-auth-check.ts:27-38` (presence check only).
- **Fix:** Refuse the documented placeholders and secrets shorter than 32 bytes when `deploymentMode === "authenticated"` (hard-fail for `public`, warn for `private`) in `startup-refusals.ts` and the doctor check. Low risk, but it can refuse startup for an existing misconfigured deployment, so described.

### L-04: Legacy raw-secret agent-JWT fallback on by default

- **Location:** `server/src/agent-auth-jwt.ts:38` (agent key defaults to `BETTER_AUTH_SECRET`), `:218-226` (fallback accepts tokens signed with the raw secret for any `company_id` unless `PAPERCLIP_AGENT_JWT_DISABLE_LEGACY_FALLBACK=true`); `iss`/`aud`/`instance_id` optional.
- **Impact:** Widens any secret leak (M-05, L-03) to cross-company agent impersonation. Tokens have a 48-hour TTL, so no valid legacy token can still exist.
- **Fix:** Flip the default (`PAPERCLIP_AGENT_JWT_ENABLE_LEGACY_FALLBACK=true` to opt back in), require `iss`/`aud`/`instance_id`, and prefer a separate agent secret.

### L-05: `/api/openapi.json` served unauthenticated in `authenticated` mode

- **Location:** `server/src/routes/openapi.ts:12575-12581`; mounted in the `api` router whose only global gate is `boardMutationGuard` (safe methods pass with `actor.type === "none"`).
- **Fix:** `assertAuthenticated(req)` when `deploymentMode === "authenticated"`; verify the UI docs page fetches with a session.

### L-06: Public routine triggers have no rate limit; `signingMode: "none"` is URL-only

- **Location:** `server/src/routes/routines.ts:656-677` (no limiter); `server/src/services/routines.ts:3032-3034,3067-3079,3130-3146`.
- **Impact:** A leaked `none` or `bearer` trigger URL allows unlimited run dispatch until the budget hard-stop; only HMAC modes carry a replay key.
- **Fix:** Per-`publicId` limiter like the chat webhooks, a per-trigger dispatch cap, and deprecate `none` in the UI. Additive.

### L-07: Webhook and OAuth limiters key on `req.ip` while `TRUST_PROXY` is unset by default

- **Location:** `server/src/routes/chat-channels.ts:716-738`, `voice-sessions.ts:93-96`, `public-mcp.ts:24-38`; `app.ts:572-575`.
- **Impact:** Behind a proxy without `TRUST_PROXY`, every caller shares one bucket, so one abuser starves a chat endpoint's legitimate deliveries.
- **Fix:** Doctor/startup warning when exposure is `public` and `TRUST_PROXY` is unset; key provider-webhook buckets on `publicId` with a higher cap plus signature-failure penalties.

### L-08: Unvalidated `baseRef` reaches git argv positionally

- **Location:** `packages/shared/src/validators/issue.ts:173` (`baseRef: z.string()`, while `existingBranch` is validated at `:145-158`); sinks `server/src/services/workspace-runtime.ts:1038` (`rev-parse --verify`), `:1082` (`merge-base`), `:3696`, `:4051` (`worktree add -b <branch> <path> <baseRef>`).
- **Impact:** A value starting with `-` is parsed as a git option. No option on these subcommands yielding code execution or file write was identified; this is hardening.
- **Fix:** Validate `baseRef` with the `isValidExistingBranchName` rules and insert `--` before positional refs.

### L-09: Agent-settable `worktreeParentDir` accepts absolute and `~` paths

- **Location:** `packages/shared/src/validators/issue.ts:183`; `server/src/services/workspace-runtime.ts:801-806,3405-3410,3442`.
- **Impact:** An agent can make the server `mkdir -p` and `git worktree add` under any host directory writable by the server user (a constrained write, sub-directory named after the sanitized branch).
- **Fix:** Add `worktreeParentDir` to the agent-denied paths in `workspace-command-authz.ts`, or require it to resolve inside the repository root or `PAPERCLIP_HOME` for agent actors.

### L-10: `window.open` without `noopener` on markdown images

- **Location:** `ui/src/pages/IssueDetail.tsx:5926`. Every other `window.open` and `target="_blank"` in `ui/src` already carries `noopener`/`noreferrer`.
- **Attack path:** An agent embeds `![x](https://attacker.example/img.png)` in a comment; the operator clicks it; the opened page receives `window.opener` and can redirect the Paperclip tab to a look-alike login page.
- **Applied:** Yes: `window.open(src, "_blank", "noopener,noreferrer")`.

### L-11: Remote images in agent-authored markdown leak the full instance URL

- **Location:** `ui/src/components/MarkdownBody.tsx:1017-1032` (default `img` passthrough); no `<meta name="referrer">` in `ui/index.html`.
- **Applied (partial):** The global `Referrer-Policy: strict-origin-when-cross-origin` header (M-09) now limits the leak to the origin. Not applied: `referrerPolicy="no-referrer"` on the markdown `img` renderer, or click-to-load for remote images in agent-authored content.

### L-12: `text/html` attachments lack a `sandbox` CSP; hand-built `Content-Disposition`

- **Location:** `server/src/routes/issues.ts:19577-19600` (CSP only for SVG; `text/html` is always `attachment`, so this is defense in depth); `server/src/routes/assets.ts:370` and `server/src/routes/access.ts:3478` build `filename="..."` by stripping only `"`, so a CR/LF in `originalFilename` makes `setHeader` throw (500 for that asset).
- **Fix:** Add `Content-Security-Policy: sandbox; default-src 'none'` for every non-inline type in `issues.ts`; use `res.attachment(name)` in `assets.ts`/`access.ts`.

### L-13: Plugin UI bundles served unauthenticated with `Access-Control-Allow-Origin: *`

- **Location:** `server/src/routes/plugin-ui-static.ts:207-300` (company access checked only when `?companyId=` is supplied), `:489`.
- **Impact:** Any site can read installed plugin UI source and enumerate installed plugins by key.
- **Fix:** Require an authenticated actor for `/_plugins/*` in `authenticated` mode and drop the wildcard (the host loads these same-origin; the dev proxy is loopback-only).

### L-14: Mermaid SVG injected with `dangerouslySetInnerHTML`

- **Location:** `ui/src/components/MarkdownBody.tsx:728-767`. `securityLevel: "strict"` is correct and mermaid 12.1.0 sanitizes with DOMPurify, but mermaid has had repeated label-XSS CVEs and there is no CSP backstop.
- **Fix:** Run the returned SVG through DOMPurify (`USE_PROFILES: {svg, svgFilters}`, forbid `foreignObject`, `script`, `on*`, non-fragment `href`) before injection, or render mermaid inside the existing sandboxed preview iframe.

### L-15: Sandboxed HTML artifact can navigate itself to an external site

- **Location:** `ui/src/components/HtmlArtifactPreview.tsx:12` (`sandbox="allow-scripts"`). Documented and accepted in `doc/html-artifact-previews.md`; the opaque origin keeps cookies and DOM safe, but an artifact script can replace the preview with attacker content inside Paperclip's chrome.
- **Fix:** Count `load` events and unmount after the first navigation, or drop `allow-scripts` for artifacts from low-trust agents.

### L-16: `${{ inputs.stable_date }}` interpolated into `run:` in release jobs

- **Location:** `.github/workflows/release.yml:1456-1457` (`preview_stable`) and `:1545-1546` (`publish_stable`, environment `npm-stable`, `id-token: write`, `contents: write`). The `preflight_stable` job at `:1350` already passes the same input through `env:`.
- **Impact:** Only a dispatcher with write access can set the input, but it lets them run shell inside a publishing job in a way the environment reviewer never sees in a diff.
- **Fix:** Pass `STABLE_DATE: ${{ inputs.stable_date }}` via `env:` and validate `^[0-9]{4}-[0-9]{2}-[0-9]{2}$`. Low risk, but the release workflow cannot be exercised here, so described.

### L-17: Mutable action tags in privileged jobs

- **Location:** `.github/workflows/docker.yml:82,122,131,178,185,213,229,425`; `agent-runtime-images.yml:30-43`; `release.yml` publish jobs (`:402,448,453,728,755,760,1017,1044,1049,1157,1476,1503,1508,1641`); `refresh-lockfile.yml:23-32`; `storybook-visual.yml:47-57,68,99,108`; `release-smoke.yml:66-135,198`. Most other workflows are SHA-pinned.
- **Fix:** Pin to full SHAs with a version comment and enable "Require actions to be pinned to a full-length commit SHA". Not applied because the correct SHAs must be verified against the upstream repositories.

### L-18: `persist-credentials` left at default on privileged checkouts

- **Location:** `.github/workflows/commitperclip-review.yml:20-23` (`pull_request_target` with `pull-requests: write`, `checks: write`); `docker.yml:81-86,291-294`; `agent-runtime-images.yml:30`; `storybook-visual.yml:47`. None of these jobs push.
- **Applied (partial):** `persist-credentials: false` added to the `pull_request_target` checkout, which holds the highest-value token. The job's scripts use only the GitHub API through a short-lived app token and run no `git` commands. The remaining checkouts are described.

### L-19: Lockfile-edit policy exemption keyed only on a PR-controlled branch name

- **Location:** `.github/workflows/pr-trusted.yml:56-68` (`github.head_ref != 'chore/refresh-lockfile'`). `check-pr-lockfile.mjs:274-275` additionally requires `prAuthor === 'github-actions[bot]'`.
- **Fix:** Add `github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.user.login == 'github-actions[bot]'` to the exemption. Policy gate, not a security boundary (`pnpm-lock.yaml` is CODEOWNERS-protected).

### L-20: `agent-runtime-images.yml` dispatch can overwrite and re-sign any existing version tag

- **Location:** `.github/workflows/agent-runtime-images.yml:10-24,54-58` (free-text `version` input, no immutability check, cosign keyless signing of whatever was built).
- **Fix:** Refuse to push if the tag exists (`docker buildx imagetools inspect` precheck) or restrict dispatch versions to `dev-*`; consumers pin by digest and verify the cosign identity.

### L-21: `.dockerignore` does not exclude `.env*` or key files

- **Location:** `.dockerignore`; `Dockerfile:130` (`COPY . .`), `:191` (production stage copies the whole `/app`). `.gitignore:15,70,85` show these files are expected to exist locally.
- **Impact:** A local `docker build` on a machine with a root-level `.env` bakes it into an image layer. CI builds from a clean checkout are unaffected.
- **Applied:** Yes: `.env`, `.env.*`, `*.pem` excluded, with the committed `.env.example` and `.env.*.example` files kept in the context. `scripts/check-docker-deps-stage.mjs` passes.

### L-22: CLI-auth approval URL built from client `X-Forwarded-Host`

- **Location:** `server/src/routes/access.ts:148-162` (`requestBaseUrl` prefers `x-forwarded-host` and `x-forwarded-proto` regardless of `trust proxy`; used only when neither the runtime canonical origin nor `authPublicBaseUrl` is configured).
- **Impact:** On a deployment without a configured public URL, a client can influence the host in the approval link returned to it. Low because the link is returned to the same caller and `authenticated + public` requires an explicit public URL.
- **Fix:** Use `req.protocol`/`req.hostname` (which honor `TRUST_PROXY`) or the `requestHost()` helper now shared by the two guards.

### Informational findings (I-01 to I-12)

- **I-01 (applied):** `server/src/board-claim.ts:35-37,155` compared a 192-bit random token and 96-bit code with `!==`. Replaced with a length-checked `timingSafeEqual`, matching the rest of the codebase.
- **I-02 (applied):** `server/src/secrets/local-encrypted-provider.ts:220` created the GCM decipher without `authTagLength`, so Node accepted tags from 4 to 16 bytes. The provider always writes 16-byte tags; the decipher now pins `authTagLength: 16`. Verified by a direct round-trip: normal material decrypts, an 8-byte tag is rejected with "Invalid authentication tag length".
- **I-03:** `PATCH /api/auth/profile` (`server/src/app.ts:669`, handler `routes/auth.ts:65-100`) is mounted before `boardMutationGuard` (`:751`), so it skips the Origin check; mitigated by `SameSite=Lax` and JSON-only parsing. Mount it inside the `api` router.
- **I-04:** Anonymous `/api/health` (`server/src/routes/health.ts:395-427`) returns deployment mode, exposure, commit, bootstrap status, cloud slug, and hidden-setting names; full server info in `local_trusted`. Intentional per code comments; `bootstrap_pending` is what makes M-06's race observable.
- **I-05:** 10 MB JSON bodies are parsed before authentication on every non-webhook path (`server/src/app.ts:593-594`). Consider a small pre-auth limit with route-level large limits.
- **I-06:** The cloud-tenant trusted-header path (`server/src/middleware/auth.ts:619-790`) is a single shared secret that conveys any user and role; constant-time compared and inert when unset. Self-hosted deployments must never set `PAPERCLIP_CLOUD_TENANT_SERVER_TOKEN`.
- **I-07:** Plugin modules are `import()`ed into the host document (`ui/src/plugins/slots.tsx:427,446`) and framed same-origin without `sandbox` (`launchers.tsx:449-453`); server-side plugin code runs under `node:vm` (`server/src/services/plugin-runtime-sandbox.ts:156`), which is not a security boundary. Installing a plugin equals granting it the operator's session; state this in the install UI.
- **I-08:** `LIKE`/`ILIKE` patterns are parameterized but not wildcard-escaped (`server/src/routes/cases.ts:705-708`, `tool-gateway.ts:813-840`, `services/decision-training.ts:315-317`); `agent-commentary-reader.ts:43` already escapes correctly.
- **I-09:** `packages/shared/src/portability-zip.ts:294-308` builds `files` as a plain object; an entry named `__proto__` sets the local object's prototype. Use `Object.create(null)` or a `Map`.
- **I-10:** `local-encrypted-provider.ts:42-45` accepts any 32-character string as the master key (generated keys are always random); `better-auth.ts:170-184` reads `x-forwarded-proto` to pick the Secure-cookie instance regardless of `trust proxy` (affects only the caller's own cookie); `better-auth.ts:197-203` adds `http://` variants of every allowed hostname as trusted origins; `docker-compose.yml:44` defaults the tool-action signing secret to empty, which fails closed (`tool-content-guards.ts:62-68`).
- **I-11:** `refresh-lockfile.yml:40,55-98` auto-merges lockfile PRs with `GITHUB_TOKEN` (depends on branch protection requiring CODEOWNER review); `scripts/release-lib.sh:385-407` retries canary/nightly publishes with `--provenance=false`; `docker/ecs-task-definition.json:12` pins `:latest`.
- **I-12:** `server/src/auth/better-auth.ts:73-84` enables rate limiting for all `authenticated` deployments while `doc/DEPLOYMENT-MODES.md` says private is off by default (code is safer; fix the doc). `better-auth.ts:246-250` recommends `BETTER_AUTH_SECRET=paperclip-dev-secret` in an error message.

## 5. Applied fixes

All applied fixes are on branch `security/assessment-2026-10-20` in commit `1a20bc5a2`. Each is local, behavior-preserving for correctly configured deployments, and covered by a test or a direct verification.

| Finding | Files | Change | Verification |
|---|---|---|---|
| H-01 | `server/src/middleware/private-hostname-guard.ts`, `server/src/__tests__/private-hostname-guard.test.ts` | Honor `X-Forwarded-Host` only from a peer trusted by `trust proxy fn`, mirroring `board-mutation-guard.ts` | 2 new tests: untrusted forwarded host is rejected; trusted proxy forwarded host is honored. The 6 existing tests in the file and `app-private-hostname-gate.test.ts` pass |
| H-02 | `server/src/routes/routines.ts`, `server/src/__tests__/routines-routes.test.ts` | Apply `assertNoAgentHostWorkspaceCommandMutation` to `POST /routines/:id/run` | 2 new tests: agent with `provisionCommand` gets 403 and no run is dispatched; board user with the same body gets 202 with settings passed through. All 16 existing route tests pass |
| M-09 (partial) | `server/src/middleware/security-headers.ts` (new), `server/src/app.ts`, `server/src/__tests__/security-headers.test.ts` (new) | Global `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`; route-level stricter values still override | New unit test; static-UI, health, and wildcard-auth suites pass |
| L-10 | `ui/src/pages/IssueDetail.tsx` | `window.open(src, "_blank", "noopener,noreferrer")` | `IssueDetail.test.tsx` (157 tests) passes before and after |
| L-18 (partial) | `.github/workflows/commitperclip-review.yml` | `persist-credentials: false` on the `pull_request_target` checkout | The job's scripts contain no `git` invocation and use only the API |
| L-21 | `.dockerignore` | Exclude `.env`, `.env.*`, `*.pem`; keep `.env.example` and `.env.*.example` | `node scripts/check-docker-deps-stage.mjs` passes |
| I-01 | `server/src/board-claim.ts` | Length-checked `timingSafeEqual` for token and code | `board-claim.test.ts` passes |
| I-02 | `server/src/secrets/local-encrypted-provider.ts` | `createDecipheriv(..., { authTagLength: 16 })` | Direct round-trip through `localEncryptedProvider.createSecret`/`resolveVersion`: decrypts normally; 8-byte tag rejected |

## 6. Checks run and results

| Check | Command | Result |
|---|---|---|
| Dependency audit (before) | `pnpm audit --json` on the committed lockfile | 56 advisories: 1 critical, 21 high, 25 moderate, 9 low across 1,642 dependencies. Raw output kept in the session scratchpad |
| Dependency audit (simulated refresh) | `pnpm install --resolution-only --no-frozen-lockfile` in a scratch worktree, then `pnpm audit` | Unchanged (56): the CI refresh keeps existing resolutions |
| Dependency audit (simulated update) | `pnpm update --recursive --lockfile-only` in a scratch worktree, then `pnpm audit` | 4 advisories: 0 critical, 0 high, 3 moderate, 1 low (false positive on the workspace package `cli`). Not applied (see M-13) |
| Secret scan, working tree and full history | `gitleaks git` (v8.24.3) after `git fetch --unshallow`; 5,054 commits scanned, 176.9 MB | 163 matches, all classified: test fixtures (fake PEM blocks, the jwt.io example token, `wrong-...` bearer strings), hex digests in evidence JSON under `doc/plans`, a patch hash flagged as a Discord token, a UUID in `docs/deploy/secrets.md`. **No live credential.** The clone was shallow (50 commits) when the session started; it was unshallowed before the scan |
| Static analysis | `semgrep` 1.x with `p/security-audit`, `p/nodejs`, `p/typescript`, `p/javascript`, `p/secrets`, `p/github-actions`, `p/dockerfile` over `server/src`, `packages/*/src`, `cli/src`, `ui/src`, `.github`, Dockerfiles, `docker/`, `scripts/` (tests excluded) | 71 findings, 235 rules, 4,390 files: 48 mutable action tags (L-17), 8 `run:` interpolations (L-16; the rest are 40-hex SHAs), 7 `::add-mask::` patterns (reviewed; tokens are masked before use), 2 `missing USER` (the entrypoint drops to `node` via gosu), 1 `gcm-no-tag-length` (I-02, fixed), 2 `direct-response-write` and 1 `res.sendFile` (reviewed: escaped or realpath-contained), 1 Python `urllib` in an evals script |
| Repo lint-style checks (before and after) | `pnpm check:token-gates`, `pnpm check:module-boundaries`, `pnpm check:no-git-push`, `pnpm check:tokens`, `pnpm check:node-version`, `node scripts/check-docker-deps-stage.mjs` | All pass before and after. The repository has no ESLint/Biome configuration; these scripts are its lint gates |
| Targeted server suites (before) | `vitest run` on `private-hostname-guard`, `app-private-hostname-gate`, `board-mutation-guard`, `board-claim`, `routines-routes`, `workspace-command-authz`, `issue-workspace-command-authz`, `static-ui-cache`, `static-ui-compression`, `static-ui-idle`, `health`, `express5-auth-wildcard`, `redaction` | 114 passed, 1 skipped; `issue-workspace-command-authz` needed `--testTimeout=90000` for its cold import of the issues router (2 passed) and the `@paperclipai/plugin-sdk` build that `pnpm test:run` performs |
| Targeted server suites (after) | Same set plus the new `security-headers.test.ts`, `--testTimeout=90000` | 13 files passed, 1 skipped; 136 tests passed, 1 skipped |
| Secrets suites (after) | `secrets-service`, `agent-identity-master-key`, `secret-provider-registry`, `agent-instance-secrets` | 3 passed, 104 skipped (database-backed cases skip without embedded Postgres, see below) |
| UI suite (before and after) | `vitest run src/pages/IssueDetail.test.tsx` | 157 passed both times |
| Typecheck (after) | `pnpm --filter @paperclipai/server typecheck`, `pnpm --filter @paperclipai/ui typecheck` | Both pass (exit 0). The server step also runs `prepare:runner-vendor`, which compiles the Rust runner |
| Full Vitest suite (before) | `pnpm test:run` | **Not completed.** Stopped after 56 minutes at 119 of roughly 1,000 server suites (811 tests, 62 failed). Every failure was in a database-backed suite: embedded Postgres refuses to `initdb` as root in this container ("The files belonging to this database system will be owned by user postgres... must also own the server process"). Throughput was about two suites per minute, so a full run would take many hours |

## 7. Checks not performed and why

| Check | Status | Reason |
|---|---|---|
| Full Vitest suite to completion, before and after | Not performed | Runtime of many hours at the observed throughput; database-backed suites cannot start embedded Postgres as root in this container. Targeted suites covering every changed file were run before and after instead |
| Browser suites (`pnpm test:e2e`, `pnpm test:release-smoke`, storybook visual) | Not performed | Opt-in per `AGENTS.md`; no change touches them |
| `pnpm build` and `pnpm -r typecheck` across all packages | Not performed | The server and UI packages, which contain every changed TypeScript file, were typechecked and pass. The full workspace build and the typecheck of the other packages were out of proportion to the size of the applied changes |
| Dynamic testing against a running instance | Not performed | Out of scope by instruction; nothing was run against any deployed target |
| Verification of GitHub repository settings (tag protection rulesets, branch protection, environment reviewers, "pin actions to SHA" setting) | Not performed | Not visible from the repository contents; M-12, L-19, and I-11 depend on them |
| Verification of upstream action SHAs for pinning (L-17) | Not performed | Requires fetching each upstream repository's tags; left for the maintainers |
| Rust runner review (`packages/paperclip-runner/runner`) | Not performed in depth | Only the TypeScript surfaces that drive it were reviewed; secret scan and semgrep covered the files |
| Private dependencies, environment files, deploy targets | None needed | The repository builds from public registries; no `.env` is committed; no deploy target was in scope |

## 8. Prioritized remediation plan

### Now (this week)

1. **Merge the assessment branch** after review: H-01, H-02, M-09 headers, L-10, L-18, L-21, I-01, I-02.
2. **H-03 and M-07:** route `ghFetch` and the AI-connection provider `fetch` through `guardedRemoteHttpFetch`, with an operator allowlist for private GitHub Enterprise and gateway hosts.
3. **M-13:** run `pnpm update --recursive --lockfile-only` on the `chore/refresh-lockfile` branch, then bump `svix` and `@tailwindcss/typography`; this clears every critical and high advisory.
4. **M-08:** stop publishing Postgres from `docker/docker-compose.yml` and require `POSTGRES_PASSWORD`.
5. **M-06 (documentation part):** document `PAPERCLIP_AUTH_DISABLE_SIGN_UP` in `doc/DOCKER.md`, both compose files, and the ECS template.

### Next (this month)

6. **M-02 and M-03:** gate trust-widening permission edits by agents behind an approval, and default `requireBoardApprovalForNewAgents` to `true` for new companies.
7. **M-01 and L-01:** bound the requested role and grant keys by the actor's own rank; assert company access on the environment `?companyId=`.
8. **M-05:** extend `sanitizeInheritedPaperclipEnv` with a control-plane denylist and route every adapter's runtime environment through it.
9. **M-06 (defaults):** disable sign-up once an instance admin exists or when exposure is `public`; gate full health details on company access.
10. **L-03 and L-04:** refuse placeholder and short secrets in `authenticated` mode; flip the legacy agent-JWT fallback to opt-in.
11. **M-12, L-16, L-17, L-19, L-20:** tag-protection ruleset, `env:` indirection for `stable_date`, SHA-pin the remaining privileged jobs, tighten the lockfile exemption, refuse tag overwrites in `agent-runtime-images.yml`.

### Later (this quarter)

12. **M-04:** ship the `local_trusted` credential-required mode behind a flag and document the limitation.
13. **M-10 and M-11:** publish from the committed lockfile; pin the agent CLIs and the NodeSource bootstrap.
14. **M-09 (remainder):** HSTS for public HTTPS deployments, `Permissions-Policy`, and a report-only CSP leading to an enforced one.
15. **L-05 to L-09, L-11 to L-15, L-22, and the informational items** as hygiene work in the areas they touch.

## Appendix: Areas reviewed and found sound

- **Company scoping:** `assertCompanyAccess`/`getAccessibleResource` convention at about 300 call sites; sampled routes (issues, companies, secrets, instance settings, user profiles, resource memberships, access, agents, approvals, assets, file resources, execution workspaces, plugins, tool gateway) all scoped; 404-not-403 oracle guard.
- **Agent identity:** keys hashed, revocation and expiry checked, company mismatch rejected at auth time, keys without a responsible user refused, key scopes enforced centrally, per-company JWT keys, cancelled runs lose writes.
- **Cloud paths:** Ed25519 JWS bound to endpoint and method, one-time runtime-identity claim, self-hosted instances reject every assertion, constant-time tenant token with `instance_admin` rows purged per request.
- **Webhooks:** Slack HMAC with 300-second window and workspace pinning, GitHub HMAC with delivery dedupe, Discord Ed25519, Telegram secret token required, Teams JWT via the Microsoft SDK, AgentMail and voice Svix-style HMAC over raw bytes; all fail closed, 1 MB raw cap, per-endpoint limiters.
- **Public MCP:** PKCE S256 mandatory, exact redirect URI, 60-second single-use codes, 15-minute access tokens, rotating refresh tokens with replay revocation, single-company grants, SSRF-guarded client metadata, hashed file-transfer tickets bound to grant, company, target, and session.
- **Outbound HTTP:** `remote-http-endpoint-guard.ts` resolves once, denies loopback, RFC 1918, CGNAT, and link-local, normalizes IPv4-mapped IPv6, pins the socket, and uses manual redirects; used by remote MCP, event webhooks, HTTP adapters, plugin `ctx.http`, and GitHub attachments.
- **Files:** local-disk keys reject traversal; S3 keys are server-generated; workspace browse, search, and download use `realpath` containment with NUL checks; plugin UI static files are realpath-contained; zip import enforces per-entry and total decompression caps and never writes archive paths to disk; managed git clone uses `execFile` with `--`.
- **UI:** react-markdown without `rehype-raw` and with the default URL allowlist; HTML artifacts in `srcdoc` with `sandbox="allow-scripts"` and a restrictive CSP meta; uploaded SVGs DOMPurify-sanitized twice and served as attachments with a `sandbox` CSP; `text/html` attachments never inline; postMessage receivers check origin and interaction id; login `?next=` validated; service worker caches only hashed public assets; no secrets in web storage.
- **Secrets and crypto:** AES-256-GCM with random IV and 0600 key file; HS256-pinned JWTs with derived keys and `timingSafeEqual`; 192/256-bit random API keys; error handler never leaks stacks and redacts secret-sensitive routes; pino and body redaction; export strips secrets; telemetry sends only a random install id and enum dimensions; Sentry `sendDefaultPii: false`.
- **CI:** `commitperclip-review.yml` checks out `master` only and reads PR data as JSON through the API; `ci-profile.yml` never checks out PR code; `pr.yml` delegates to `pr-trusted.yml@master` with zero secrets and restore-only caches; self-hosted runners gated by numeric actor-ID allowlists; npm trusted publishing via OIDC with no `NPM_TOKEN`; image and migrator attestations; every remote download in build scripts is version-pinned and checksum-verified; no git or tarball dependencies in the lockfile; `postinstall` scripts perform no network I/O.
