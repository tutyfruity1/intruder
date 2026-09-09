# Local HTTP Lab

Local HTTP Lab is a safety-first HTTP Repeater and restricted Intruder for development and API debugging. It has a React/Vite/Tailwind UI and a Node/Express TypeScript API.

## Run locally

Requirements: Node.js 20+ and npm.

```bash
npm install
npm run dev
```

Open <http://localhost:3000>. The API listens on `127.0.0.1:3001`. For a production build use `npm run build && npm start`.

## Features

- Repeater for common HTTP methods, headers, request bodies, response headers and response bodies.
- Restricted Intruder with **sniper**, **battering ram**, **pitchfork**, and **cluster bomb** generation.
- Put `§markers§` or `{{markers}}` in URLs, headers, or bodies. Preview generated requests before execution.
- Intruder payload transformation chains: URL and Base64 (standard or URL-safe) encoding/decoding, HTML entities, JSON/Unicode escaping, hex encoding/decoding, case and whitespace changes, and prepend/append steps. The chain is applied to previewed and executed payloads in every mode; an empty chain keeps the original behavior.
- Pitchfork and Cluster Bomb accept separate dictionaries keyed by marker name (or position index), while the original shared dictionary remains supported.
- Repeater and interception editors include synchronized query-parameter and cookie editors. Changes update the URL and `Cookie` header without requiring raw request editing.
- Security Center exposes the effective target policy, local/private and external allowlists, request budgets, proxy limits, and the safety guarantees enforced by the server.
- Authorized Testing Mode is a separate, explicit project/session policy. Enable it in Security Center, add target rules (hostname, CIDR, `host:port`, or exact `http(s)://` URL), and enable only the address families, localhost/private/link-local/internal-DNS, redirect, and non-standard-port permissions required for the assessment. Every DNS answer and every redirect destination is checked again before connection; mixed or unexpected DNS answers are rejected.
- Request history, proxy traffic, and security settings persist in `data/history.json`, `data/traffic.json`, and `data/settings.json`.
- A restricted HTTP/HTTPS proxy listens on `127.0.0.1:3002` by default. The port can be changed in Settings or with `PROXY_PORT`.
- Optional interception pauses ordinary HTTP proxy requests before forwarding. The Traffic tab lists pending requests and permits safe method, URL, header, and body edits before Continue or Drop. Pending work is bounded by a configurable queue limit and timeout; completed, dropped, timed-out, and queue-rejected requests are clearly marked in traffic history.
- Hard limits: 1 MB request bodies, 5 MB response bodies, 60-second maximum timeout, 200 history entries, and a configurable (1–1000) Intruder request cap.
- Intruder accepts at most 20 transformation steps, 50 named dictionaries, 1000 values per dictionary, and 4096 characters per payload after transformation.

## Security model

This application is intentionally not an open proxy. Only `http` and `https` are accepted; URLs with embedded credentials, shell commands, redirects, and hop-by-hop headers are rejected or constrained. By default, requests must target localhost or private development ranges (loopback, RFC1918, link-local, and private IPv6). Hostnames are resolved immediately before each request and every resulting address must be private. Public IPs, multicast/broadcast, unspecified addresses, and DNS names resolving to them are blocked.

The **Allowlist** proxy mode is explicit opt-in. Settings has a separate External allowlist and `allowExternalHosts` is `false` by default. To authorize an external target, add its exact hostname or IP, enable external hosts, and keep the proxy in Allowlist mode. DNS answers are checked immediately before connecting; a hostname is rejected if any answer is private, special-use, or otherwise unsafe (including mixed DNS answers that could indicate rebinding). Embedded credentials are never accepted. Local/private defaults remain available independently of the external allowlist. Proxy request concurrency, requests-per-minute, outbound connection timeout, and CONNECT ports are bounded in Settings.

**Authorization warning:** only enable an external host after you have permission to send traffic to it. This is a development/security-testing tool, not a general-purpose internet proxy. Do not expose the API or proxy to untrusted networks.

Do not expose the API to untrusted networks. The Docker compose file is intended for local development and persists only the `data` directory.

## Policy modes

Safe Mode is the default and preserves the strict local/private policy. Authorized Testing Mode is stored with the current `data` directory (the project/session policy) and is never an implicit bypass: a request must match an explicit authorized target rule and the corresponding permission switches. Rules support hostnames, wildcard hostnames, IPv4/IPv6 literals, CIDR ranges, `host:port`, and exact HTTP(S) URLs. The Security Center shows the active permissions and the policy decision log is available at `/api/audit`.

## Recon workspace

The **Recon** tab provides bounded local recon jobs. Passive runs accept only explicitly supplied HTTP(S) URLs and optional metadata, redact obvious secrets, and persist findings locally. Active runs require Authorized Testing Mode plus an explicit request confirmation, reuse the common SSRF policy, are limited to 20 URLs, expose a queued/running/completed/cancelled lifecycle, and can be cancelled through the UI or `/api/recon/runs/:id/cancel`. Recon decisions are written to the same audit log; the feature is not an unrestricted scanner.

## Traffic proxy

The **Traffic** tab controls the local proxy and shows captured requests and responses separately from Repeater history. The API server starts the proxy automatically; it can also be stopped and restarted from the tab. Configure an HTTP client or browser manually to use an HTTP proxy at `127.0.0.1:3002` (or the configured port). For example, in Firefox set **Settings → Network Settings → Manual proxy configuration**, set HTTP Proxy to `127.0.0.1`, the port to the configured port, and enable “Use this proxy for HTTPS” if you want the browser to issue CONNECT. Chromium can be started with `--proxy-server=http://127.0.0.1:3002` for a test profile. Captured HTTP entries can be searched, deleted, or loaded into Repeater.

Interception is disabled by default. Enable it in Settings, then use the Traffic tab or these API resources: `/api/proxy/interception/status`, `/api/proxy/interception/pending`, `/api/proxy/interception/pending/:id` (GET/PUT), `/continue`, and `/drop`. Original and edited targets are validated against the same SSRF policy immediately before forwarding. Pending requests are not written to traffic storage until they are continued, dropped, timed out, or rejected by the queue limit.

HTTPS CONNECT is supported only as a blind TCP tunnel to an allowlisted host and configured port (443 by default). The proxy returns `200 Connection Established`, then forwards encrypted bytes without reading or modifying TLS. CONNECT is never sent to the interception queue and no certificates, MITM, decryption, request/response bodies, or plaintext HTTPS capture are produced. Traffic records show only CONNECT metadata, timestamps, target, connection status, and byte counters where available. Blocked CONNECT requests are recorded as blocked metadata. Ordinary HTTP absolute-form forwarding remains captured and uses the same SSRF policy as Repeater and Intruder.

## Docker

```bash
docker compose up --build
```

The development UI is available on <http://localhost:3000> and the API on <http://localhost:3001>. Build the frontend separately for static hosting (`npm run build`); Vite output is in `dist/client`.

## Validation

```bash
npm run typecheck
npm test
npm run build
```

## Full user manual

### 1. What Local HTTP Lab is

Local HTTP Lab is a local-first HTTP security-testing workbench for systems
that you own or are explicitly authorized to assess. It combines:

- **Repeater** for precise, one-request-at-a-time HTTP work.
- **Intruder** for bounded, reproducible request generation.
- **Traffic** for proxy history and optional interception.
- **Recon** for passive findings and explicitly authorized, bounded active
  profiles.
- **Security Center** for target permissions, budgets, audit decisions, and
  the current SSRF policy.
- **History** for replayable request/response records.

The application is deliberately not a general-purpose open proxy. Every
outbound path shares the same destination policy, including Repeater, Intruder,
Injection Lab, Recon, ordinary proxy forwarding, and interception forwarding.

### 2. Installation and first launch

#### Requirements

- Node.js 20 or newer.
- npm.
- A modern browser.
- Docker only if you want to run Juice Shop or another disposable local target.

#### Install and run

```bash
npm install
npm run dev
```

Open:

| Component | Default address |
|---|---|
| Web UI | `http://localhost:3000` |
| API | `http://127.0.0.1:3001` |
| HTTP proxy | `http://127.0.0.1:3002` |

For a production build:

```bash
npm run build
npm start
```

The application stores local state in `data/`. Treat this directory as
sensitive: it can contain request history, traffic records, audit decisions,
settings, and recon findings.

#### Run Juice Shop locally

```bash
docker compose up --build
```

Keep the target bound to localhost. Do not publish a vulnerable training
application to a LAN, VPN, cloud host, or public interface.

### 3. Security Center and policy configuration

Open **Security Center** before sending traffic. It displays the effective
policy, target rules, permission switches, limits, and recent decisions.

#### Safe Mode

Safe Mode is the default. It is intended for normal development and local
debugging:

- localhost and loopback are restricted to the configured local policy;
- private and link-local destinations are classified explicitly;
- public destinations are not implicitly trusted;
- redirects are constrained;
- credentials in URLs, ambiguous parsing, and unsafe address forms are
  rejected;
- request, response, timeout, concurrency, and rate limits remain active.

#### Authorized Testing Mode

Use Authorized Testing Mode only for a named project or session where you have
permission to test the target.

1. Open **Security Center**.
2. Select **Authorized Testing Mode**.
3. Add an explicit target rule.
4. Select only the address families and destination classes required.
5. Enable redirects or non-standard ports only when the assessment needs them.
6. Confirm the effective policy summary before sending traffic.

A request is allowed only when all required checks pass:

1. The URL is syntactically valid and uses HTTP or HTTPS.
2. Userinfo and ambiguous host/port parsing are rejected.
3. The destination matches an explicit project/session rule.
4. DNS is resolved immediately before connection.
5. Every resulting address satisfies the selected IPv4/IPv6, local/private,
   link-local, and internal-DNS permissions.
6. The port satisfies the standard or explicitly allowed non-standard-port
   policy.
7. Redirect destinations are parsed, resolved, and checked again.

This means that enabling Authorized Testing Mode is not a hidden bypass and
does not turn the application into an unrestricted outbound client.

#### Target rule formats

Rules can contain:

```text
127.0.0.1
127.0.0.1:8080
10.10.0.0/16
fd00::/8
internal.example.test
*.staging.example.test
http://127.0.0.1:8080
https://service.example.test/api/health
```

Prefer the narrowest rule that covers the test. Use an exact URL rule when a
single endpoint is enough; use CIDR only for an explicitly scoped network.

#### Audit decisions

Each allow or block decision records the mode, target, result, and reason.
Inspect the audit endpoint when diagnosing a policy result:

```text
GET http://127.0.0.1:3001/api/audit
```

Do not treat an allowed decision as proof that the target is safe; it only
means that the configured policy authorized the network destination.

### 4. Repeater workflow

Repeater is the primary tool for manual testing.

1. Open **Repeater**.
2. Select the HTTP method.
3. Enter a complete URL.
4. Add headers in the header editor.
5. Add a body when required by the endpoint.
6. Use the query editor for query parameters and the cookie editor for cookies.
7. Send the request.
8. Inspect status, timing, response headers, and response body.
9. Save or reload the request from **History**.

The raw request editor and structured query/cookie editors stay synchronized.
Use the structured editors when you want to avoid malformed separators or
accidentally duplicating a cookie.

Example safe local request:

```http
GET http://127.0.0.1:8080/api/Challenges
```

Use the response status and body as evidence, and use the audit record to
explain why the request was permitted.

#### Redirect behavior

Redirects are not followed blindly. In Authorized Testing Mode, each `Location`
value is treated as a new destination and is independently parsed, resolved,
matched, and audited. A redirect chain stops when any destination violates the
policy or the configured redirect budget.

### 5. Intruder workflow

Intruder generates bounded request variants. It supports:

- **Sniper**: one marker position at a time.
- **Battering ram**: one payload list across markers.
- **Pitchfork**: corresponding values from multiple dictionaries.
- **Cluster bomb**: the Cartesian product of dictionaries.

Markers:

```text
GET http://127.0.0.1:8080/rest/products/search?q=§apple§
```

or:

```text
GET http://127.0.0.1:8080/rest/products/search?q={{query}}
```

Recommended workflow:

1. Build and send one known-good Repeater request first.
2. Copy it to Intruder.
3. Add the smallest useful marker set.
4. Preview generated requests.
5. Set a request budget before execution.
6. Use response filters for status, body length, error, or timing changes.
7. Stop the run when the signal is found.
8. Export or save only the evidence needed for the assessment.

Intruder limits protect both the target and the workstation. Keep dictionaries
small, avoid unbounded Cartesian products, and never use a production target
for exploratory payload generation.

### 6. Injection Lab workflow

Injection Lab is for comparing input handling and response behavior in a
controlled request flow.

1. Start from a baseline request.
2. Record the normal response status, body shape, and timing.
3. Apply one input transformation at a time.
4. Compare the result with the baseline.
5. Keep the request count and payload size within the displayed budget.
6. Record the exact request and response in History.

Use harmless markers and parser-boundary probes for initial diagnosis. Do not
start with destructive statements, resource exhaustion, shell execution, or
payloads that modify unrelated records.

### 7. HTTP proxy and interception

Configure a browser or HTTP client to use:

```text
HTTP proxy: 127.0.0.1
Port: 3002
```

Chromium example:

```bash
chromium --proxy-server=http://127.0.0.1:3002 http://127.0.0.1:8080
```

The **Traffic** tab provides:

- request and response history;
- search and filtering;
- loading a request into Repeater;
- proxy start/stop controls;
- interception queue state;
- continue and drop actions.

Enable interception only when you need to pause and edit a request. For a
pending item:

1. Review the original method, URL, headers, and body.
2. Make the smallest required edit.
3. Continue or drop the request explicitly.
4. Confirm the resulting audit and traffic record.

HTTPS CONNECT is a blind tunnel. The application does not perform TLS MITM,
certificate injection, plaintext capture, or interception of encrypted HTTPS
requests. Only CONNECT metadata and connection outcome are recorded.

### 8. Recon workspace

Recon has two distinct modes.

#### Passive recon

Passive recon accepts explicitly supplied URLs and metadata. It can collect
headers, status, content type, technology hints, and other bounded findings.
Secrets are redacted before persistence.

1. Open **Recon**.
2. Create a passive run.
3. Add only in-scope HTTP(S) URLs.
4. Add optional scope metadata.
5. Start the run.
6. Review findings and evidence.

#### Active recon

Active recon requires both Authorized Testing Mode and explicit per-run
authorization. It is limited to a small URL set, reuses the common SSRF
policy, and supports cancellation.

Use active recon only after documenting:

- target ownership or authorization;
- allowed hosts and ports;
- request budget;
- time window;
- excluded paths and data classes.

### 9. History, persistence, and evidence

The default local files are:

```text
data/settings.json
data/history.json
data/traffic.json
data/audit.json
data/recon.json
```

Evidence should include:

- test name and scope;
- timestamp;
- exact request;
- relevant response excerpt;
- policy decision;
- operator note;
- cleanup or rollback result.

Redact cookies, authorization headers, tokens, passwords, API keys, and
personal data before sharing evidence.

### 10. Operational limits

The following limits are intentional:

| Resource | Default protection |
|---|---|
| Request body | 1 MB |
| Response body | 5 MB |
| Timeout | 60 seconds maximum |
| History | 200 entries |
| Intruder requests | Configurable, capped at 1000 |
| Recon URLs | 20 per run |
| Intruder transforms | 20 steps |
| Named dictionaries | 50 |
| Values per dictionary | 1000 |
| Payload length | 4096 characters |

Do not remove these limits to make a test “work.” Adjust them only for a
documented, authorized test and keep the smallest value that reproduces the
behavior.

### 11. Troubleshooting

#### The request is blocked

1. Open Security Center.
2. Read the latest audit decision.
3. Check the active mode.
4. Check the exact target rule, scheme, hostname, address family, and port.
5. Check whether DNS returned mixed or private/public answers.
6. Add a narrower explicit rule or change the documented permission; do not
   bypass the policy in code.

#### The proxy is not receiving traffic

1. Confirm the proxy is running in the Traffic tab.
2. Confirm the client uses `127.0.0.1:3002`.
3. Check whether the client is using an HTTPS CONNECT tunnel rather than
   ordinary HTTP forwarding.
4. Verify the target is in scope.
5. Inspect blocked proxy metadata in Traffic and Audit.

#### A response is marked incomplete

Some training applications advertise an incorrect `Content-Length` or close a
connection early. Local HTTP Lab records the partial body when it is safely
available and marks the transport condition in the response metadata. Treat
such evidence as partial, not as a complete document.

#### State from an earlier lab run is confusing

Stop the target, preserve any evidence needed, and recreate the disposable
target from its documented seed/reset procedure. Do not edit application
databases manually while evaluating a finding.

### 12. Developer workflow

Run the existing checks before and after changes:

```bash
npm run typecheck
npm test
npm run build
```

When changing security policy or request transport, add regression tests for:

- URL parsing and userinfo rejection;
- IPv4, IPv6, mapped IPv6, CIDR, and hostname matching;
- DNS resolution and mixed answers;
- redirects and redirect chains;
- standard and non-standard ports;
- Safe Mode and Authorized Testing Mode;
- audit allow/block reasons;
- shared behavior across Repeater, Intruder, proxy, interception, and Recon.

### 13. Responsible-use checklist

Before every active test, confirm:

- You own the target or have written authorization.
- The target is disposable or the test has an approved rollback.
- The exact hosts, ports, paths, and time window are documented.
- The policy mode and target rules are visible in Security Center.
- The request budget and timeout are bounded.
- Secrets and personal data will not be copied into reports.
- Destructive, DoS, RCE, and data-exfiltration tests are separately approved.

After the test:

- Stop active runs.
- Disable Authorized Testing Mode when it is no longer needed.
- Remove temporary target rules.
- Review audit and traffic history.
- Redact exported evidence.
- Stop or isolate the vulnerable training target.

## Juice Shop laboratory walkthrough

This section documents the controlled local run performed with Local HTTP Lab
against an OWASP Juice Shop instance at `http://127.0.0.1:8080`. The requests
were sent through the Repeater or the local interception proxy, not directly
from an unrestricted script. The lab reached **44 of 116 achievements**.

### Start the lab

1. Start Juice Shop on a local-only port:

   ```bash
   docker compose up --build
   ```

2. Start Local HTTP Lab:

   ```bash
   npm install
   npm run dev
   ```

3. Open `http://localhost:3000`, go to **Security Center**, select
   **Authorized Testing Mode**, and add an explicit target rule for
   `127.0.0.1:8080`.

4. Enable only the permissions needed for the local target:
   **localhost**, **loopback**, **IPv4**, and **non-standard ports**. Keep
   redirects disabled unless the individual test requires a redirect response.

5. In Repeater, use requests such as:

   ```text
   GET http://127.0.0.1:8080/api/Challenges
   ```

   Refreshing this endpoint shows the current solved count. The policy audit
   log explains every allow/block decision.

### Achievements confirmed through the lab

Each item below describes the workflow and the evidence used to confirm it.
Paths are relative to `http://127.0.0.1:8080`.

#### Public files and information disclosure

1. **Confidential Document**
   - Open the `/ftp` directory listing through Repeater.
   - Request the exposed `acquisitions.md` document.
   - Refresh `/api/Challenges` and verify `directoryListingChallenge` is solved.

2. **Easter Egg**
   - Request the exposed `eastere.gg` file through the `/ftp` file server using
     the lab's URL-encoding/repeater controls.
   - Confirm the response is handled by the public file route.
   - Verify `easterEggLevelOneChallenge`.

3. **Forgotten Developer Backup**
   - Use the `/ftp` listing to identify `package.json.bak`.
   - Request that backup through Repeater.
   - Verify `forgottenDevBackupChallenge`.

4. **Forgotten Sales Backup**
   - Request `coupons_2013.md.bak` from the `/ftp` file server.
   - Confirm the file route accepts the encoded legacy filename.
   - Verify `forgottenBackupChallenge`.

5. **Misplaced Signature File**
   - Request `suspicious_errors.yml` through the `/ftp` endpoint.
   - Use an encoded suffix where the file server expects a permitted document
     extension; do not upload or modify a file.
   - Verify `misplacedSignatureFileChallenge`.

6. **Poison Null Byte**
   - Reuse the encoded `/ftp` file-name request that reaches one of the
     legacy backup files.
   - Confirm the server strips the terminator before resolving the file.
   - Verify `nullByteChallenge`.

7. **Security Policy**
   - Request `/security.txt`.
   - Confirm the response is a security policy document.
   - Verify `securityPolicyChallenge`.

8. **Missing Encoding**
   - Request the version-specific encoded image path under
     `/assets/public/images/uploads/`.
   - Keep the request read-only and use the exact encoded filename exposed by
     the local Juice Shop version.
   - Verify `missingEncodingChallenge`.

9. **Extra Language**
   - Request `/assets/i18n/tlh_AA.json`.
   - Confirm the response is a language resource.
   - Verify `extraLanguageChallenge`.

10. **Access Log**
    - Browse `/support/logs` and request an `access.log` entry.
    - Keep the request read-only; do not alter or delete log files.
    - Verify `accessLogDisclosureChallenge`.

11. **Misplaced IaC Files**
    - Browse `/infrastructure`.
    - Request a read-only `Dockerfile`, `docker-compose.yml`, or Terraform
      file such as `/infrastructure/terraform/main.tf`.
    - Verify `misplacedIacFiles`.

12. **Retrieve Blueprint**
    - Inspect the product image metadata from the local product API/assets.
    - Request the exposed blueprint asset, which in this image was an STL
      product asset.
    - Verify `retrieveBlueprintChallenge`.

13. **Privacy Policy Inspection**
    - Request the hidden proof resource:
      `/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility`.
    - Confirm the image response.
    - Verify `privacyPolicyProofChallenge`.

14. **Nested Easter Egg**
    - Request:
      `/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg`.
    - Confirm the local HTML response.
    - Verify `easterEggLevelTwoChallenge`.

15. **Exposed Metrics**
    - Request the local metrics endpoint, `/metrics`.
    - Use a normal user agent and read the Prometheus response only.
    - Verify `exposedMetricsChallenge`.

16. **Premium Paywall**
    - Request the premium-content route:
      `/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us`.
    - Do not send payment or interact with an external cryptocurrency service.
    - Verify `premiumPaywallChallenge`.

#### Authentication and account handling

17. **Password Strength**
    - Submit the documented weak-password login for the local admin fixture.
    - Do not reuse this credential outside the disposable Juice Shop.
    - Verify `weakPasswordChallenge`.

18. **Exposed Credentials**
    - Use the seeded testing account documented by the Juice Shop fixture.
    - Submit the login through Repeater and inspect only the local response.
    - Verify `exposedCredentialsChallenge`.

19. **Login Admin**
    - Submit a bounded authentication test using the local login endpoint.
    - The successful result creates only a local session and basket.
    - Verify `loginAdminChallenge`.

20. **Login Jim**
    - Log in as the seeded Jim fixture using the local account data.
    - Capture the returned token in the Repeater response.
    - Verify `loginJimChallenge`.

21. **Login Bender**
    - Log in as the seeded Bender fixture.
    - Keep the resulting session local and temporary.
    - Verify `loginBenderChallenge`.

22. **Login Amy**
    - Log in as the seeded Amy fixture.
    - Confirm the response is a normal local authentication response.
    - Verify `loginAmyChallenge`.

23. **Login MC SafeSearch**
    - Log in as the seeded MC SafeSearch fixture.
    - Do not attempt password spraying against any other service.
    - Verify `loginRapperChallenge`.

24. **Login Support Team**
    - Log in as the seeded support fixture.
    - Use the credentials only from the local Juice Shop seed data.
    - Verify `loginSupportChallenge`.

25. **Empty User Registration**
    - Send an empty JSON registration body to `POST /api/Users`.
    - Confirm the server rejects or sanitizes the request without retaining a
      real account.
    - Verify `emptyUserRegistration`.

26. **Repetitive Registration**
    - Submit a disposable local registration where `passwordRepeat` differs
      from `password`.
    - Confirm the validation response and avoid creating a persistent user.
    - Verify `passwordRepeatChallenge`.

27. **Password Hash Leak**
    - Authenticate with a disposable local account.
    - Request `/rest/user/whoami?fields=password`.
    - Verify that the intentionally vulnerable fixture exposes a password field
      and that `passwordHashLeakChallenge` is marked solved.

28. **Email Leak**
    - Using the same local session, request
      `/rest/user/whoami?callback=callback`.
    - Confirm the JSONP response is returned.
    - Verify `emailLeakChallenge`.

29. **View Basket**
    - Authenticate as a seeded local user.
    - Request another numeric basket ID with `GET /rest/basket/:id`.
    - Read the response only; do not update or checkout the basket.
    - Verify `basketAccessChallenge`.

30. **Bjoern's Favorite Pet**
    - Use the local reset-password endpoint with the seeded Bjoern security
      answer and a temporary replacement password.
    - Restore the original fixture password after verification.
    - Verify `resetPasswordBjoernOwaspChallenge`.

31. **Reset Jim's Password**
    - Submit the seeded Jim security answer to `/rest/user/reset-password`.
    - Restore Jim's original password immediately after the challenge is
      registered.
    - Verify `resetPasswordJimChallenge`.

32. **Reset Bender's Password**
    - Submit the seeded Bender security answer.
    - Restore the original Bender password after confirmation.
    - Verify `resetPasswordBenderChallenge`.

33. **Reset Bjoern's Password**
    - Submit the seeded Bjoern security answer.
    - Restore the original Bjoern password after confirmation.
    - Verify `resetPasswordBjoernChallenge`.

34. **Reset Morty's Password**
    - Submit the seeded Morty security answer.
    - Restore the original Morty password after confirmation.
    - Verify `resetPasswordMortyChallenge`.

35. **Reset Uvogin's Password**
    - Submit the seeded Uvogin security answer.
    - Restore the original Uvogin password after confirmation.
    - Verify `resetPasswordUvoginChallenge`.

#### Web3, redirects, and policy behavior

36. **Blockchain Hype**
    - Request the local asset `/assets/public/images/products/56px.png`.
    - Keep redirect following disabled in Repeater.
    - Verify `tokenSaleChallenge`.

37. **Web3 Sandbox**
    - Request `/assets/public/images/products/11px.png`.
    - Confirm the image response is returned locally.
    - Verify `web3SandboxChallenge`.

38. **Admin Section**
    - Request `/assets/public/images/products/19px.png`.
    - Confirm the request is allowed by the explicit local target rule.
    - Verify `adminSectionChallenge`.

39. **Score Board**
    - Request `/assets/public/images/products/1px.png`.
    - Confirm the response through Repeater or the browser configured to use the
      Local HTTP Lab proxy.
    - Verify `scoreBoardChallenge`.

40. **Privacy Policy**
    - Request `/assets/public/images/products/81px.png`.
    - Confirm the response through the proxy.
    - Verify `privacyPolicyChallenge`.

41. **Outdated Allowlist**
    - Request `/redirect?to=` with one of the challenge's documented
      cryptocurrency destination values.
    - Do not follow the external redirect; inspect the `Location` response
      locally.
    - Verify `redirectCryptoCurrencyChallenge`.

#### Controlled injection and authorization checks

42. **User Credentials**
    - Use `GET /rest/products/search` with a bounded, read-only UNION query
      that returns the Users columns in the product response shape.
    - Limit the request to one short payload and inspect only the response.
    - Verify that the response contains the seeded user records and
      `unionSqlInjectionChallenge` is solved.

43. **Database Schema**
    - Use the same search endpoint with a bounded read-only UNION query against
      SQLite's schema metadata.
    - Do not issue writes, deletes, sleep functions, or table modifications.
    - Verify `dbSchemaChallenge`.

44. **Error Handling**
    - Send a harmless malformed request that produces a normal application
      error response.
    - Confirm the error is recorded by Repeater and that no server process is
      interrupted.
    - Verify `errorHandlingChallenge`.

### Safety boundaries

The remaining Juice Shop achievements include intentionally destructive or
high-risk behaviors: RCE and DoS payloads, XXE file disclosure/XXE DoS,
YAML memory bombs, arbitrary file writes, wallet depletion, supply-chain
payloads, active XSS, forged JWTs, SSRF/SSTI, and data-destroying workflows.
They are not executed by this walkthrough. A production-grade framework should
represent them as explicit, reviewable plans with dry-run mode, payload
classification, per-request confirmation, disposable-target checks, time and
memory budgets, and automatic rollback where possible.

For every completed test, use the **Challenges** endpoint to verify the result,
the **History** tab to retain the request/response pair, and the **Audit** view
to confirm why Local HTTP Lab allowed the destination. This keeps the
achievement run reproducible and demonstrates that Repeater, proxy, and
future Intruder/Recon workflows all share one transparent SSRF policy.
