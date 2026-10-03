# AIGate: AI Control Layer, HackYeah 2026 (Goldman Sachs task)

Project name: **AIGate**. Use the name in the README, dashboard header and slides. Maven coordinates `pl.aibron:aigate`, base package `pl.aibron.aigate`.

## Situation

We are building this at a hackathon. Submission deadline is Sunday 4 Oct 2026, 11:00 Warsaw time, so every hour counts. Prefer the simplest thing that works and is demonstrable over anything elegant but unfinished. The project must run end-to-end at all times: never leave `main` in a state where the gateway does not start or tests fail.

Everything user-facing (code, comments, README, dashboard, slides, commit messages) is in English, because the task requires an English submission.

## What we are building

A gateway that sits between AI clients (apps, agents) and local LLMs and governs every interaction. Clients point their OpenAI-compatible base URL at the gateway instead of at the model server; the gateway inspects requests, responses and tool calls, enforces a central policy, tracks budgets, and records an audit trail shown on a dashboard.

The task brief asks for:

- Two layers of checks: deterministic rule-based checks (PII, secrets, access control) and AI-based semantic checks.
- One central policy file: block/redact thresholds, allowed models, budgets, with different strictness levels.
- Budget and resource governance covering paid APIs and local models.
- Detection of known historical attacks from an external signature feed (for example unsafe deserialization payloads, model-repository supply-chain patterns).
- A dashboard for management and for security teams, with exportable audit logs.
- An automated test suite with positive and negative cases that judges can run themselves.
- An architecture diagram.

No paid AI services are provided, so everything runs on local models through Ollama. Do not add any dependency on OpenAI, Anthropic or other hosted APIs. A "commercial" model may appear in the policy only to demonstrate pricing and allowlist rules; it is never actually called.

Agent-to-MCP traffic is covered only through `tool_calls` inside chat completions. A separate MCP proxy is out of scope; say so in the README.

## How it is judged

| Criterion | Weight |
|---|---|
| Robustness of the solution and quality of guardrails | 30% |
| Architecture and performance efficiency | 20% |
| Security reporting | 20% |
| Completeness of the self-testing suite | 20% |
| Practical implementability and scalability | 10% |

Judges will run the test suite, type their own surprise prompts, edit the policy file live to see whether changes apply without a restart, review the architecture, dashboard and logs, and may ask for performance telemetry. A first evaluation phase is done from the submission alone, so the repository has to be runnable by a stranger from the README with one command.

Consequences for how we work:

- Every control ships together with its tests (at least one case that must pass through and one that must be stopped).
- Policy hot reload is a core feature, not a nice-to-have.
- Per-step latency is measured from the start, and the semantic check only runs when it is needed.

## Stack

- Java 21, Maven wrapper, Spring Boot 4.1.1, Apache Camel 4.22.1 through `org.apache.camel.springboot:camel-spring-boot-bom` and `camel-*-starter` artifacts. Virtual threads enabled.
  - These versions belong together: Camel 4.22.1's parent POM sets `spring-boot-version` 4.1.1 and Spring Framework 7.0.9. Do not mix in Spring Boot 3 examples from older docs.
  - Spring Boot 4 split several starters into smaller modules (tests in particular); check artifact names against the Spring Boot 4.1 docs.
  - The default `java` on the dev machine is 17; set `JAVA_HOME` to a 21 JDK before running `./mvnw`.
- Inbound: Camel REST DSL / `platform-http`.
- Outbound: `camel-http` to Ollama's OpenAI-compatible endpoint (`http://localhost:11434/v1/chat/completions` by default, configurable).
- Policy: YAML parsed with Jackson into Java records, held in an `AtomicReference`, reloaded by a `camel-file-watch` route watching the `policy/` directory.
- Audit store: H2 in file mode through `JdbcTemplate`, on a Docker volume.
- Telemetry: `camel-micrometer` and Spring Boot Actuator.
- Resilience: Camel circuit breaker (Resilience4j) around model calls.
- Dashboard: Thymeleaf + HTMX + Chart.js served by the same application. No separate frontend build.
- Tests: JUnit 6 (Jupiter 6.1.x) with `org.apache.camel:camel-test-spring-junit6`. There is no `camel-test-spring-junit*-starter` in the Spring Boot BOM; use the plain artifact. The upstream model is replaced by a stub so `./mvnw test` passes on a machine without Ollama.
- Run: Docker Compose for the gateway and the signature feed server, with Ollama on the host (`host.docker.internal`).

Check Camel component names, starter artifact IDs and endpoint options against the Camel 4 documentation instead of relying on memory; they changed between major versions.

Models (names configurable in `application.yml`; README lists the `ollama pull` commands):

- Main model for the demo: `llama3.2:3b`.
- Harmful-content guard: `llama-guard3:1b`. It classifies content into hazard categories S1-S14 and answers `safe` or `unsafe` plus a category. It does not detect prompt injection or jailbreaks.
- Injection judge: `granite3-guardian:2b` (Apache 2.0), asked whether the text is a prompt injection or jailbreak attempt. Answers yes/no.

Both guards are called through the OpenAI-compatible endpoint with `logprobs: true` and `top_logprobs`; Ollama returns them (verified on 0.34). The score is the probability of the first `unsafe` / `Yes` token, which is what the policy thresholds compare against.

## Architecture

Main route, in order:

1. **Authenticate**: resolve the client from the `Authorization: Bearer <key>` header by comparing its SHA-256 against `api_key_sha256` in the policy file. Unknown key: 401.
2. **Model allowlist**: the requested model must be allowed for this client.
3. **Budget**: reject when the client's token, cost or model-time budget for the current window is spent; trip a loop breaker when a client sends too many near-identical requests in a short window (normalised text, Jaccard similarity on word shingles).
4. **Rule checks on the request**: PII, secrets, attack signatures, tool definitions the client is not allowed to use. Hard signature hits give `BLOCK`. Soft signals (injection-like phrases, role-play markers, base64 or other encoded blobs, unusually long input) add to a risk score.
5. **Decision**: `ALLOW`, `REDACT` (mask findings and continue), `BLOCK`, or `UNSURE`. `UNSURE` means the risk score is between the profile's `unsure_above` and `block_above`.
6. **Semantic check** (only for `UNSURE`, or when the profile says always): ask both guard models in parallel; block when either score crosses the profile's threshold.
7. **Forward** to the upstream model inside a circuit breaker. Upstream is always called with `stream=false`. When the client asked for `stream=true`, return the already checked answer as a single SSE chunk followed by `data: [DONE]`, so streaming clients do not break.
8. **Rule checks on the response**: leaked PII or secrets, and `tool_calls` against the client's tool allowlist and argument deny patterns.
9. **Audit**: wire-tap an event to a separate route that writes to the database, so auditing never slows the response.

Supporting routes:

- Policy reload: on file change, parse and validate; on success swap the active policy and record an audit event; on failure keep the previous policy and surface the error on the dashboard. Watch the directory, not the file: editors that save by rename break single-file bind mounts in Docker.
- Signature feed: on a timer, fetch a JSON list of signatures from the URL in the policy, with a bundled file as fallback. Docker Compose serves `feed/signatures.json` from a small static server so the demo can add a signature live and show it being picked up.

Extension points (see `docs/ARCHITECTURE.md`, section 8). Keep these as interfaces from day one, even though the first build has one implementation each:

- `IdentityResolver`: header -> `CallerIdentity(clientId, subject, onBehalfOf, groups, authMethod)`. First implementation: API key. Target: corporate IdP via OIDC JWT.
- `AuditSink`: receives every `AuditEvent` from the wire-tap; sinks are independent and a failing sink never blocks the others or the response. First implementation: H2. Target: SIEM over syslog/CEF, Splunk HEC, Kafka.

A blocked request returns HTTP 403 with an OpenAI-style error body that includes the audit event ID and the reason category, never the sensitive content itself.

## Policy file

`policy/policy.yaml` is the single source of truth. Target shape (adjust field names if something reads better, but keep it one file):

```yaml
version: 1
profiles:
  strict:
    semantic_check: always           # always | on_unsure | never
    on_pii: block                    # allow | redact | block
    on_secret: block
    on_signature_match: block
    risk: { unsure_above: 0.2, block_above: 0.6 }
    guard_thresholds: { harmful: 0.5, injection: 0.5 }
  balanced:
    semantic_check: on_unsure
    on_pii: redact
    on_secret: block
    on_signature_match: block
    risk: { unsure_above: 0.3, block_above: 0.8 }
    guard_thresholds: { harmful: 0.7, injection: 0.7 }
  permissive:
    semantic_check: never
    on_pii: allow
    on_secret: redact
    on_signature_match: block
    risk: { unsure_above: 1.0, block_above: 1.0 }
models:
  - name: llama3.2:3b
    kind: local
    price_per_1k_input: 0.0002       # estimated compute cost
    price_per_1k_output: 0.0004
  - name: gpt-4o
    kind: commercial                 # never called; shows pricing and allowlist rules
    price_per_1k_input: 0.0025
    price_per_1k_output: 0.01
budgets:
  window: 1h
  max_tokens: 200000
  max_cost_usd: 5.00
  max_model_seconds: 600
  loop_breaker:
    max_similar_requests: 5
    within: 60s
    similarity: 0.9
signatures:
  feed_url: http://signature-feed/signatures.json
  refresh: 1m
clients:
  - id: demo-agent
    api_key_sha256: "<sha256 of the key>"
    profile: balanced
    models: [llama3.2:3b]
    tools:
      allowed: [search_docs, get_weather]
      deny_argument_patterns: ["(?i)drop\\s+table", "\\.\\./"]
    budgets:
      max_tokens: 50000
  - id: finance-app
    api_key_sha256: "<sha256 of the key>"
    profile: strict
    models: [llama3.2:3b, gpt-4o]
    budgets:
      max_cost_usd: 1.00
```

Demo keys are documented in the README; only their hashes live in the policy.

## Checks

Rule-based, each as its own small class with its own tests:

- PII: email, phone, payment card (Luhn), IBAN (mod 97), Polish PESEL (checksum), US SSN.
- Secrets: common API key and token formats, private key blocks, JWTs, high-entropy strings next to words such as `password` or `secret`.
- Attack signatures from the feed: unsafe deserialization payload markers, suspicious model-repository references, known prompt-injection phrases.
- Tool governance: tools offered in the request and tool calls in the response, checked against the client's allowlist and argument deny patterns.
- Output: system prompt leakage (canary token planted in the system prompt).

Checksums matter: validate them so that random digit strings are not reported as PII.

Semantic: one call per guard model with the text under review; parse verdict, category and score.

## Audit and reporting

Each audit event stores: ID, timestamp, client, model, direction (request/response), decision, category, matched rule, a masked excerpt, token counts, cost, and per-step latencies. Store masked content only; an audit log full of raw secrets would be its own vulnerability.

Map categories to the OWASP Top 10 for LLM Applications so the security view speaks a language the judges know.

Endpoints:

- `POST /v1/chat/completions`: the gateway.
- `GET /dashboard`: two views, one for management (cost, usage, budget consumption per client) and one for security (blocked and redacted events by category, recent events, policy reload history, per-step latency p50/p95).
- `GET /audit/export?format=jsonl|csv`: audit export.
- Actuator metrics for telemetry.

## Tests

`./mvnw test` must pass without Ollama (the first run still downloads Maven and dependencies). Provide a way to run the tests in a container too, for judges without JDK 21. Organise tests so the output reads like a checklist of guardrails: for each control, benign input passes, malicious input is stopped, and edge cases (invalid checksum, policy reload, exhausted budget, disallowed tool call) behave as specified. Add a small separate set of integration tests against real Ollama, skipped unless an environment flag is set.

## Milestones

Work through these in order and keep each one working before starting the next.

1. Project skeleton; pass-through route to Ollama; one test with a stubbed upstream; README with run instructions.
2. Policy file loading, validation and hot reload; client authentication; model allowlist.
3. Rule checks on requests (PII, secrets) with redact/block decisions; audit events to H2.
4. Response checks and tool governance.
5. Budgets and loop breaker.
6. Semantic check with the guard models.
7. Dashboard and audit export.
8. Signature feed.
9. Demo agent script, Docker Compose, architecture diagram (Mermaid in the README), telemetry notes.

## Working rules

- Commit small and often with clear messages.
- When something in this file is ambiguous, pick the simpler option, note the choice in the README, and move on.
- Keep a `THIRD_PARTY.md` listing open-source components, model licences (Llama 3.2 Community License, Apache 2.0 for Granite) and AI tools used.
- Do not add features outside this file without asking.
