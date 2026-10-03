# AIGate

AIGate is an AI control layer: an OpenAI-compatible gateway that sits between AI clients (apps, agents) and models. A client changes one setting, its base URL, and from then on every prompt, answer, tool definition and tool call is checked against one policy file, charged to a budget and written to an audit trail. Everything runs locally on Ollama; no hosted AI service is involved.

Built for HackYeah 2026, task "AI Control Layer".

## Quick start

Requirements: Docker, and [Ollama](https://ollama.com) running on the host.

```bash
ollama pull llama3.2:3b        # main model for the demo
ollama pull llama-guard3:1b    # guard: harmful content
ollama pull granite4:3b        # guard: prompt injection judge
docker compose up --build
```

Open http://localhost:8080/dashboard and use the Playground tab, or call the API with a demo key:

```bash
curl -s localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer aigate-demo-agent-key' \
  -d '{"model":"llama3.2:3b","messages":[{"role":"user","content":"Customer 44051401359 asks about a mortgage"}]}'
```

The model receives `Customer [PESEL] asks about a mortgage`. Send the same request with `aigate-finance-app-key` and it is blocked.

Without Docker: JDK 21 and `./mvnw spring-boot:run` (on macOS `export JAVA_HOME=$(/usr/libexec/java_home -v 21)` first).

| API key | Client | Profile | Models |
|---|---|---|---|
| `aigate-demo-agent-key` | `demo-agent` | balanced | llama3.2:3b |
| `aigate-finance-app-key` | `finance-app` | strict | llama3.2:3b, gpt-4o (priced, never called) |
| `aigate-sandbox-key` | `sandbox` | permissive | llama3.2:3b, granite4:3b |

The policy stores only SHA-256 hashes of these keys.

## Test suite

```bash
./mvnw test                                   # JDK 21, no Ollama needed
docker compose --profile test run --rm tests  # no JDK needed either
```

221 tests, all with a stubbed model and stubbed guards, so they run offline in about 15 seconds once dependencies are downloaded. Test names read as a checklist (`blocked: strict profile refuses a request containing a PESEL`, `allowed: ordinary multi-turn chat with growing history does not trip the loop breaker`). Every control has at least one case that must pass and one that must be stopped.

| Suite | What it proves |
|---|---|
| `PiiDetectorsTest`, `SecretDetectorsTest` | Detectors and checksums (PESEL, IBAN/NRB mod 97, Luhn), and what must not be flagged |
| `RequestContentPolicyTest`, `ResponseInspectionTest` | Allow / redact / block per profile, in both directions; system prompt leakage |
| `ToolGovernanceTest` | Tool allowlist, argument deny patterns, replayed tool calls |
| `RiskScorerTest`, `SemanticCheckTest` | Injection risk score; guards called only when needed; fail-closed |
| `KnownAttackSignaturesTest`, `SignatureFeedTest` | Historical exploits; live feed update over HTTP, invalid feed and feed outage |
| `BudgetGovernanceTest` | Token and cost budgets, loop breaker |
| `PolicyLoaderTest`, `PolicyHotReloadTest` | Validation, hot reload, editor-style saves, broken edits keep the old policy |
| `AuthenticationTest`, `ModelAllowlistTest` | API keys, model allowlist |
| `OidcAuthenticationTest` | IdP tokens against a local JWKS: valid, expired, wrong audience or issuer, foreign key, `alg: none`, HMAC confusion, unknown agent; groups tighten but never loosen |
| `AuditTrailTest`, `DashboardAndExportTest` | Audit content (masked), dashboard, export, Prometheus metrics |
| `CefFormatterTest`, `SiemForwardingTest`, `KafkaSinkTest` | CEF format and escaping; real UDP, TCP, HTTP receivers and an embedded Kafka broker get masked events; a dead SIEM or broker does not slow clients |
| `ThreatCorpusTest` | The team's red-team corpus in `testdata/test-cases.json`, replayed end to end |
| `LiveOllamaTest` | Same gateway with the real models; skipped unless `AIGATE_LIVE=true` (`AIGATE_LIVE=true ./mvnw test -Dtest=LiveOllamaTest`) |

GitHub Actions runs the suite on every push.

### Live evaluation with real models

`python3 demo/evaluate.py` replays the request-side cases of the team corpus against a running gateway with the real guard models and prints the confusion table. Latest run (demo-agent, balanced profile): 49 of 49 decided as expected, including the five semantic cases where only the guard models can tell a harmful request ("move client funds so compliance will not spot it") from a legitimate one ("what controls help compliance detect unusual fund movements"). Answer-side and tool-call cases need a scripted model and run in `ThreatCorpusTest`: 54 of 54.

## Architecture

```mermaid
flowchart LR
    C[Agent or app<br/>OpenAI SDK] -- base URL --> G
    subgraph G[AIGate]
        direction TB
        A[auth + model allowlist] --> B[budget + loop breaker] --> R[rules: PII, secrets,<br/>signatures, tools, risk score]
        R -- grey zone only --> S[guards in parallel]
        R --> F[forward, circuit breaker]
        S --> F
        F --> O[response rules] --> W[(audit wire-tap)]
    end
    F --> M[Ollama: llama3.2:3b]
    S --> GM[Ollama: llama-guard3:1b<br/>+ granite4:3b judge]
    P[/policy/policy.yaml/] -- hot reload --> G
    SF[signature feed] -- pull --> G
    W --> D[dashboard, export,<br/>Prometheus]
```

Details, decision model and extension points (corporate IdP, SIEM): [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

Java 21, Spring Boot 4.1.1, Apache Camel 4.22.1, H2, Micrometer, Resilience4j, Thymeleaf + htmx + Chart.js.

## Controls

| Control | Layer | OWASP LLM Top 10 (2025) |
|---|---|---|
| API key per client or OIDC access token from the corporate IdP; model allowlist | rules | access control |
| PII: PESEL, IBAN and Polish NRB, payment card, email, phone, US SSN; checksums validated | rules | LLM02 |
| Secrets: cloud and vendor tokens, private keys, JWT, credentials in URLs, high-entropy passwords; base64-encoded variants | rules | LLM02 |
| Prompt injection: risk score from EN and PL indicators, then a guard model for the grey zone | rules + semantic | LLM01 |
| Harmful content: Llama Guard 3 hazard categories S1-S14 | semantic | - |
| Known exploits on AI infrastructure from an external feed (17 signatures with CVE or source) | rules | LLM03, LLM05, LLM01 |
| Tool allowlist, argument deny patterns, poisoned tool descriptions | rules | LLM06, LLM05 |
| PII and secrets in answers and tool-call arguments (silent masking or block) | rules | LLM02 |
| System prompt leakage: canary token and verbatim overlap | rules | LLM07 |
| Token, cost and model-time budgets; loop breaker; circuit breaker | rules | LLM10 |

Not covered, on purpose: LLM04 data and model poisoning, LLM08 vector stores (no RAG in scope), LLM09 misinformation, and access control for agents' persistent or shared memory stores (the gateway sees what goes to the model, not what an agent reads from its own memory).

## Policy

[`policy/policy.yaml`](policy/policy.yaml) is the single source of truth; every key is documented in the file.

- **Profiles** are the strictness levels. `strict` blocks PII and checks every request with the guard models; `balanced` masks PII and asks the guards only when the rule risk score is in the grey zone; `permissive` lets PII through and never calls the guards. Each profile also sets risk and guard thresholds and whether a guard outage blocks or allows.
- **Models** carry a price per 1000 tokens. Local models get an estimated compute price, so one budget covers local and commercial use.
- **Budgets** per window: tokens, USD, model seconds, loop breaker. Clients override single fields.
- **Clients**: key hash, profile, models, tool allowlist and argument deny patterns.
- **Identity**: optional corporate IdP (OIDC). Access tokens are validated against the provider's JWKS (signature, `iss`, `aud`, `exp`; asymmetric algorithms only). `azp` selects the policy client, the user claim is recorded as the person the agent acts for, and IdP groups can tighten the client's profile but never loosen it. Works with Entra ID, Keycloak, Okta; API keys keep working alongside.
- **Audit sinks**: SIEM forwarding, see below.

Edit the file while the gateway runs. A valid change applies within about a second, also through the Docker bind mount. An invalid change (including a misspelled key) is rejected as a whole, the previous policy stays active, and the dashboard shows the errors. Every valid policy is also saved as a last-known-good copy in the data directory; if the file is broken when the gateway starts, it runs that copy, reports the errors and records a `policy_reload REJECTED` audit event, instead of refusing to start.

## Attack signature feed

Known exploits against AI infrastructure: pickle, PyYAML and Java deserialization, `torch.load`, `trust_remote_code`, known malicious Hugging Face repositories, Probllama (CVE-2024-37032), ShadowRay (CVE-2023-48022), Langflow RCE (CVE-2025-3248), Log4Shell, reverse shells, MCP tool poisoning and known jailbreaks. They are matched against prompts, answers, tool descriptions and tool-call arguments.

The gateway starts from the copy bundled in the jar and follows `signatures.feed_url` from the policy; Compose serves `feed/` with nginx on port 8090. Edit `feed/signatures.json`, bump `version`, and the change is live within the policy's `refresh` interval (30 s). An unreachable or invalid feed keeps the current set. Without Docker: `python3 -m http.server 8090 -d feed`.

## Dashboard, audit, telemetry

- **Security view** (`/dashboard/security`): threats by category with OWASP id, per-step latency p50/p95, top rules, policy reloads and feed updates, filterable event log with masked excerpts, decisions over time.
- **Management view** (`/dashboard/management`): budget consumption per client against policy limits, usage and cost by client and model, tokens over time.
- **Playground** (`/dashboard/playground`): send a prompt through the public endpoint with any demo key and see the decision, matched rules and step timings.
- **Export**: `GET /audit/export?format=jsonl` or `?format=csv`, optional `&hours=24`. The audit store only ever holds masked text.
- **SIEM forwarding**: the `audit.sinks` section of the policy sends every event (requests, policy reloads, feed updates) to a SIEM as RFC 5424 syslog with an ArcSight CEF payload over UDP or TCP, or as JSON, to Splunk HEC (token from an environment variable), or onto a Kafka topic keyed by client (bounded producer, optional SASL with the password from the environment). JSON sinks emit flat fields or, with `format: ecs`, Elastic Common Schema. Sinks are Camel endpoints, hot-reloaded with the policy; a SIEM that is down never delays a client. Compose includes a receiver standing in for the SIEM: `docker compose logs -f siem`.
- **Metrics**: `GET /actuator/prometheus`, including `aigate_step_latency_seconds{step=...}`, `aigate_request_latency_seconds`, `aigate_requests_total{decision,category,client}`, `aigate_tokens_total`, `aigate_cost_usd_total`.

Measured on an M2 Max with the models warm:

| Path | Added by AIGate |
|---|---|
| Rules only (auth, budget, PII, secrets, signatures, risk score) | about 1 ms; p95 of each rule step below 1.5 ms |
| Grey zone or strict profile: both guards in parallel | about 100 ms |
| Model call itself, for comparison | 500 ms to several seconds |

The guard models are pinged every 4 minutes so Ollama keeps them loaded; a cold load would cost seconds.

## Demo agent

```bash
pip install -r demo/requirements.txt
python demo/agent.py --demo        # scripted path: masking, injection, rogue tool, path traversal, indirect injection
python demo/agent.py --loop 7      # a stuck agent; the loop breaker stops it
python demo/agent.py "What is the weather in Krakow?"
```

The agent uses the official OpenAI SDK; the only AIGate-specific line is `base_url`.

## Configuration

| Setting | Default | Environment variable |
|---|---|---|
| Model endpoint | `http://localhost:11434/v1/chat/completions` | `AIGATE_UPSTREAM_URI` |
| Guard endpoint | same Ollama | `AIGATE_GUARDS_URI` |
| Guard models | `llama-guard3:1b`, `granite4:3b` | `AIGATE_GUARD_HARM_MODEL`, `AIGATE_GUARD_INJECTION_MODEL` |
| Policy directory | `policy` | `AIGATE_POLICY_DIR` |
| Signature feed URL | from the policy | `AIGATE_SIGNATURES_FEED_URL` |
| Audit database | `./data/aigate` (H2) | `AIGATE_DB_URL` |
| Syslog host for SIEM sinks | from the policy | `AIGATE_SIEM_SYSLOG_HOST` |

## Scope and known limits

- Streaming: the gateway needs the whole answer to check it, so a `stream=true` client gets the checked answer as one SSE chunk.
- Budgets and the loop breaker are in memory, per instance. Several instances need a shared store such as Redis.
- Agent-to-MCP traffic is governed through tool definitions and tool calls in chat completions; there is no separate MCP proxy.
- The guard models are small local models. The injection judge misses some role-play jailbreaks; known ones are covered by feed signatures. Granite Guardian 3 (2B) was evaluated and dropped because it scored ordinary requests as jailbreaks.

Open-source components and AI tools used: [THIRD_PARTY.md](THIRD_PARTY.md).
