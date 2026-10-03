# AIGate

AI control layer for HackYeah 2026. AIGate is an OpenAI-compatible gateway: point any client's base URL at it and every chat completion, tool definition and tool call is checked against one policy file, charged to a budget and recorded in an audit trail.

Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Requirements

- JDK 21 (`java -version` must say 21; on macOS `export JAVA_HOME=$(/usr/libexec/java_home -v 21)`)
- [Ollama](https://ollama.com) running on the host, for the live gateway only. Tests do not need it.

```bash
ollama pull llama3.2:3b
ollama pull llama-guard3:1b
ollama pull granite4:3b
```

## Run the tests

```bash
./mvnw test
```

The upstream model is replaced by a stub, so the suite runs without Ollama. The first run downloads Maven and dependencies.

## Run the gateway

```bash
./mvnw spring-boot:run
```

Then call it like the OpenAI API, with one of the demo keys:

```bash
curl -s localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer aigate-demo-agent-key' \
  -d '{"model":"llama3.2:3b","messages":[{"role":"user","content":"Name the capital of Poland in one word."}]}'
```

Demo clients defined in `policy/policy.yaml` (the policy stores only SHA-256 hashes of these keys):

| API key | Client | Profile | Models |
|---|---|---|---|
| `aigate-demo-agent-key` | `demo-agent` | balanced | llama3.2:3b |
| `aigate-finance-app-key` | `finance-app` | strict | llama3.2:3b, gpt-4o (never called) |
| `aigate-sandbox-key` | `sandbox` | permissive | llama3.2:3b, granite4:3b |

## Policy

`policy/policy.yaml` is the single source of truth: profiles (strictness levels), models with prices, budgets, signature feed and clients. Every key is documented in the file.

Edit it while the gateway runs. A valid change applies to the next request, typically within a second or two. An invalid change is rejected as a whole and the previous policy stays active; misspelled keys count as invalid.

| Setting | Default | Environment variable |
|---|---|---|
| Upstream model endpoint | `http://localhost:11434/v1/chat/completions` | `AIGATE_UPSTREAM_URI` |
| Gateway port | `8080` | `SERVER_PORT` |
| Policy directory | `policy` | `AIGATE_POLICY_DIR` |

## Attack signature feed

Known exploits against AI infrastructure (pickle and PyYAML deserialization, `torch.load`, `trust_remote_code`, known malicious Hugging Face repos, Probllama, ShadowRay, Langflow RCE, Log4Shell, reverse shells, MCP tool poisoning, known jailbreaks) are matched against prompts, answers, tool descriptions and tool-call arguments. Each signature carries its CVE or source.

The gateway starts from the copy bundled in the jar and then follows `signatures.feed_url` from the policy. To play the external feed locally:

```bash
python3 -m http.server 8090 -d feed
```

Edit `feed/signatures.json` (bump `version`) and the gateway applies it within the policy's `refresh` interval. An invalid or unreachable feed keeps the current set.

## Dashboard and audit

- `http://localhost:8080/dashboard`: live view, refreshed every 3 seconds. Requests in the last hour by decision, tokens, cost, policy revision and reload errors, and the latest events with category, OWASP id, matched rules and masked excerpt.
- `GET /audit/export?format=jsonl` or `?format=csv`, optional `&hours=24`: audit export for security teams.
- `GET /actuator/metrics`, `GET /actuator/health`: telemetry.

The audit store is H2 in `./data/` (`AIGATE_DB_URL` to change it). It only ever contains masked text.

## Scope notes

- Upstream errors (unknown model, Ollama down) are passed through with their original status code.
