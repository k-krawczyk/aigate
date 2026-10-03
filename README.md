# AIGate

AI control layer for HackYeah 2026. AIGate is an OpenAI-compatible gateway: point any client's base URL at it and every chat completion, tool definition and tool call is checked against one policy file, charged to a budget and recorded in an audit trail.

Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Requirements

- JDK 21 (`java -version` must say 21; on macOS `export JAVA_HOME=$(/usr/libexec/java_home -v 21)`)
- [Ollama](https://ollama.com) running on the host, for the live gateway only. Tests do not need it.

```bash
ollama pull llama3.2:3b
ollama pull llama-guard3:1b
ollama pull granite3-guardian:2b
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

Metrics: `GET /actuator/metrics`, `GET /actuator/health`.

## Scope notes

- Upstream errors (unknown model, Ollama down) are passed through with their original status code.
