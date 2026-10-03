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

Then call it like the OpenAI API:

```bash
curl -s localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"llama3.2:3b","messages":[{"role":"user","content":"Name the capital of Poland in one word."}]}'
```

| Setting | Default | Environment variable |
|---|---|---|
| Upstream model endpoint | `http://localhost:11434/v1/chat/completions` | `AIGATE_UPSTREAM_URI` |
| Gateway port | `8080` | `SERVER_PORT` |

Metrics: `GET /actuator/metrics`, `GET /actuator/health`.

## Scope notes

- Upstream errors (unknown model, Ollama down) are passed through with their original status code.
