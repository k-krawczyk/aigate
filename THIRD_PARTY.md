# Third-party components and AI tools

## Runtime and build

| Component | Version | Licence | Use |
|---|---|---|---|
| Spring Boot | 4.1.1 | Apache 2.0 | Application framework, Actuator, JDBC, Thymeleaf integration |
| Apache Camel (Spring Boot starters) | 4.22.1 | Apache 2.0 | Routing: platform-http, http, file-watch, timer, Resilience4j circuit breaker |
| Resilience4j | 2.4.0 (via Camel) | Apache 2.0 | Circuit breaker around model calls |
| Jackson (databind, YAML) | 2.21 | Apache 2.0 | JSON and policy YAML parsing |
| H2 Database | managed by Spring Boot | MPL 2.0 / EPL 1.0 | Audit store |
| Micrometer, Prometheus registry | managed by Spring Boot | Apache 2.0 | Metrics |
| Thymeleaf | managed by Spring Boot | Apache 2.0 | Dashboard templates |
| htmx | 2.0.4 (vendored) | Zero-Clause BSD | Dashboard live refresh |
| Chart.js | 4.4.7 (vendored) | MIT | Dashboard charts |
| JUnit, AssertJ, Spring Test | managed by Spring Boot | EPL 2.0, Apache 2.0 | Test suite |
| Eclipse Temurin | 21 | GPLv2 with Classpath Exception | Container base images |
| nginx | 1.27-alpine | BSD-2-Clause | Serves the signature feed in Compose |
| Python | 3.12-alpine image | PSF License | Syslog receiver standing in for a SIEM in Compose |
| OpenAI Python SDK | >= 1.40 | Apache 2.0 | Demo agent client (talks only to AIGate) |
| Ollama | 0.34 | MIT | Local model server (not bundled) |

## Models (pulled by the user, not bundled)

| Model | Licence | Use |
|---|---|---|
| `llama3.2:3b` | Llama 3.2 Community License | Main model in the demo |
| `llama-guard3:1b` | Llama 3.2 Community License | Harmful content guard |
| `granite4:3b` | Apache 2.0 | Prompt injection judge |

## Data

The signature feed references public CVEs and research (JFrog, Invariant Labs, vendor advisories); patterns are our own. Example API keys and PII in tests are documented test values or fabricated (for example the AWS documentation key `AKIAIOSFODNN7EXAMPLE` and the Visa test number `4111 1111 1111 1111`).

## AI tools

The code and documentation were written with the help of Claude Code (Anthropic). Design decisions, review and testing were done by the team.
