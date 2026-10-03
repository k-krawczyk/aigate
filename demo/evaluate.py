"""Replays the request-side cases of testdata/test-cases.json against a running AIGate with real models and
prints the confusion against the expected decisions. Answer-side and tool-call cases need a scripted model and
are covered by ThreatCorpusTest instead.

    python demo/evaluate.py [--gateway http://localhost:8080]
"""

import argparse
import json
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

CORPUS = Path(__file__).resolve().parent.parent / "testdata" / "test-cases.json"
SKIP_GROUPS = {"budget"}


def call(gateway, key, model, text):
    body = json.dumps({"model": model, "max_tokens": 20, "messages": [{"role": "user", "content": text}]}).encode()
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    request = urllib.request.Request(f"{gateway}/v1/chat/completions", body, headers)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.status, response.headers.get("X-AIGate-Request-Id")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()).get("error", {}).get("audit_id")


def audited(gateway, ids):
    with urllib.request.urlopen(f"{gateway}/audit/export?format=jsonl&hours=1") as response:
        rows = [json.loads(line) for line in response.read().decode().splitlines() if line.strip()]
    return {row["id"]: row for row in rows if row["id"] in ids}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway", default="http://localhost:8080")
    args = parser.parse_args()

    cases = [c for c in json.loads(CORPUS.read_text())["cases"]
             if c["group"] not in SKIP_GROUPS and c["direction"] == "request" and "tools_offered" not in c]
    sent = []
    for c in cases:
        key, model = "aigate-demo-agent-key", "llama3.2:3b"
        if c["id"] == "access-01":
            key = None
        elif c["id"] == "access-02":
            key = "not-a-real-key"
        elif c["id"] == "access-03":
            model = "gpt-4o"
        started = time.perf_counter()
        status, audit_id = call(args.gateway, key, model, c["text"])
        sent.append((c, status, audit_id, time.perf_counter() - started))

    time.sleep(1)
    rows = audited(args.gateway, {s[2] for s in sent})
    confusion = Counter()
    misses = []
    answer_side = []
    for c, status, audit_id, seconds in sent:
        row = rows.get(audit_id, {})
        got = row.get("decision", "?")
        if row.get("direction") == "response":
            # The request passed; the model's own answer was then masked or blocked. Scored as the request decision.
            answer_side.append(f"  {c['id']:<22} {got} on the answer ({row.get('rules')})")
            got = "ALLOW"
        confusion[(c["expected"], got)] += 1
        if got != c["expected"]:
            misses.append(f"  {c['id']:<22} expected {c['expected']:<6} got {got:<6} {c['text'][:70]}")

    correct = sum(n for (e, g), n in confusion.items() if e == g)
    print(f"{correct}/{len(sent)} request-side cases decided as expected\n")
    print("expected -> got")
    for (e, g), n in sorted(confusion.items()):
        print(f"  {e:<6} -> {g:<6} {n}")
    if answer_side:
        print("\nrequest allowed, answer then checked")
        print("\n".join(answer_side))
    if misses:
        print("\nmisses")
        print("\n".join(misses))


if __name__ == "__main__":
    main()
