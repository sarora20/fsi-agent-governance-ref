.PHONY: install test live-demo demo eval eval-adk eval-remote serve evidence live-claude

install:
	pip install -e ".[dev,adk,service]"

test:
	pytest

live-demo:
	./scripts/run-demo.sh

demo:
	govagent demo --audit reports/demo-audit.jsonl

eval:
	govagent eval --adapter scripted

eval-adk:
	govagent eval --adapter adk-scripted

eval-remote:
	govagent eval --adapter scripted-remote

serve:
	govagent serve --state govagent-state.db

evidence: eval
	govagent evidence --audit reports/audit-scripted.jsonl --report reports/eval-scripted.json

live-claude:
	govagent eval --adapter claude --judge --out reports
