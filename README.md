# haarf-relay

Logs in one side, regulator-grade evidence out the other — without touching the agent's code.

haarf-relay is a plug-and-play log enrichment processor that converts raw AI-agent logs into
HAARF-tagged, PHI-scrubbed, SIEM-ready compliance telemetry. It sits inside an organization's
*existing* log-forwarding pipeline and requires zero changes to the agent application it
observes. It is the evidence leg of the
[Task Force for AI Agents in Healthcare](https://github.com/Task-force-for-AI-agents-in-Healthcare)
stack: [HAARF](https://github.com/Task-force-for-AI-agents-in-Healthcare/haarf) defines the
rules, [QFIRE](https://github.com/Task-force-for-AI-agents-in-Healthcare/qfire) enforces them at
runtime, and haarf-relay proves — continuously, from production logs — that they were followed.

**Status: M1 (skeleton).** Working today: `stdin → parse(haarf_audit) → stdout` JSONL with the
flat dotted-key wire format (`gen_ai.*` / `hc_agent.*`). See `haarf-relay-design.md` in the
parent workspace for the full design and roadmap (redaction, enrichment, metrics, Splunk/OTLP
outputs).

## Try it

```sh
go build ./cmd/haarf-relay
export HAARF_RELAY_SALT=$(openssl rand -hex 16)   # per-deployment patient-hash salt
./haarf-relay < testdata/haarf_audit/rt1.jsonl
```

Each HAARF harness audit entry becomes one flat JSON event:

```json
{"event.id":"01J...","event.timestamp":"2026-02-26T23:45:46.718362808Z","gen_ai.operation.name":"execute_tool","gen_ai.request.model":"gemini-2.5-flash","gen_ai.tool.name":"order_imaging","hc_agent.haarf.condition":"baseline","hc_agent.haarf.scenario_id":"RT-1","hc_agent.haarf.trial_id":"RT-1_baseline_0","hc_agent.patient.context_hash":"9f2c...","hc_agent.phi.redaction_count":0,"hc_agent.policy.decision":"allow","hc_agent.relay.schema_version":"hc_agent/0.1","hc_agent.relay.source_format":"haarf_audit","hc_agent.relay.version":"0.1.0-dev","hc_agent.tool.args_hash":"d55677b9e3366c4c"}
```

Notes on M1 behavior (all deliberate, all revisited in M2 when the redaction stage lands):

- `patient_id` is HMAC-SHA256-pseudonymized when `HAARF_RELAY_SALT` is set, and **dropped**
  when it isn't — a raw or unsalted patient reference never passes through.
- `tool_args` and `denial_reason` free text are dropped entirely (they can carry clinical
  content); the enforcement layer is preserved as `hc_agent.policy.layer`, derived from the
  `denial_reason` prefix (`RBAC:` → `rbac`, `CONTRAINDICATION:` → `contraindication`,
  `INJECTION:` → `injection`, `CIRCUIT_BREAKER:` → `circuit_breaker`).

## Develop

```sh
make verify      # gofmt + vet + build + race tests
make fixtures    # regenerate testdata from a HAARF checkout (HAARF_DIR=../haarf)
make golden      # rewrite golden outputs after an intentional wire-format change
```

All test data is synthetic, generated from HAARF's committed trial corpus by
`testdata/gen` — fixtures are never hand-edited (enforced in CI).

## License

Apache-2.0. HAARF requirement text is consumed as data under CC BY-SA 4.0.
