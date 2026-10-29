# Sending captures to your observability stack

Every capture carries flat `attributes` that use OpenTelemetry's names where a convention exists (`gen_ai.conversation.id`, `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.operation.name`, `url.full`, `server.address`, `event.name`). The attack fields sit under `firstwatch.*`, because OpenTelemetry has no attributes for attacks yet. The full mapping is in [SPEC.md](../SPEC.md#telemetry-attributes).

## Export one capture

```bash
firstwatch export otlp security-captures/<folder>/capture.json
```

prints one OTLP/JSON log record, with `eventName` `firstwatch.capture`, severity `WARN` for a stop and `INFO` for a note, the summary as the body, and every attribute. POST it to any collector's `/v1/logs`:

```bash
firstwatch export otlp capture.json |
  curl -X POST http://localhost:4318/v1/logs -H 'Content-Type: application/json' --data-binary @-
```

[examples/opentelemetry/](../examples/opentelemetry/) has a minimal collector config and a script that sends every capture.

From code: `to_otlp(rec)` in Python, `toOtlp(rec)` in Node.

## Joining captures to your traces

If your agent already emits OpenTelemetry GenAI spans, pass the same session ID to `watch(…, session_id=…)`. The capture's `gen_ai.conversation.id` then matches the spans, and your backend can show the attack beside the run that met it.

## Status

The export follows the OTLP/JSON encoding (`resourceLogs` → `scopeLogs` → `logRecords`, with `timeUnixNano` as a string and attribute values as `AnyValue`). As of 0.1.0 it's checked against that encoding in tests, but it hasn't yet been sent to a live collector in CI. If your backend rejects a record, please [open an issue](https://github.com/dave8172/firstwatch/issues/new?template=bug.yml).
