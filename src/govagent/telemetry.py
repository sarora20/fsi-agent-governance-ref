"""OpenTelemetry tracing for every hop: console -> harness -> model -> IdP -> gateway checks -> backend.

Span names follow the OpenTelemetry GenAI semantic conventions (open-telemetry/semantic-conventions-genai,
status "development" in Sept 2026): `invoke_agent {agent}`, `chat {model}`, `execute_tool {tool}`, with
`gen_ai.provider.name`, `gen_ai.agent.name`, `gen_ai.tool.name`, `gen_ai.usage.*`. Gateway spans use a
`govagent.*` namespace. Context crosses process boundaries in the W3C `traceparent` header.

Two sinks:
  TraceStore   in memory, per process, for the built-in trace view (always on)
  OTLP/HTTP    to Jaeger or any collector when OTEL_EXPORTER_OTLP_ENDPOINT is set

Tracing never changes a decision: if OpenTelemetry is missing, every call here is a no-op.
"""

from __future__ import annotations

import os
import threading
from collections import OrderedDict
from contextlib import contextmanager
from typing import Any, Iterator

try:
    from opentelemetry import context as otel_context
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor, SpanExporter, SpanExportResult
    from opentelemetry.trace import SpanKind, Status, StatusCode
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

    AVAILABLE = True
except ImportError:  # pragma: no cover - tracing is optional
    AVAILABLE = False

_PROPAGATOR = TraceContextTextMapPropagator() if AVAILABLE else None
_LOCK = threading.Lock()
_STORE: "TraceStore | None" = None
_SERVICE = "govagent"


class TraceStore(SpanExporter if AVAILABLE else object):  # type: ignore[misc]
    """Keeps the most recent traces in memory, as plain dicts, for the dashboard."""

    def __init__(self, max_traces: int = 400):
        self.max_traces = max_traces
        self._traces: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
        self._lock = threading.Lock()

    def export(self, spans):  # noqa: D401 - SpanExporter API
        with self._lock:
            for s in spans:
                tid = format(s.context.trace_id, "032x")
                self._traces.setdefault(tid, []).append(span_to_dict(s))
                self._traces.move_to_end(tid)
            while len(self._traces) > self.max_traces:
                self._traces.popitem(last=False)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    def get(self, trace_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._traces.get(trace_id, []))

    def clear(self) -> None:
        with self._lock:
            self._traces.clear()


def span_to_dict(s: "ReadableSpan") -> dict[str, Any]:
    parent = format(s.parent.span_id, "016x") if s.parent else None
    status = s.status.status_code.name if s.status else "UNSET"
    return {
        "trace_id": format(s.context.trace_id, "032x"), "span_id": format(s.context.span_id, "016x"),
        "parent_id": parent, "name": s.name, "kind": s.kind.name, "start_ns": s.start_time, "end_ns": s.end_time,
        "status": status, "status_message": s.status.description if s.status else None,
        "attributes": {k: (list(v) if isinstance(v, tuple) else v) for k, v in (s.attributes or {}).items()},
        "events": [{"name": e.name, "attributes": dict(e.attributes or {})} for e in s.events],
        "service": (s.resource.attributes.get("service.name") if s.resource else None) or _SERVICE,
        "scope": s.instrumentation_scope.name if s.instrumentation_scope else "",
    }


def setup(service_name: str, otlp_endpoint: str | None = None) -> "TraceStore | None":
    """Configure tracing for this process (idempotent). Returns the in-memory store."""
    global _STORE, _SERVICE
    if not AVAILABLE:
        return None
    with _LOCK:
        if _STORE is not None:
            return _STORE
        _SERVICE = service_name
        provider = TracerProvider(resource=Resource.create({"service.name": service_name,
                                                            "service.namespace": "govagent"}))
        _STORE = TraceStore()
        provider.add_span_processor(SimpleSpanProcessor(_STORE))
        endpoint = otlp_endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        if endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

                provider.add_span_processor(BatchSpanProcessor(
                    OTLPSpanExporter(endpoint=endpoint.rstrip("/") + "/v1/traces")))
            except ImportError:
                pass
        trace.set_tracer_provider(provider)
        return _STORE


def store() -> "TraceStore | None":
    return _STORE or setup(_SERVICE)


def tracer(name: str):
    if not AVAILABLE:
        return _NoopTracer()
    store()
    return trace.get_tracer(name)


def current_traceparent() -> str | None:
    if not AVAILABLE:
        return None
    carrier: dict[str, str] = {}
    _PROPAGATOR.inject(carrier)
    return carrier.get("traceparent")


def current_trace_id() -> str | None:
    if not AVAILABLE:
        return None
    ctx = trace.get_current_span().get_span_context()
    return format(ctx.trace_id, "032x") if ctx.is_valid else None


def inject_headers(headers: dict[str, str] | None = None) -> dict[str, str]:
    headers = dict(headers or {})
    tp = current_traceparent()
    if tp:
        headers["traceparent"] = tp
    return headers


@contextmanager
def continue_trace(traceparent: str | None) -> Iterator[None]:
    """Make `traceparent` (from an incoming request) the parent of spans started inside."""
    if not AVAILABLE or not traceparent:
        yield
        return
    token = otel_context.attach(_PROPAGATOR.extract({"traceparent": traceparent}))
    try:
        yield
    finally:
        otel_context.detach(token)


@contextmanager
def span(tracer_name: str, name: str, kind: str = "INTERNAL", *, new_trace: bool = False,
         **attributes: Any) -> Iterator[Any]:
    """Start a span; attributes with None values are dropped. Yields the span (or a no-op).

    new_trace=True starts its own trace instead of joining whatever span is current. Use it for
    a span that must be a root even when something else already opened one — a web framework's
    own request span, say, which would otherwise make two runs in one request share a trace.
    """
    if not AVAILABLE:
        yield _NoopSpan()
        return
    t = tracer(tracer_name)
    with t.start_as_current_span(name, context=otel_context.Context() if new_trace else None,
                                 kind=getattr(SpanKind, kind),
                                 attributes={k: v for k, v in attributes.items() if v is not None}) as s:
        yield s


def set_attrs(s: Any, **attributes: Any) -> None:
    for k, v in attributes.items():
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            v = [str(x) for x in v]
        s.set_attribute(k, v)


def mark_error(s: Any, message: str) -> None:
    if AVAILABLE and hasattr(s, "set_status"):
        s.set_status(Status(StatusCode.ERROR, message[:200]))


def record_span(tracer_name: str, name: str, start_ns: int, end_ns: int, error: str | None = None,
                **attributes: Any) -> None:
    """A child span with explicit timing (used for gateway checks measured as they run)."""
    if not AVAILABLE:
        return
    s = tracer(tracer_name).start_span(name, start_time=start_ns,
                                       attributes={k: v for k, v in attributes.items() if v is not None})
    if error:
        s.set_status(Status(StatusCode.ERROR, error[:200]))
    s.end(end_time=end_ns)


class _NoopSpan:
    def set_attribute(self, *a: Any, **k: Any) -> None: ...
    def add_event(self, *a: Any, **k: Any) -> None: ...
    def set_status(self, *a: Any, **k: Any) -> None: ...


class _NoopTracer:
    @contextmanager
    def start_as_current_span(self, *a: Any, **k: Any) -> Iterator[_NoopSpan]:
        yield _NoopSpan()
