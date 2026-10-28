// Package telemetry is the bridge's traces (mountain plan/15 §7): pushed over OTLP/HTTP when configured, nothing at
// all otherwise. A Tracing with no endpoint adds no interceptor and wraps no handler, so a bridge without one serves
// exactly what it served before. Its shape is mountain/pkg/telemetry's, which the bridge does not import (plan/15 §3).
//
// Everything that decides a span is passed explicitly (the provider, the propagator, no meter: otelconnect's own
// metrics are off and otelhttp's go to a no-op meter, so no series is added): no OTel global is set.
//
// Spans: one server span per BridgeService call (otelconnect, named by procedure; a stream's lasts as long as the
// stream) and per webhook route (named by its pattern). The bridge is public, so a caller's traceparent starts a new
// trace linked to it, never a child (otelconnect's default, otelhttp's public endpoint).
package telemetry

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
)

// Tracing is the bridge's tracer, or none (the zero value).
type Tracing struct {
	tp       trace.TracerProvider
	flush    func(context.Context) error
	shutdown func(context.Context) error
}

// New is the tracing for endpoint, the OTLP/HTTP traces URL in full (its /v1/traces path included; "" = none).
func New(endpoint, service string) (*Tracing, error) {
	if endpoint == "" {
		return &Tracing{}, nil
	}
	exp, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpointURL(endpoint),
		otlptracehttp.WithProxy(func(*http.Request) (*url.URL, error) { return nil, nil })) // in-cluster: no proxy
	if err != nil {
		return nil, err
	}
	return WithExporter(exp, service), nil
}

// WithExporter is a tracing over exp: New's, or a test's in-memory one.
func WithExporter(exp sdktrace.SpanExporter, service string) *Tracing {
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithResource(resource.NewSchemaless(semconv.ServiceName(service))))
	return &Tracing{tp: tp, flush: tp.ForceFlush, shutdown: tp.Shutdown}
}

// Interceptors is what the API's handler adds: otelconnect's, or none without tracing.
func (t *Tracing) Interceptors() []connect.Interceptor {
	if t == nil || t.tp == nil {
		return nil
	}
	ic, err := otelconnect.NewInterceptor(otelconnect.WithTracerProvider(t.tp),
		otelconnect.WithPropagator(propagation.TraceContext{}), otelconnect.WithoutMetrics())
	if err != nil {
		panic(err) // only a metrics option can fail, and metrics are off
	}
	return []connect.Interceptor{ic}
}

// Handler is h with a server span per request named pattern, or h itself without tracing.
func (t *Tracing) Handler(pattern string, h http.Handler) http.Handler {
	if t == nil || t.tp == nil {
		return h
	}
	return otelhttp.NewHandler(h, pattern,
		otelhttp.WithTracerProvider(t.tp),
		otelhttp.WithPropagators(propagation.TraceContext{}),
		otelhttp.WithMeterProvider(noopmetric.NewMeterProvider()),
		otelhttp.WithPublicEndpointFn(func(*http.Request) bool { return true }),
		otelhttp.WithSpanNameFormatter(func(pattern string, _ *http.Request) string { return pattern }))
}

// Flush exports the spans buffered so far, or does nothing without tracing.
func (t *Tracing) Flush() error {
	if t == nil || t.flush == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return t.flush(ctx)
}

// Shutdown flushes the spans still buffered (a few seconds at most), or does nothing without tracing.
func (t *Tracing) Shutdown() error {
	if t == nil || t.shutdown == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return t.shutdown(ctx)
}
