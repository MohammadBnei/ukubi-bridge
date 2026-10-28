package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	bridgev1 "github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1"
	"github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1/bridgev1connect"
)

type teapot struct{}

func (teapot) ServeHTTP(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }

const caller = "0af7651916cd43dd8448eb211c80319c"

// TestNone: no endpoint, no tracing: the handler is untouched and no interceptor is added.
func TestNone(t *testing.T) {
	none, err := New("", "x")
	if err != nil {
		t.Fatal(err)
	}
	var nilT *Tracing
	for name, tr := range map[string]*Tracing{"New(\"\")": none, "nil": nilT, "zero": {}} {
		if h := tr.Handler("POST /x", teapot{}); h != (teapot{}) {
			t.Errorf("%s: the handler is wrapped (%T)", name, h)
		}
		if ics := tr.Interceptors(); ics != nil {
			t.Errorf("%s: %d interceptors", name, len(ics))
		}
		if err := tr.Shutdown(); err != nil {
			t.Errorf("%s: shutdown: %v", name, err)
		}
	}
	tr, err := New("http://127.0.0.1:1/v1/traces", "x")
	if err != nil || tr.tp == nil || len(tr.Interceptors()) != 1 {
		t.Errorf("an endpoint: %v", err) // the positive control: an endpoint makes a tracer
	}
	tr.Shutdown()
}

// check: one server span named name, linked to the caller's trace and not a child of it, for service ukubi-bridge.
func check(t *testing.T, exp *tracetest.InMemoryExporter, name string) tracetest.SpanStub {
	t.Helper()
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("%d spans", len(spans))
	}
	s := spans[0]
	if s.Name != name || s.SpanKind != trace.SpanKindServer {
		t.Errorf("span %q kind %v", s.Name, s.SpanKind)
	}
	if s.Parent.IsValid() || s.SpanContext.TraceID().String() == caller {
		t.Errorf("a public request became a child of the caller's trace: parent %v", s.Parent)
	}
	if len(s.Links) != 1 || s.Links[0].SpanContext.TraceID().String() != caller {
		t.Errorf("links: %+v", s.Links)
	}
	if v, ok := s.Resource.Set().Value("service.name"); !ok || v.AsString() != "ukubi-bridge" {
		t.Errorf("service.name: %v", v)
	}
	return s
}

// TestWebhookSpans: a webhook request gets one server span named by its route; the answer is the handler's.
func TestWebhookSpans(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tr := WithExporter(exp, "ukubi-bridge")
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/webhook/github", nil)
	r.Header.Set("traceparent", "00-"+caller+"-b7ad6b7169203331-01")
	tr.Handler("POST /webhook/github", teapot{}).ServeHTTP(w, r)
	if w.Code != http.StatusTeapot {
		t.Errorf("the answer: %d", w.Code)
	}
	if err := tr.Flush(); err != nil {
		t.Fatal(err)
	}
	check(t, exp, "POST /webhook/github")
}

// TestAPISpans: a BridgeService call through the generated handler gets one RPC server span named by its procedure,
// with the error's status; a caller's traceparent is linked, not trusted.
func TestAPISpans(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tr := WithExporter(exp, "ukubi-bridge")
	path, h := bridgev1connect.NewBridgeServiceHandler(bridgev1connect.UnimplementedBridgeServiceHandler{}, connect.WithInterceptors(tr.Interceptors()...))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req := connect.NewRequest(&bridgev1.PublishRequest{})
	req.Header().Set("traceparent", "00-"+caller+"-b7ad6b7169203331-01")
	_, err := bridgev1connect.NewBridgeServiceClient(srv.Client(), srv.URL).Publish(context.Background(), req)
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("the answer: %v", err)
	}
	if err := tr.Flush(); err != nil {
		t.Fatal(err)
	}
	s := check(t, exp, "bridge.v1.BridgeService/Publish")
	if s.Status.Code.String() != "Error" {
		t.Errorf("status %v", s.Status)
	}
}
