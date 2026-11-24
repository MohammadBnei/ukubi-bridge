package bus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	bridgev1 "github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1"
	"github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1/bridgev1connect"
)

// An oversized message is refused, compressed or not; one under the cap reaches the handler.
func TestRequestSizeLimit(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(New(nil, nil, nil).Handler())
	srv := httptest.NewServer(mux)
	defer srv.Close()
	for _, c := range []struct {
		name string
		opts []connect.ClientOption
		size int
		want connect.Code
	}{
		{"under", nil, maxRequest - 1024, connect.CodeUnauthenticated},
		{"over", nil, maxRequest + 1, connect.CodeResourceExhausted},
		{"over, gzip", []connect.ClientOption{connect.WithSendGzip()}, maxRequest + 1, connect.CodeResourceExhausted},
	} {
		cl := bridgev1connect.NewBridgeServiceClient(srv.Client(), srv.URL, c.opts...)
		_, err := cl.Publish(context.Background(), connect.NewRequest(&bridgev1.PublishRequest{Event: &bridgev1.CloudEvent{Data: make([]byte, c.size)}}))
		if got := connect.CodeOf(err); got != c.want {
			t.Errorf("%s: got %v (%v), want %v", c.name, got, err, c.want)
		}
	}
}
