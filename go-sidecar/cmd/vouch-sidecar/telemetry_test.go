package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"
)

// collector is a stand-in OpenTelemetry collector that records what it is sent.
type collector struct {
	mu       sync.Mutex
	requests []collected
	answer   func(n int) int // status for the nth request, starting at 1
}

type collected struct {
	path        string
	contentType string
	body        otlpTraceRequest
	raw         string
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body otlpTraceRequest
	json.Unmarshal(raw, &body)

	c.mu.Lock()
	c.requests = append(c.requests, collected{r.URL.Path, r.Header.Get("Content-Type"), body, string(raw)})
	n := len(c.requests)
	c.mu.Unlock()

	status := http.StatusOK
	if c.answer != nil {
		status = c.answer(n)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, "{}")
}

func (c *collector) spans() []otlpSpan {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []otlpSpan
	for _, req := range c.requests {
		for _, rs := range req.body.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				out = append(out, ss.Spans...)
			}
		}
	}
	return out
}

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

func attrsOf(s otlpSpan) map[string]string {
	out := map[string]string{}
	for _, a := range s.Attributes {
		switch {
		case a.Value.StringValue != nil:
			out[a.Key] = *a.Value.StringValue
		case a.Value.IntValue != nil:
			out[a.Key] = *a.Value.IntValue
		}
	}
	return out
}

var (
	hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex16 = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// ---------------------------------------------------------------------------
// What reaches the collector
// ---------------------------------------------------------------------------

func TestSigningRequestsBecomeSpans(t *testing.T) {
	col := &collector{}
	server := httptest.NewServer(col)
	defer server.Close()

	exporter, err := newTraceExporter(server.URL, quiet())
	if err != nil {
		t.Fatal(err)
	}
	h := localHandler(t, newTestSigner(t), serverConfig{tracer: exporter})

	before := time.Now()
	do(t, h, http.MethodPost, "/sign", goodIntent)
	do(t, h, http.MethodPost, "/sign", `{}`) // refused: still a span
	do(t, h, http.MethodGet, "/health", "")  // not a signing request: no span
	do(t, h, http.MethodPost, "/sign/hybrid", goodIntent)
	exporter.close()

	if len(col.requests) == 0 {
		t.Fatal("nothing reached the collector")
	}
	first := col.requests[0]
	if first.path != "/v1/traces" || first.contentType != "application/json" {
		t.Fatalf("posted to %s as %s", first.path, first.contentType)
	}
	resource := first.body.ResourceSpans[0].Resource.Attributes[0]
	if resource.Key != "service.name" || *resource.Value.StringValue != "vouch-sidecar" {
		t.Fatalf("resource = %+v", resource)
	}

	spans := col.spans()
	if len(spans) != 3 {
		t.Fatalf("%d spans, want 3 (two /sign, one /sign/hybrid, none for /health)", len(spans))
	}
	seen := map[string]bool{}
	for _, s := range spans {
		if !hex32.MatchString(s.TraceID) || !hex16.MatchString(s.SpanID) || seen[s.SpanID] {
			t.Fatalf("bad or repeated ids: trace %q span %q", s.TraceID, s.SpanID)
		}
		seen[s.SpanID] = true
		if s.Kind != 2 {
			t.Fatalf("kind = %d, want 2 (server)", s.Kind)
		}
		start, err1 := strconv.ParseInt(s.StartTimeUnixNano, 10, 64)
		end, err2 := strconv.ParseInt(s.EndTimeUnixNano, 10, 64)
		if err1 != nil || err2 != nil || end < start || start < before.UnixNano() {
			t.Fatalf("times %q to %q", s.StartTimeUnixNano, s.EndTimeUnixNano)
		}
		if s.Status != nil {
			t.Fatalf("status set on a request that did not fail in the server: %+v", s.Status)
		}
	}

	ok := attrsOf(spans[0])
	if spans[0].Name != "POST /sign" || ok["http.response.status_code"] != "200" ||
		ok["vouch.intent.action"] != "read.file" || ok["vouch.did"] != testDID ||
		ok["vouch.proof"] != "eddsa-jcs-2022" || ok["vouch.credential.id"] == "" {
		t.Fatalf("signed span = %s %v", spans[0].Name, ok)
	}
	if refused := attrsOf(spans[1]); refused["http.response.status_code"] != "400" || refused["vouch.credential.id"] != "" {
		t.Fatalf("refused span = %v", refused)
	}
	if spans[2].Name != "POST /sign/hybrid" || attrsOf(spans[2])["vouch.proof"] != "eddsa-jcs-2022+mldsa44-jcs-2024" {
		t.Fatalf("hybrid span = %s %v", spans[2].Name, attrsOf(spans[2]))
	}

	// The wire format: integer enums, lowerCamelCase keys, numbers as strings.
	for _, want := range []string{`"resourceSpans"`, `"scopeSpans"`, `"startTimeUnixNano":"`, `"kind":2`, `"intValue":"200"`} {
		if !regexp.MustCompile(regexp.QuoteMeta(want)).MatchString(first.raw) {
			t.Fatalf("payload lacks %s:\n%s", want, first.raw)
		}
	}
	for _, secret := range []string{"proofValue", "api.example.com", `"d"`} {
		if regexp.MustCompile(regexp.QuoteMeta(secret)).MatchString(first.raw) {
			t.Fatalf("payload contains %q", secret)
		}
	}
}

func TestSpanJoinsTheCallersTrace(t *testing.T) {
	col := &collector{}
	server := httptest.NewServer(col)
	defer server.Close()
	exporter, _ := newTraceExporter(server.URL, quiet())
	h := localHandler(t, newTestSigner(t), serverConfig{tracer: exporter})

	const traceID, parentID = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
	do(t, h, http.MethodPost, "/sign", goodIntent, func(r *http.Request) {
		r.Header.Set("traceparent", "00-"+traceID+"-"+parentID+"-01")
	})
	do(t, h, http.MethodPost, "/sign", goodIntent, func(r *http.Request) {
		r.Header.Set("traceparent", "00-00000000000000000000000000000000-"+parentID+"-01")
	})
	exporter.close()

	spans := col.spans()
	if len(spans) != 2 {
		t.Fatalf("%d spans", len(spans))
	}
	if spans[0].TraceID != traceID || spans[0].ParentSpanID != parentID || spans[0].SpanID == parentID {
		t.Fatalf("did not join the caller's trace: %+v", spans[0])
	}
	if spans[1].TraceID == "00000000000000000000000000000000" || spans[1].ParentSpanID != "" {
		t.Fatalf("an invalid traceparent was trusted: %+v", spans[1])
	}
}

func TestParseTraceparent(t *testing.T) {
	const tid, sid = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
	if gotT, gotS, ok := parseTraceparent("00-" + tid + "-" + sid + "-01"); !ok || gotT != tid || gotS != sid {
		t.Fatalf("valid header rejected: %q %q %v", gotT, gotS, ok)
	}
	bad := []string{
		"",
		"garbage",
		"00-" + tid + "-" + sid,               // no flags
		"00-" + tid + "-" + sid + "-01-extra", // version 00 allows no more parts
		"ff-" + tid + "-" + sid + "-01",       // forbidden version
		"00-" + tid[:31] + "-" + sid + "-01",  // short trace id
		"00-" + tid + "-" + sid[:15] + "-01",  // short span id
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-" + sid + "-01", // upper case
		"00-" + tid + "-0000000000000000-01",                 // zero span id
		"00-zzzz2f3577b34da6a3ce929d0e0e4736-" + sid + "-01",
		"00-" + tid + "-" + sid + "-0",
	}
	for _, header := range bad {
		if _, _, ok := parseTraceparent(header); ok {
			t.Fatalf("accepted %q", header)
		}
	}
}

// ---------------------------------------------------------------------------
// A collector in trouble never gets in the way of signing
// ---------------------------------------------------------------------------

func TestSigningWorksWhenTheCollectorIsDown(t *testing.T) {
	server := httptest.NewServer(&collector{})
	server.Close() // nothing is listening at this address any more

	exporter, err := newTraceExporter(server.URL, quiet())
	if err != nil {
		t.Fatal(err)
	}
	h := localHandler(t, newTestSigner(t), serverConfig{tracer: exporter})

	start := time.Now()
	for i := 0; i < 5; i++ {
		if rec := do(t, h, http.MethodPost, "/sign", goodIntent); rec.Code != http.StatusOK {
			t.Fatalf("status %d while the collector is down", rec.Code)
		}
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("signing waited on the collector: %s", elapsed)
	}
	exporter.close()
}

func TestSpansAreDroppedNotQueuedForever(t *testing.T) {
	// No run loop: nothing drains the queue, as with a stalled collector.
	e := &traceExporter{queue: make(chan span, 4), logger: quiet()}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			e.record(span{name: "POST /sign"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("record blocked on a full queue")
	}
	if got := e.dropped.Load(); got != 96 {
		t.Fatalf("dropped %d spans, want 96", got)
	}
}

func TestExportRetriesABusyCollectorOnce(t *testing.T) {
	statuses := map[string]struct {
		answers []int
		calls   int
		ok      bool
	}{
		"busy then fine":     {[]int{503, 200}, 2, true},
		"rate limited twice": {[]int{429, 429}, 2, false},
		"bad request":        {[]int{400, 200}, 1, false},
		"unauthorized":       {[]int{401, 200}, 1, false},
		"fine first time":    {[]int{200}, 1, true},
	}
	for name, c := range statuses {
		col := &collector{answer: func(n int) int { return c.answers[min(n, len(c.answers))-1] }}
		server := httptest.NewServer(col)
		e := &traceExporter{url: server.URL + tracePath, client: server.Client(), logger: quiet()}
		err := e.send([]span{{traceID: newID(16), spanID: newID(8), name: "POST /sign", start: time.Now(), end: time.Now()}})
		server.Close()

		if (err == nil) != c.ok || len(col.requests) != c.calls {
			t.Fatalf("%s: err=%v after %d calls, want ok=%v after %d", name, err, len(col.requests), c.ok, c.calls)
		}
	}
}

func TestTraceURL(t *testing.T) {
	good := map[string]string{
		"http://localhost:4318":                   "http://localhost:4318/v1/traces",
		"http://localhost:4318/":                  "http://localhost:4318/v1/traces",
		"https://otel.example.com/collector":      "https://otel.example.com/collector/v1/traces",
		"http://collector:4318/v1/traces":         "http://collector:4318/v1/traces",
		" http://collector:4318/v1/traces?x=1#y ": "http://collector:4318/v1/traces",
	}
	for in, want := range good {
		if got, err := traceURL(in); err != nil || got != want {
			t.Fatalf("%q -> %q (%v), want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "collector:4318", "localhost", "ftp://collector:4318", "http://", "://x"} {
		if _, err := traceURL(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}
