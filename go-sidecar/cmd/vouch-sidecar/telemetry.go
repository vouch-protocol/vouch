package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Tracing sends one span per signing request to an OpenTelemetry collector
// over OTLP/HTTP with the JSON encoding. It is off unless an endpoint is set,
// and it never delays or fails a signature: spans are queued and dropped when
// the collector cannot keep up.

const (
	tracePath      = "/v1/traces"
	traceQueueSize = 512
	traceBatchSize = 64
	traceFlushWait = 2 * time.Second

	spanKindServer  = 2 // SPAN_KIND_SERVER
	statusCodeError = 2 // STATUS_CODE_ERROR
)

// span is one finished signing request.
type span struct {
	traceID      string
	spanID       string
	parentSpanID string
	name         string
	start, end   time.Time
	attrs        []spanAttr
	failed       bool
}

// spanAttr holds a string or an integer attribute.
type spanAttr struct {
	key   string
	str   string
	num   int64
	isNum bool
}

func strAttr(key, value string) spanAttr { return spanAttr{key: key, str: value} }
func intAttr(key string, value int64) spanAttr {
	return spanAttr{key: key, num: value, isNum: true}
}

type traceExporter struct {
	url     string
	client  *http.Client
	logger  *slog.Logger
	queue   chan span
	done    chan struct{}
	dropped atomic.Int64
}

// traceURL turns the configured endpoint into the URL spans are posted to. A
// collector base address such as http://collector:4318 gets /v1/traces added;
// an address that already ends in /v1/traces is used as given.
func traceURL(endpoint string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("--otel-endpoint must be an http or https URL, such as http://localhost:4318")
	}
	if !strings.HasSuffix(u.Path, tracePath) {
		u.Path = strings.TrimRight(u.Path, "/") + tracePath
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

func newTraceExporter(endpoint string, logger *slog.Logger) (*traceExporter, error) {
	target, err := traceURL(endpoint)
	if err != nil {
		return nil, err
	}
	e := &traceExporter{
		url:    target,
		client: &http.Client{Timeout: 5 * time.Second},
		logger: logger,
		queue:  make(chan span, traceQueueSize),
		done:   make(chan struct{}),
	}
	go e.run()
	return e, nil
}

// record queues a finished span. It never blocks.
func (e *traceExporter) record(s span) {
	if e == nil {
		return
	}
	select {
	case e.queue <- s:
	default:
		e.dropped.Add(1)
	}
}

// close sends what is queued and stops the exporter.
func (e *traceExporter) close() {
	if e == nil {
		return
	}
	close(e.queue)
	<-e.done
}

func (e *traceExporter) run() {
	defer close(e.done)
	ticker := time.NewTicker(traceFlushWait)
	defer ticker.Stop()

	batch := make([]span, 0, traceBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := e.send(batch); err != nil {
			e.logger.Warn("trace export failed", "spans", len(batch), "error", err.Error())
		}
		batch = batch[:0]
	}
	for {
		select {
		case s, open := <-e.queue:
			if !open {
				flush()
				return
			}
			batch = append(batch, s)
			if len(batch) == traceBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
			if n := e.dropped.Swap(0); n > 0 {
				e.logger.Warn("trace spans dropped: the collector is not keeping up", "spans", n)
			}
		}
	}
}

// send posts one batch. A busy or briefly unavailable collector gets a single
// second attempt; anything else is not retried.
func (e *traceExporter) send(batch []span) error {
	body, err := json.Marshal(otlpRequest(batch))
	if err != nil {
		return err
	}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		status, err := e.post(body)
		switch {
		case err != nil:
			last = err
		case status == http.StatusOK:
			return nil
		case status == http.StatusTooManyRequests || status == http.StatusBadGateway ||
			status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout:
			last = fmt.Errorf("collector answered %d", status)
		default:
			return fmt.Errorf("collector answered %d", status)
		}
	}
	return last
}

func (e *traceExporter) post(body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, errors.New("collector unreachable")
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, nil
}

// ---------------------------------------------------------------------------
// OTLP JSON encoding
// ---------------------------------------------------------------------------

type otlpAnyValue struct {
	StringValue *string `json:"stringValue,omitempty"`
	IntValue    *string `json:"intValue,omitempty"` // 64-bit integers travel as decimal strings
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

type otlpStatus struct {
	Code int `json:"code"`
}

type otlpSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	ParentSpanID      string         `json:"parentSpanId,omitempty"`
	Name              string         `json:"name"`
	Kind              int            `json:"kind"`
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	EndTimeUnixNano   string         `json:"endTimeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes,omitempty"`
	Status            *otlpStatus    `json:"status,omitempty"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type otlpScopeSpans struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpResourceSpans struct {
	Resource   otlpResource     `json:"resource"`
	ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
}

type otlpTraceRequest struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

func otlpString(key, value string) otlpKeyValue {
	return otlpKeyValue{Key: key, Value: otlpAnyValue{StringValue: &value}}
}

func otlpRequest(batch []span) otlpTraceRequest {
	spans := make([]otlpSpan, 0, len(batch))
	for _, s := range batch {
		out := otlpSpan{
			TraceID:           s.traceID,
			SpanID:            s.spanID,
			ParentSpanID:      s.parentSpanID,
			Name:              s.name,
			Kind:              spanKindServer,
			StartTimeUnixNano: strconv.FormatInt(s.start.UnixNano(), 10),
			EndTimeUnixNano:   strconv.FormatInt(s.end.UnixNano(), 10),
		}
		for _, a := range s.attrs {
			if a.isNum {
				n := strconv.FormatInt(a.num, 10)
				out.Attributes = append(out.Attributes, otlpKeyValue{Key: a.key, Value: otlpAnyValue{IntValue: &n}})
			} else {
				out.Attributes = append(out.Attributes, otlpString(a.key, a.str))
			}
		}
		if s.failed {
			out.Status = &otlpStatus{Code: statusCodeError}
		}
		spans = append(spans, out)
	}
	return otlpTraceRequest{ResourceSpans: []otlpResourceSpans{{
		Resource: otlpResource{Attributes: []otlpKeyValue{
			otlpString("service.name", "vouch-sidecar"),
			otlpString("service.version", Version),
		}},
		ScopeSpans: []otlpScopeSpans{{
			Scope: otlpScope{Name: "vouch-sidecar", Version: Version},
			Spans: spans,
		}},
	}}}
}

// ---------------------------------------------------------------------------
// Trace context
// ---------------------------------------------------------------------------

// newID returns n random bytes as lowercase hex.
func newID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// A span with a made-up ID is worse than no span.
		return ""
	}
	return hex.EncodeToString(b)
}

// parseTraceparent reads a W3C traceparent header and returns the caller's
// trace ID and span ID, so the signing span joins the caller's trace.
func parseTraceparent(header string) (traceID, parentSpanID string, ok bool) {
	parts := strings.Split(strings.TrimSpace(header), "-")
	if len(parts) < 4 {
		return "", "", false
	}
	version, traceID, parentSpanID := parts[0], parts[1], parts[2]
	if len(version) != 2 || !isLowerHex(version) || version == "ff" {
		return "", "", false
	}
	if version == "00" && len(parts) != 4 {
		return "", "", false
	}
	if len(traceID) != 32 || !isLowerHex(traceID) || isAllZero(traceID) {
		return "", "", false
	}
	if len(parentSpanID) != 16 || !isLowerHex(parentSpanID) || isAllZero(parentSpanID) {
		return "", "", false
	}
	if len(parts[3]) != 2 || !isLowerHex(parts[3]) {
		return "", "", false
	}
	return traceID, parentSpanID, true
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != ""
}

func isAllZero(s string) bool {
	return strings.Trim(s, "0") == ""
}
