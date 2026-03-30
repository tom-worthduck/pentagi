package observability

import (
	"context"
	"testing"

	"pentagi/pkg/observability/langfuse"

	otellog "go.opentelemetry.io/otel/log"
	otellognoop "go.opentelemetry.io/otel/log/noop"
	otelmetric "go.opentelemetry.io/otel/metric"
	otelmetricnoop "go.opentelemetry.io/otel/metric/noop"
	oteltrace "go.opentelemetry.io/otel/trace"
	oteltracenoop "go.opentelemetry.io/otel/trace/noop"
)

type testLangfuseClient struct {
	forceFlushCalls int
	shutdownCalls   int
}

func (c *testLangfuseClient) API() langfuse.Client {
	return langfuse.Client{}
}

func (c *testLangfuseClient) Observer() langfuse.Observer {
	return langfuse.NewNoopObserver()
}

func (c *testLangfuseClient) Shutdown(context.Context) error {
	c.shutdownCalls++
	return nil
}

func (c *testLangfuseClient) ForceFlush(context.Context) error {
	c.forceFlushCalls++
	return nil
}

type testTelemetryClient struct {
	forceFlushCalls int
	shutdownCalls   int
}

func (c *testTelemetryClient) Logger() otellog.LoggerProvider {
	return otellognoop.NewLoggerProvider()
}

func (c *testTelemetryClient) Tracer() oteltrace.TracerProvider {
	return oteltracenoop.NewTracerProvider()
}

func (c *testTelemetryClient) Meter() otelmetric.MeterProvider {
	return otelmetricnoop.NewMeterProvider()
}

func (c *testTelemetryClient) Shutdown(context.Context) error {
	c.shutdownCalls++
	return nil
}

func (c *testTelemetryClient) ForceFlush(context.Context) error {
	c.forceFlushCalls++
	return nil
}

func TestObserverFlushFlushesAllConfiguredBackends(t *testing.T) {
	t.Parallel()

	lfclient := &testLangfuseClient{}
	otelclient := &testTelemetryClient{}
	obs := &observer{
		lfclient:   lfclient,
		otelclient: otelclient,
	}

	if err := obs.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if lfclient.forceFlushCalls != 1 {
		t.Fatalf("expected Langfuse flush to be called once, got %d", lfclient.forceFlushCalls)
	}
	if otelclient.forceFlushCalls != 1 {
		t.Fatalf("expected OTEL flush to be called once, got %d", otelclient.forceFlushCalls)
	}
}

func TestObserverShutdownShutsDownAllConfiguredBackends(t *testing.T) {
	t.Parallel()

	lfclient := &testLangfuseClient{}
	otelclient := &testTelemetryClient{}
	obs := &observer{
		lfclient:   lfclient,
		otelclient: otelclient,
	}

	if err := obs.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	if lfclient.shutdownCalls != 1 {
		t.Fatalf("expected Langfuse shutdown to be called once, got %d", lfclient.shutdownCalls)
	}
	if otelclient.shutdownCalls != 1 {
		t.Fatalf("expected OTEL shutdown to be called once, got %d", otelclient.shutdownCalls)
	}
}
