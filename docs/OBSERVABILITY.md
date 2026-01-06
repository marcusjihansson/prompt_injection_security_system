# Observability: Tracing & Monitoring

**Status**: ✅ Implemented  
**Version**: 2.0.0  
**Date**: December 2024

---

## Overview

Comprehensive observability with **OpenTelemetry distributed tracing** and **Prometheus metrics** for production monitoring and debugging.

### Key Features

1. **Distributed Tracing** - OpenTelemetry spans for request flow visibility
2. **Prometheus Metrics** - Real-time metrics for monitoring and alerting
3. **Correlation IDs** - Track requests across the entire system
4. **Structured Logging** - JSON logs with trace context
5. **Auto-Instrumentation** - Automatic tracing for FastAPI and HTTP calls

### Benefits

- 🔍 **Debug Production Issues** - Trace requests end-to-end
- 📊 **Monitor Performance** - Real-time latency and throughput metrics
- 🚨 **Set Up Alerts** - Prometheus-based alerting on key metrics
- 📈 **Visualize Trends** - Grafana dashboards for metrics
- 🔗 **Connect Logs** - Correlation IDs link logs to traces

---

## 1. Distributed Tracing

### What is Distributed Tracing?

Distributed tracing tracks a request as it flows through multiple services and components:

```
User Request → API → Cache → Detector → LLM → Response
     ↓           ↓      ↓        ↓        ↓
  Span 1     Span 2  Span 3   Span 4   Span 5
```

Each span contains:
- Operation name and duration
- Parent-child relationships
- Custom attributes (user, IP, threat type)
- Errors and exceptions

### Quick Start

```python
from trust.observability import init_tracing
from trust.api.observable_api import create_observable_app

# Initialize tracing
init_tracing(
    service_name="threat-detection-system",
    otlp_endpoint="http://localhost:4317",  # Jaeger/Tempo
)

# Create observable app (tracing auto-enabled)
app = create_observable_app(
    enable_tracing=True,
    enable_metrics=True,
)

# Run: uvicorn trust.api.observable_api:app
```

### Trace Visualization

When viewing in Jaeger/Grafana Tempo, you'll see:

```
/v1/detect (200ms)
  ├─ validate_input (1ms)
  ├─ detect.enhanced_detector (195ms)
  │   ├─ cache_lookup.L1 (0.5ms) - MISS
  │   ├─ cache_lookup.L2 (10ms) - MISS  
  │   ├─ cache_lookup.L3 (20ms) - MISS
  │   ├─ adaptive_fast_path (2ms) - UNCERTAIN
  │   └─ llm_detection (160ms) - THREAT
  ├─ audit_log (2ms)
  └─ cache_store (1ms)
```

### Manual Tracing

Add custom spans to your code:

```python
from trust.observability import trace_function, get_tracer

# Decorator for functions
@trace_function("my_operation")
def process_data(data):
    # Automatically traced
    return result

# Manual spans
tracer = get_tracer(__name__)

with tracer.start_as_current_span("custom_operation") as span:
    span.set_attribute("user_id", user.id)
    span.set_attribute("operation_type", "analysis")
    
    result = do_work()
    
    span.set_attribute("result_count", len(result))
```

### Trace Detectors

Special tracing for threat detection:

```python
from trust.observability import trace_detector

with trace_detector(
    detector_name="regex_baseline",
    input_text=text,
    result=detection_result,
) as span:
    # Span automatically includes:
    # - detector.name
    # - input.length, input.preview
    # - result.is_threat, result.threat_type, result.confidence
    pass
```

---

## 2. Prometheus Metrics

### Available Metrics

**Request Metrics**:
- `threat_detection_requests_total` - Total requests by endpoint, method, status
- `threat_detection_requests_in_progress` - Current active requests
- `threat_detection_request_duration_seconds` - Request latency histogram

**Detection Metrics**:
- `threat_detection_detections_total` - Detections by threat type and method
- `threat_detection_threats_blocked_total` - Blocked threats by type
- `threat_detection_detection_duration_seconds` - Detection latency histogram

**Cache Metrics**:
- `threat_detection_cache_hits_total` - Cache hits by tier (L1/L2/L3)
- `threat_detection_cache_misses_total` - Cache misses
- `threat_detection_cache_size_bytes` - Cache size by tier

**Fast-Path Metrics**:
- `threat_detection_fast_path_requests_total` - Fast-path usage
- `threat_detection_slow_path_requests_total` - Slow-path (LLM) usage

**Security Metrics**:
- `threat_detection_auth_attempts_total` - Auth attempts by method and result
- `threat_detection_rate_limit_exceeded_total` - Rate limit violations

**Error Metrics**:
- `threat_detection_errors_total` - Errors by type and endpoint

### Accessing Metrics

**Endpoint**: `GET /metrics`

Returns Prometheus text format:

```prometheus
# HELP threat_detection_requests_total Total number of detection requests
# TYPE threat_detection_requests_total counter
threat_detection_requests_total{endpoint="/v1/detect",method="POST",status="success"} 1523.0

# HELP threat_detection_request_duration_seconds Request duration in seconds
# TYPE threat_detection_request_duration_seconds histogram
threat_detection_request_duration_seconds_bucket{endpoint="/v1/detect",method="POST",le="0.01"} 834.0
threat_detection_request_duration_seconds_bucket{endpoint="/v1/detect",method="POST",le="0.05"} 1234.0
threat_detection_request_duration_seconds_sum{endpoint="/v1/detect",method="POST"} 45.2
threat_detection_request_duration_seconds_count{endpoint="/v1/detect",method="POST"} 1523.0
```

### Recording Custom Metrics

```python
from trust.observability import get_metrics_collector

metrics = get_metrics_collector()

# Record detection
metrics.record_detection(
    threat_type="prompt_injection",
    detection_method="fast_path",
    duration=0.002,
    is_threat=True,
)

# Record cache hit
metrics.record_cache_hit(cache_tier="L2")

# Record auth attempt
metrics.record_auth_attempt(method="api_key", success=True)

# Record error
metrics.record_error(error_type="ValidationError", endpoint="/v1/detect")
```

---

## 3. Correlation IDs

### What are Correlation IDs?

Correlation IDs uniquely identify each request and appear in:
- HTTP headers
- Trace spans
- Log messages
- Audit logs

This allows you to:
- Find all logs for a specific request
- Link traces to logs
- Debug issues across services

### Usage

**Automatic**:
```bash
# API automatically generates correlation IDs
curl http://localhost:8000/v1/detect -d '{"text": "test"}'

# Response includes:
{
  "is_threat": false,
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Manual**:
```bash
# Provide your own correlation ID
curl -H "X-Correlation-ID: my-custom-id-123" \
  http://localhost:8000/v1/detect \
  -d '{"text": "test"}'
```

**In Code**:
```python
from trust.observability.tracing import get_correlation_id, set_correlation_id

# Get current correlation ID
correlation_id = get_correlation_id()

# Set custom correlation ID
set_correlation_id("custom-id-123")
```

### Log Search

Find all logs for a request:

```bash
# Search logs by correlation ID
grep "550e8400-e29b-41d4-a716-446655440000" app.log

# With jq for JSON logs
cat app.log | jq 'select(.correlation_id == "550e8400-e29b-41d4-a716-446655440000")'
```

---

## 4. Structured Logging

### JSON Logs

All logs include structured fields:

```json
{
  "timestamp": "2024-12-09T10:30:45.123456Z",
  "level": "INFO",
  "message": "Request completed",
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
  "method": "POST",
  "path": "/v1/detect",
  "status_code": 200,
  "duration_ms": 45.2,
  "trace_id": "1234567890abcdef",
  "span_id": "abcdef1234567890"
}
```

### Configuration

```bash
# Log level
LOG_LEVEL=INFO

# Log format (json or text)
LOG_FORMAT=json

# Include trace IDs
LOG_INCLUDE_TRACE_ID=true
```

---

## 5. Complete Setup Guide

### Local Development (Jaeger)

**1. Start Jaeger**:
```bash
docker run -d --name jaeger \
  -e COLLECTOR_OTLP_ENABLED=true \
  -p 16686:16686 \
  -p 4317:4317 \
  jaegertracing/all-in-one:latest
```

**2. Configure App**:
```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

**3. Start App**:
```bash
uvicorn trust.api.observable_api:app --host 0.0.0.0 --port 8000
```

**4. View Traces**:
- Open http://localhost:16686
- Select service: "threat-detection-system"
- Click "Find Traces"

### Production (Grafana Stack)

**1. Start Grafana Stack** (docker-compose.yml):
```yaml
version: '3'
services:
  # Grafana Tempo (traces)
  tempo:
    image: grafana/tempo:latest
    ports:
      - "4318:4318"  # OTLP HTTP
    command: ["-config.file=/etc/tempo.yaml"]

  # Prometheus (metrics)
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'

  # Grafana (dashboards)
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=true
```

**2. Prometheus Config** (prometheus.yml):
```yaml
scrape_configs:
  - job_name: 'threat-detection'
    static_configs:
      - targets: ['app:8000']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

**3. Start Services**:
```bash
docker-compose up -d
```

**4. Access**:
- Grafana: http://localhost:3000
- Prometheus: http://localhost:9090
- Tempo: http://localhost:4318

---

## 6. Grafana Dashboards

### Import Pre-built Dashboards

**FastAPI Dashboard**:
- Dashboard ID: 14600
- Includes: Request rates, latency, errors

**Custom Threat Detection Dashboard**:

```json
{
  "dashboard": {
    "title": "Threat Detection System",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {"expr": "rate(threat_detection_requests_total[5m])"}
        ]
      },
      {
        "title": "P95 Latency",
        "targets": [
          {"expr": "histogram_quantile(0.95, rate(threat_detection_request_duration_seconds_bucket[5m]))"}
        ]
      },
      {
        "title": "Threat Detection Rate",
        "targets": [
          {"expr": "rate(threat_detection_threats_blocked_total[5m])"}
        ]
      },
      {
        "title": "Cache Hit Rate",
        "targets": [
          {"expr": "rate(threat_detection_cache_hits_total[5m]) / (rate(threat_detection_cache_hits_total[5m]) + rate(threat_detection_cache_misses_total[5m]))"}
        ]
      }
    ]
  }
}
```

### Key Queries

**Request Rate**:
```promql
rate(threat_detection_requests_total[5m])
```

**P95 Latency**:
```promql
histogram_quantile(0.95, 
  rate(threat_detection_request_duration_seconds_bucket[5m])
)
```

**Error Rate**:
```promql
rate(threat_detection_errors_total[5m])
```

**Cache Hit Rate**:
```promql
sum(rate(threat_detection_cache_hits_total[5m])) / 
(sum(rate(threat_detection_cache_hits_total[5m])) + 
 sum(rate(threat_detection_cache_misses_total[5m])))
```

---

## 7. Alerting

### Prometheus Alerting Rules

```yaml
groups:
  - name: threat_detection_alerts
    rules:
      # High error rate
      - alert: HighErrorRate
        expr: rate(threat_detection_errors_total[5m]) > 0.05
        for: 5m
        annotations:
          summary: "High error rate detected"

      # High latency
      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(threat_detection_request_duration_seconds_bucket[5m])) > 1.0
        for: 5m
        annotations:
          summary: "P95 latency exceeds 1 second"

      # Low cache hit rate
      - alert: LowCacheHitRate
        expr: sum(rate(threat_detection_cache_hits_total[5m])) / (sum(rate(threat_detection_cache_hits_total[5m])) + sum(rate(threat_detection_cache_misses_total[5m]))) < 0.6
        for: 10m
        annotations:
          summary: "Cache hit rate below 60%"
```

---

## 8. Troubleshooting

### No Traces Appearing

**Check**:
1. OTLP endpoint configured: `echo $OTEL_EXPORTER_OTLP_ENDPOINT`
2. Collector running: `curl http://localhost:4317`
3. Tracing enabled in code
4. Check logs for export errors

### Metrics Not Updating

**Check**:
1. `/metrics` endpoint accessible
2. Prometheus scraping: Check Prometheus targets
3. Metrics collector initialized

### Correlation IDs Missing

**Check**:
1. Middleware added to app
2. Check response headers: `X-Correlation-ID`
3. Verify context variable set

---

## 9. Performance Impact

### Overhead

- **Tracing**: ~1-2ms per request
- **Metrics**: <1ms per request  
- **Correlation IDs**: <0.1ms per request
- **Structured Logging**: ~0.5ms per log

**Total**: ~2-4ms overhead (negligible)

### Optimization

- Use sampling for high-traffic: `OTEL_TRACES_SAMPLER_ARG=0.1` (10%)
- Batch span exports (default)
- Async metrics recording

---

## 10. Best Practices

### Tracing
✅ **Do**:
- Use descriptive span names
- Add relevant attributes
- Trace critical paths only
- Use sampling in production

❌ **Don't**:
- Trace every function call
- Add sensitive data to spans
- Ignore sampling

### Metrics
✅ **Do**:
- Use histograms for latency
- Label consistently
- Keep cardinality low
- Set up alerting

❌ **Don't**:
- Create high-cardinality labels
- Track PII in metrics
- Ignore metric limits

### Logging
✅ **Do**:
- Use structured logging
- Include correlation IDs
- Log at appropriate levels
- Rotate logs

❌ **Don't**:
- Log sensitive data
- Over-log (DEBUG everywhere)
- Miss correlation IDs

---

## Resources

- **Code**: `src/trust/observability/`
- **API**: `src/trust/api/observable_api.py`
- **Config**: `.env.example`
- **OpenTelemetry Docs**: https://opentelemetry.io/
- **Prometheus Docs**: https://prometheus.io/
- **Grafana Docs**: https://grafana.com/docs/

---

**Status**: ✅ Complete  
**Impact**: Full production observability  
**Ready for**: Production monitoring and debugging 🔍
