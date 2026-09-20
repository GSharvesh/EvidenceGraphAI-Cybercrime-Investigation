"""Prometheus counters, gauges, and histograms for EvidenceGraphAI."""

from prometheus_client import Counter, Gauge, Histogram

# Graph Database Metrics
GRAPH_QUERY_COUNT = Counter(
    "evidencegraph_graph_query_total",
    "Total number of Cypher queries executed",
)

GRAPH_QUERY_ERRORS = Counter(
    "evidencegraph_graph_query_errors_total",
    "Total number of Cypher query errors encountered",
)

GRAPH_ACTIVE_CONNECTIONS = Gauge(
    "evidencegraph_graph_active_connections",
    "Number of active graph query operations",
)

GRAPH_QUERY_DURATION_SECONDS = Histogram(
    "evidencegraph_graph_query_duration_seconds",
    "Cypher query execution duration in seconds",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# API Request Metrics
HTTP_REQUEST_COUNT = Counter(
    "evidencegraph_http_requests_total",
    "Total HTTP requests received",
    ["method", "endpoint", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "evidencegraph_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
