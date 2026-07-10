#output "name" {
   # value = google_logging_log_scope.logging_log_scope.name
#}

output "trace_scope_id" {
    value = google_observability_trace_scope.observability_trace_scope.trace_scope_id
}
