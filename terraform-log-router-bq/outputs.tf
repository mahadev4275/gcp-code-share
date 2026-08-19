output "sink_name" {
  value = google_logging_project_sink.logs_to_bq.name
}
 

git output "writer_identity" {
  value = google_logging_project_sink.logs_to_bq.writer_identity
}