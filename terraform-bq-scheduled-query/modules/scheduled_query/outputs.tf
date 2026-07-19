output "scheduled_query_id" {
  value = google_bigquery_data_transfer_config.scheduled_query.id
}

output "service_account" {
  value = google_service_account.scheduled_query_sa.email
}