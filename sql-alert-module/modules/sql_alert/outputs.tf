output "alert_policy_id" {
  value = google_monitoring_alert_policy.sql_alert.id
}

output "notification_channel_id" {
  value = google_monitoring_notification_channel.email.id
}

output "notification_email" {
  value = var.notification_email
}