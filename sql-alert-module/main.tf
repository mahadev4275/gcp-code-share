resource "google_project_service" "monitoring" {
  project = var.project_id
  service = "monitoring.googleapis.com"

  disable_on_destroy = false
}

module "sql_alert" {

  source = "./modules/sql_alert"

  alert_name = "Critical Error Logs Alert"

  notification_email = "aman92121rastogi@gmail.com"

  query = <<EOF
SELECT *
FROM `${var.project_id}.global._Default._AllLogs`
WHERE severity IN ("ERROR","CRITICAL")

EOF

  periodicity = 600

  threshold = "0"

  depends_on = [
    google_project_service.monitoring
  ]
}
