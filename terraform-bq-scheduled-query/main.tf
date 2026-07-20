module "billing_summary_query" {

  source = "./modules/scheduled_query"

  project_id = var.project_id

  dataset_id = "projects_logs_bq"

  query_name = "daily_billing_summary"

  service_account_name = "bq-scheduled-query"

  schedule = "every 24 hours"

  query = <<EOF
SELECT
  DATE(usage_start_time) AS usage_date,
  project.id,
  SUM(cost) AS total_cost
FROM
  `billing_reports.gcp_billing_export_v1_*`
GROUP BY
  usage_date,
  project.id
EOF
}