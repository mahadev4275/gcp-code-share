#########################################################
# BigQuery Table
#########################################################

resource "google_bigquery_table" "daily_summary" {
  dataset_id = google_bigquery_dataset.dataset.dataset_id
  table_id   = "daily_summary"

  schema = jsonencode([
    {
      name = "id"
      type = "INTEGER"
      mode = "REQUIRED"
    },
    {
      name = "name"
      type = "STRING"
      mode = "NULLABLE"
    },
    {
      name = "salary"
      type = "INTEGER"
      mode = "NULLABLE"
    }
  ])
}
#########################################################
# Service Account
#########################################################

resource "google_service_account" "scheduled_query_sa" {

  account_id   = var.service_account_name
  display_name = "Scheduled Query Service Account"
}

#########################################################
# BigQuery Dataset IAM
#########################################################

resource "google_bigquery_dataset" "dataset" {
dataset_id = var.dataset_id
location = var.location
}

resource "google_bigquery_dataset_iam_member" "bq_editor" {

  dataset_id = var.dataset_id

  role = "roles/bigquery.dataEditor"

  member = "serviceAccount:${google_service_account.scheduled_query_sa.email}"

  condition {
    title       = "restrict_to_scheduled_query_dataset"
    description = "Scope dataEditor access to the scheduled query target dataset only"
    #expression  = "resource.name.endsWith(\"/datasets/${var.dataset_id}\")"
    expression = "resource.name.endsWith(\"/tables/daily_summary\")"
  }
}

#########################################################
# Scheduled Query
#########################################################

resource "google_bigquery_data_transfer_config" "scheduled_query" {

  display_name = var.query_name

  location           = var.location
  data_source_id     = "scheduled_query"
  destination_dataset_id = var.dataset_id

  schedule = var.schedule

  service_account_name = google_service_account.scheduled_query_sa.email

   params = {
    query = <<EOT
SELECT
  1 AS id,
  'ferandas' AS name,
  50000 AS salary
UNION ALL
SELECT
  2 AS id,
  'John' AS name,
  60000 AS salary
UNION ALL
SELECT
  3 AS id,
  'Alex' AS name,
  70000 AS salary
EOT

    destination_table_name_template = "daily_summary"

    write_disposition = "WRITE_TRUNCATE"
  }
}