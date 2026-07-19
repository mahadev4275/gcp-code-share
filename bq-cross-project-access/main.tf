module "cross_project_access" {

  source = "./modules/bq_dataset_access"

  project_id = var.project_id

  dataset_id = "trace_spans"

  role = "roles/bigquery.dataViewer"

  members = {

    analytics_sa = "serviceAccount:analytics-sa@analytics-project.iam.gserviceaccount.com"

    sre_team = "group:sre@example.com"

    finops_team = "group:finops@example.com"
  }
}