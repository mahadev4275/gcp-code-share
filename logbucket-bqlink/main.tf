module "log_analytics" {

  source = "./modules/log_analytics"

  project_id = var.project_id

  bucket_id  = "observability-log-bucket"

  dataset_id = "log_analytics_dataset"

  location = "us-central1"
}