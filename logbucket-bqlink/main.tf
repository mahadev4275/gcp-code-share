module "log_analytics" {

  source = "./modules/log_analytics"

  project_id = var.project_id

  bucket_id = "_Trace"

  location = "global"

  retention_days = 30

  link_id = "observability_link"
}