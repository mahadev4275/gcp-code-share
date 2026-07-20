module "observability_cmek" {

  source = "./modules/restrict-non-cmek"

  project_id = var.project_id

  restricted_services = [
    "observability.googleapis.com"
  ]
}