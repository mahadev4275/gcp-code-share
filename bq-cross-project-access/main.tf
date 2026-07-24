module "cross_project_access" {

  source = "./modules/bq_dataset_access"

  project_id = var.project_id

  dataset_id = "demo"

  role = "roles/bigquery.dataViewer"

  members = { 

    User = "user:argo-50f7bc@gc-trial-0041.orgtrials.ongcp.co"

   
  }
}