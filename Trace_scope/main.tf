module "trace_scope" {
  source = "./modules/tf_for_scope"

  location = var.location
  project  = var.project
  monitored_projects = var.monitored_projects
  
}
