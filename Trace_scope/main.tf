module "trace_scope" {
  source = "../tf_for_scope"

  location = var.location
  project  = var.project
  projects = var.projects
  region   = var.region

}
