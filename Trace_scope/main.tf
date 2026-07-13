module "trace_scope" {
  source = "./Tf_for_scope"

  location = var.location
  project  = var.project
  projects = var.projects
  region   = var.region

}
