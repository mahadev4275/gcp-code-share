provider "google" {
  project = var.project
  region  = var.region
}

module "trace_scope" {
  source = "./Trace_scope"

  location = var.location
  project  = var.project
  projects = var.projects
  region   = var.region

}