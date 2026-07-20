provider "google" {
  project = var.project_id
}

resource "google_org_policy_policy" "resource_locations" {
  name   = "projects/${var.project_id}/policies/gcp.resourceLocations"
  parent = "projects/${var.project_id}"

  spec {

    rules {
      values {
        allowed_values = [
          "in:us-locations",
          "in:europe-locations"
        ]
      }
    }
  }
}
