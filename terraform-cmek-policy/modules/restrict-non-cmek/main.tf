resource "google_org_policy_policy" "restrict_non_cmek_services" {

  name   = "projects/${var.project_id}/policies/gcp.restrictNonCmekServices"
  parent = "projects/${var.project_id}"

  spec {
    rules {

      values {
        allowed_values = var.restricted_services
      }

    }
  }
}