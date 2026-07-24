########################################################
# Email Notification Channel
########################################################

resource "google_monitoring_notification_channel" "email" {

  display_name = "Email Notification"

  type = "email"

  labels = {
    email_address = var.notification_email
  }

  force_delete = false
}

########################################################
# SQL Alert Policy
########################################################

resource "google_monitoring_alert_policy" "sql_alert" {

  display_name = var.alert_name

  combiner = "OR"

  notification_channels = [
    google_monitoring_notification_channel.email.id
  ]

  conditions {

    display_name = "${var.alert_name} Condition"

    condition_sql {

      query = var.query

      minutes {
        periodicity = var.periodicity
      }

      row_count_test {

        comparison = "COMPARISON_GT"

        threshold = var.threshold
      }
    }
  }

  enabled = true

  documentation {

    content = <<EOF
Alert generated from SQL query execution.
If triggered, review Log Analytics / Observability Dataset results.
EOF

    mime_type = "text/markdown"
  }
}