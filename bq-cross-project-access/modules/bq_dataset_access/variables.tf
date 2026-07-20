variable "project_id" {
  type = string
}

variable "dataset_id" {
  type = string
}

variable "members" {
  description = "Users, groups or service accounts"
  type        = map(string)
}

variable "role" {
  type    = string
  default = "roles/bigquery.dataViewer"
}