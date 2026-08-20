variable "project_id" {
  type    = string
  default = "gcp-sbx-lab-core-80d4"
}
 
variable "dataset_id" {
  type    = string
  default = "bqdataset12_cmek"
}
 
variable "sink_name" {
  type    = string
  default = "logs-to-bigquery"
}
 
variable "region" {
  type    = string
  default = "us-central1"
}