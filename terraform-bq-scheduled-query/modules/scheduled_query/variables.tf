variable "project_id" {
  type = string
}

variable "dataset_id" {
  type = string
}

variable "query_name" {
  type = string
}
 
variable "query" {
  type = string
}


variable "schedule" {
  type    = string
  default = "every 24 hours"
}

variable "location" {
  type    = string
  default = "US"
}

variable "service_account_name" {
  type = string
}