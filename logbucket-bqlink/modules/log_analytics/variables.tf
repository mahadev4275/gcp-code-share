variable "project_id" {
  type = string
}

variable "bucket_id" {
  type = string
}

variable "location" {
  type    = string
  default = "global"
}

variable "retention_days" {
  type    = number
  default = 30
}

variable "link_id" {
  type = string
}