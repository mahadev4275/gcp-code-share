variable "alert_name" {
  type = string
}

variable "query" {
  type = string
}

variable "notification_email" {
  type = string
}

variable "periodicity" {
  type    = number
  default = 600
}

variable "threshold" {
  type    = string
  default = "0"
}