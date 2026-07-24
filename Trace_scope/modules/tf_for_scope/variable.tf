
variable "project" {
  type = string
}

variable "projects" {
  type        = list(string)
  description = "List of project IDs to include in the trace scope"
  default     = []
}

variable "location" {
  type = string
}

variable "monitored_projects" {
  type        = list(string)
  description = "List of project IDs to include in the trace scope"
}


