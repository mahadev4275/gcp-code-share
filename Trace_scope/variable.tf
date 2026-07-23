variable "project" {
  type = string
}

variable "projects" {
  type        = list(string)
  description = "List of project IDs to include in the trace scope"
}

variable "region" {
  type = string
  
}
variable "location" {
  type = string
}