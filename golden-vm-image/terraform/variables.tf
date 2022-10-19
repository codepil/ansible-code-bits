variable "unit_code" {
  description = "Operational unit short name (resource prefix)."
  type        = string
}

variable "image_project_id" {
  description = "Project id used for environmental automation service accounts."
  type        = string
}

variable "allow_destroy" {
  description = "If true, safeguards will be disabled allowing the project to be destroyed"
  default     = false
  type        = bool
}

variable "automation_project_id" {
  description = "Project id used for environmental automation service accounts."
  type        = string
}

variable "packer_source_project_ip_range" {
  description = "IP range of where packer is running from"
  type        = list(string)
}