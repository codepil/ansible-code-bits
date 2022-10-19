variable "project_id" {
    type        = string
    description = "The project ID that will be used to launch instances and store images."
}

variable "zone" {
    type        = string
    default     = "us-east1-b"
    description = "The zone in which to launch the instance used to create the image."
}

variable "environment" {
    type        = string
    description = "Associated Software Developement Lifecycle Environment"
}

variable "commit_sha" {
    description = "Associated commit hash for tracking; Will be provided by Jenkins pipelines."
    type = string
    default = ""
}

variable "skip_create_image" {
    type        = bool
    description = "Skip creating the image. Useful for setting to true during a build test stage."
    default = false
}

variable "gcp_creds" {
    type        = string
    description = "Key JSON of SA that has proper roles to run Packer; Roles needed: roles/compute.instanceAdmin.v1 and roles/iam.serviceAccountUser"
}

variable "vm_subnet" {
    type        = string
    description = "Subnet for which to launch Compute Instances for Packer building"
}