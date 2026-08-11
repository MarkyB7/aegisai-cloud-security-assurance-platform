variable "aws_region" {
  description = "AWS region used to deploy the AegisAI Verified Permissions resources."
  type        = string
  default     = "us-west-2"
}

variable "policy_store_description" {
  description = "Description assigned to the AegisAI Verified Permissions policy store."
  type        = string
  default     = "AegisAI enterprise authorization policy store"
}

variable "policy_store_validation_mode" {
  description = "Verified Permissions policy validation mode."
  type        = string
  default     = "STRICT"

  validation {
    condition     = contains(["STRICT", "OFF"], var.policy_store_validation_mode)
    error_message = "policy_store_validation_mode must be STRICT or OFF."
  }
}

variable "project_name" {
  description = "Project identifier used for naming and tagging."
  type        = string
  default     = "AegisAI"
}

variable "environment" {
  description = "Deployment environment."
  type        = string
  default     = "development"
}
