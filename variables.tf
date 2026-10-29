variable "project_id" {
  type        = string
  description = "The Google Cloud Project ID"
  default     = "project-53fcf8c4-8d5e-408d-859"
}

variable "region" {
  type        = string
  description = "The Google Cloud region for Model Armor and SDP templates"
  default     = "us-central1"
}

variable "enable_logging" {
  type        = bool
  description = "Enable template operations and sanitization logging in Cloud Logging. Set to false if you want to eliminate log ingestion costs."
  default     = true
}
