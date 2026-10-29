terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ==============================================================================
# 1. Enable Required GCP APIs
# ==============================================================================

resource "google_project_service" "modelarmor" {
  project            = var.project_id
  service            = "modelarmor.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "dlp" {
  project            = var.project_id
  service            = "dlp.googleapis.com"
  disable_on_destroy = false
}

# ==============================================================================
# 2. Task 2: Input Sanitization Template (advisor-input-filter)
# ==============================================================================

resource "google_model_armor_template" "advisor_input_filter" {
  project     = var.project_id
  location    = var.region
  template_id = "advisor-input-filter"

  filter_config {
    malicious_uri_filter_settings {
      filter_enforcement = "ENABLED"
    }

    pi_and_jailbreak_filter_settings {
      filter_enforcement = "ENABLED"
      confidence_level   = "MEDIUM_AND_ABOVE"
    }

    sdp_settings {
      basic_config {
        filter_enforcement = "ENABLED"
      }
    }

    rai_settings {
      rai_filters {
        filter_type      = "HATE_SPEECH"
        confidence_level = "HIGH"
      }
      rai_filters {
        filter_type      = "HARASSMENT"
        confidence_level = "HIGH"
      }
      rai_filters {
        filter_type      = "SEXUALLY_EXPLICIT"
        confidence_level = "HIGH"
      }
      rai_filters {
        filter_type      = "DANGEROUS"
        confidence_level = "HIGH"
      }
    }
  }

  template_metadata {
    enforcement_type        = "INSPECT_AND_BLOCK"
    log_template_operations = var.enable_logging
    log_sanitize_operations = var.enable_logging
  }

  depends_on = [google_project_service.modelarmor]
}

# ==============================================================================
# 3. Task 3: Sensitive Data Protection (SDP) Templates
# ==============================================================================

# Inspect Template: Scans for PII and financial identifiers
resource "google_data_loss_prevention_inspect_template" "advisor_inspect_template" {
  parent       = "projects/${var.project_id}/locations/${var.region}"
  template_id  = "advisor-inspect-template"
  display_name = "advisor-inspect-template"
  description  = "Inspect template for Cymbal Advisor to detect PII and financial info"

  inspect_config {
    min_likelihood = "POSSIBLE"
    include_quote  = true

    info_types {
      name = "EMAIL_ADDRESS"
    }
    info_types {
      name = "PHONE_NUMBER"
    }
    info_types {
      name = "US_SOCIAL_SECURITY_NUMBER"
    }
    info_types {
      name = "CREDIT_CARD_NUMBER"
    }
  }

  depends_on = [google_project_service.dlp]
}

# De-identify Template: Replaces findings with infoType tokens (e.g. [EMAIL_ADDRESS])
resource "google_data_loss_prevention_deidentify_template" "advisor_deidentify_template" {
  parent       = "projects/${var.project_id}/locations/${var.region}"
  template_id  = "advisor-deidentify-template"
  display_name = "advisor-deidentify-template"
  description  = "De-identify template for Cymbal Advisor to mask sensitive infoTypes"

  deidentify_config {
    info_type_transformations {
      transformations {
        primitive_transformation {
          replace_with_info_type_config = true
        }
      }
    }
  }

  depends_on = [google_project_service.dlp]
}

# ==============================================================================
# 4. Task 3: Response Sanitization Template (advisor-output-filter)
# ==============================================================================

resource "google_model_armor_template" "advisor_output_filter" {
  project     = var.project_id
  location    = var.region
  template_id = "advisor-output-filter"

  filter_config {
    sdp_settings {
      advanced_config {
        inspect_template    = "projects/${var.project_id}/locations/${var.region}/inspectTemplates/${google_data_loss_prevention_inspect_template.advisor_inspect_template.template_id}"
        deidentify_template = "projects/${var.project_id}/locations/${var.region}/deidentifyTemplates/${google_data_loss_prevention_deidentify_template.advisor_deidentify_template.template_id}"
      }
    }

    rai_settings {
      rai_filters {
        filter_type      = "HATE_SPEECH"
        confidence_level = "HIGH"
      }
      rai_filters {
        filter_type      = "HARASSMENT"
        confidence_level = "HIGH"
      }
      rai_filters {
        filter_type      = "SEXUALLY_EXPLICIT"
        confidence_level = "HIGH"
      }
      rai_filters {
        filter_type      = "DANGEROUS"
        confidence_level = "HIGH"
      }
    }
  }

  template_metadata {
    enforcement_type        = "INSPECT_AND_BLOCK"
    log_template_operations = var.enable_logging
    log_sanitize_operations = var.enable_logging
  }

  depends_on = [
    google_project_service.modelarmor,
    google_data_loss_prevention_inspect_template.advisor_inspect_template,
    google_data_loss_prevention_deidentify_template.advisor_deidentify_template
  ]
}
