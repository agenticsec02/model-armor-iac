output "model_armor_input_template" {
  description = "The resource path of the Model Armor input filter template"
  value       = google_model_armor_template.advisor_input_filter.name
}

output "model_armor_output_template" {
  description = "The resource path of the Model Armor output filter template"
  value       = google_model_armor_template.advisor_output_filter.name
}

output "sdp_inspect_template_id" {
  description = "The ID of the SDP Inspect Template"
  value       = google_data_loss_prevention_inspect_template.advisor_inspect_template.id
}

output "sdp_deidentify_template_id" {
  description = "The ID of the SDP Deidentify Template"
  value       = google_data_loss_prevention_deidentify_template.advisor_deidentify_template.id
}
