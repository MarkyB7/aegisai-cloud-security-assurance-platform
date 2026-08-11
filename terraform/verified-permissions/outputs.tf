output "policy_store_id" {
  description = "ID of the AegisAI Amazon Verified Permissions policy store."
  value       = aws_verifiedpermissions_policy_store.aegisai.policy_store_id
}

output "policy_store_arn" {
  description = "ARN of the AegisAI Amazon Verified Permissions policy store."
  value       = aws_verifiedpermissions_policy_store.aegisai.arn
}
