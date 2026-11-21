output "cluster_name" {
  value = module.eks.cluster_name
}

output "kubeconfig_command" {
  value = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "ecr_repositories" {
  value = { for k, r in aws_ecr_repository.app : k => r.repository_url }
}

output "github_ci_role_arn" {
  description = "Set as AWS_ROLE_ARN in GitHub Actions secrets/vars."
  value       = aws_iam_role.github_ci.arn
}
