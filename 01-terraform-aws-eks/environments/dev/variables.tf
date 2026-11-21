variable "project" {
  type    = string
  default = "secure-ai"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "region" {
  type    = string
  default = "eu-central-1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "kubernetes_version" {
  type    = string
  default = "1.31"
}

variable "api_allowed_cidrs" {
  description = "Your office/VPN egress CIDRs allowed to reach the EKS API. Empty = private only."
  type        = list(string)
  default     = []
}

variable "admin_role_arns" {
  description = "IAM roles (e.g. SSO admin role) that get cluster-admin."
  type        = list(string)
  default     = []
}

variable "github_repo" {
  description = "owner/repo allowed to assume the CI role via OIDC."
  type        = string
  default     = "rik959/devsecops-aisecops-portfolio"
}
