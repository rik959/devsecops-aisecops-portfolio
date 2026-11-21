variable "name" {
  description = "Name prefix for all VPC resources."
  type        = string
}

variable "region" {
  description = "AWS region (used for VPC endpoint service names)."
  type        = string
}

variable "cidr" {
  description = "VPC CIDR block. /16 gives room for /20 private subnets per AZ."
  type        = string
  default     = "10.20.0.0/16"
  validation {
    condition     = can(cidrhost(var.cidr, 0))
    error_message = "cidr must be a valid IPv4 CIDR block."
  }
}

variable "az_count" {
  description = "Number of availability zones to span."
  type        = number
  default     = 3
  validation {
    condition     = var.az_count >= 2 && var.az_count <= 4
    error_message = "Use 2-4 AZs (production should use at least 3)."
  }
}

variable "single_nat_gateway" {
  description = "One NAT gateway for all AZs (cheap, for dev) instead of one per AZ (HA, for prod)."
  type        = bool
  default     = false
}

variable "cluster_name" {
  description = "EKS cluster name, used for subnet discovery tags."
  type        = string
}

variable "flow_log_retention_days" {
  description = "CloudWatch retention for VPC flow logs."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
