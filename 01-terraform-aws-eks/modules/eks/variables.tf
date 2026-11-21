variable "cluster_name" {
  type = string
}

variable "kubernetes_version" {
  type    = string
  default = "1.31"
}

variable "vpc_id" {
  type = string
}

variable "control_plane_subnet_ids" {
  description = "Subnets for control-plane ENIs (intra subnets, no internet route)."
  type        = list(string)
}

variable "node_subnet_ids" {
  description = "Private subnets for worker nodes."
  type        = list(string)
}

variable "public_access_cidrs" {
  description = "CIDRs allowed to reach the public API endpoint. Empty = private endpoint only."
  type        = list(string)
  default     = []
  validation {
    condition     = !contains(var.public_access_cidrs, "0.0.0.0/0")
    error_message = "Refusing to expose the Kubernetes API to 0.0.0.0/0."
  }
}

variable "admin_role_arns" {
  description = "IAM role ARNs granted cluster-admin through EKS access entries."
  type        = list(string)
  default     = []
}

variable "node_instance_types" {
  type    = list(string)
  default = ["m6i.large", "m6a.large", "m5.large"]
}

variable "node_capacity_type" {
  description = "ON_DEMAND or SPOT."
  type        = string
  default     = "ON_DEMAND"
  validation {
    condition     = contains(["ON_DEMAND", "SPOT"], var.node_capacity_type)
    error_message = "node_capacity_type must be ON_DEMAND or SPOT."
  }
}

variable "node_min" {
  type    = number
  default = 2
}

variable "node_desired" {
  type    = number
  default = 3
}

variable "node_max" {
  type    = number
  default = 6
}

variable "node_disk_gb" {
  type    = number
  default = 50
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "log_kms_key_arn" {
  description = "KMS key for the control-plane log group (optional)."
  type        = string
  default     = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
