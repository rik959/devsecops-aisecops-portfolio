# Hardened EKS cluster:
#  * Kubernetes Secrets envelope-encrypted with a customer-managed KMS key
#  * API endpoint private by default (public access only from allow-listed CIDRs)
#  * All control-plane log types shipped to CloudWatch
#  * Access via EKS access entries (no aws-auth ConfigMap)
#  * Managed nodes in private subnets, IMDSv2 enforced (hop limit 1 blocks pod -> IMDS credential theft)
#  * IRSA OIDC provider + EKS Pod Identity agent for per-workload IAM

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# ---- KMS for Kubernetes secrets --------------------------------------------
data "aws_iam_policy_document" "eks_kms" {
  # checkov:skip=CKV_AWS_111: "*" in a key policy refers to this key only; root admin is the AWS default
  # checkov:skip=CKV_AWS_356: same as above
  # checkov:skip=CKV_AWS_109: same as above
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
  statement {
    sid       = "EksControlPlane"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey", "kms:CreateGrant"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.cluster.arn]
    }
  }
}

resource "aws_kms_key" "eks" {
  description             = "${var.cluster_name} Kubernetes secrets envelope encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.eks_kms.json
  tags                    = var.tags
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${var.cluster_name}-secrets"
  target_key_id = aws_kms_key.eks.key_id
}

# ---- Control plane IAM -----------------------------------------------------
data "aws_iam_policy_document" "cluster_assume" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name               = "${var.cluster_name}-cluster"
  assume_role_policy = data.aws_iam_policy_document.cluster_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
  tags              = var.tags
}

resource "aws_security_group" "cluster" {
  name        = "${var.cluster_name}-cluster"
  description = "EKS control plane additional SG"
  vpc_id      = var.vpc_id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "cluster_from_nodes" {
  security_group_id            = aws_security_group.cluster.id
  referenced_security_group_id = aws_security_group.node.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "Nodes to API server"
}

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  version  = var.kubernetes_version
  role_arn = aws_iam_role.cluster.arn

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  vpc_config {
    subnet_ids              = var.control_plane_subnet_ids
    security_group_ids      = [aws_security_group.cluster.id]
    endpoint_private_access = true
    endpoint_public_access  = length(var.public_access_cidrs) > 0
    public_access_cidrs     = length(var.public_access_cidrs) > 0 ? var.public_access_cidrs : null
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks.arn
    }
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  tags       = var.tags
  depends_on = [aws_iam_role_policy_attachment.cluster, aws_cloudwatch_log_group.cluster]
}

# ---- Access entries (replace aws-auth ConfigMap) -----------------------------
resource "aws_eks_access_entry" "admins" {
  for_each      = toset(var.admin_role_arns)
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "admins" {
  for_each      = toset(var.admin_role_arns)
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  policy_arn    = "arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope {
    type = "cluster"
  }
  depends_on = [aws_eks_access_entry.admins]
}

# ---- IRSA OIDC provider -----------------------------------------------------
data "tls_certificate" "oidc" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "this" {
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.oidc.certificates[0].sha1_fingerprint]
  tags            = var.tags
}

# ---- Managed node group ---------------------------------------------------------
data "aws_iam_policy_document" "node_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name               = "${var.cluster_name}-node"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each = toset([
    "AmazonEKSWorkerNodePolicy",
    "AmazonEC2ContainerRegistryReadOnly",
    "AmazonSSMManagedInstanceCore", # SSM Session Manager instead of SSH keys
  ])
  role       = aws_iam_role.node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/${each.value}"
}

resource "aws_security_group" "node" {
  name        = "${var.cluster_name}-node"
  description = "EKS managed nodes"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { "karpenter.sh/discovery" = var.cluster_name })
}

resource "aws_vpc_security_group_ingress_rule" "node_self" {
  security_group_id            = aws_security_group.node.id
  referenced_security_group_id = aws_security_group.node.id
  ip_protocol                  = "-1"
  description                  = "Node to node (pod networking)"
}

resource "aws_vpc_security_group_ingress_rule" "node_from_cluster" {
  # checkov:skip=CKV_AWS_25: source is the EKS cluster security group, not 0.0.0.0/0
  security_group_id            = aws_security_group.node.id
  referenced_security_group_id = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 1025
  to_port                      = 65535
  description                  = "Control plane to kubelet / webhooks"
}

resource "aws_vpc_security_group_egress_rule" "node_all" {
  security_group_id = aws_security_group.node.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Egress via NAT (tighten with an egress proxy / Network Firewall in prod)"
}

resource "aws_launch_template" "node" {
  name_prefix            = "${var.cluster_name}-node-"
  vpc_security_group_ids = [aws_security_group.node.id, aws_eks_cluster.this.vpc_config[0].cluster_security_group_id]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1          # pods cannot reach node credentials
  }

  block_device_mappings {
    device_name = "/dev/xvdb" # Bottlerocket data volume (containers, images)
    ebs {
      volume_size           = var.node_disk_gb
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(var.tags, { Name = "${var.cluster_name}-node" })
  }
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "default"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.node_subnet_ids
  ami_type        = "BOTTLEROCKET_x86_64" # minimal, immutable, SELinux-enforcing OS
  capacity_type   = var.node_capacity_type
  instance_types  = var.node_instance_types

  scaling_config {
    min_size     = var.node_min
    desired_size = var.node_desired
    max_size     = var.node_max
  }

  update_config {
    max_unavailable_percentage = 33
  }

  launch_template {
    id      = aws_launch_template.node.id
    version = aws_launch_template.node.latest_version
  }

  labels = { "workload-tier" = "general" }
  tags   = var.tags

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size] # owned by the autoscaler
  }

  depends_on = [aws_iam_role_policy_attachment.node]
}

# ---- Add-ons ---------------------------------------------------------------------
resource "aws_eks_addon" "this" {
  for_each                    = toset(["vpc-cni", "coredns", "kube-proxy", "eks-pod-identity-agent"])
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.value
  resolve_conflicts_on_update = "OVERWRITE"
  depends_on                  = [aws_eks_node_group.default]
  tags                        = var.tags
}
