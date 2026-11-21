locals {
  name = "${var.project}-${var.environment}"
  tags = {
    project     = var.project
    environment = var.environment
    managed_by  = "terraform"
    repo        = "github.com/rik959/devsecops-aisecops-portfolio"
  }
}

module "vpc" {
  source             = "../../modules/vpc"
  name               = local.name
  region             = var.region
  cidr               = var.vpc_cidr
  az_count           = 3
  single_nat_gateway = true # dev cost saving; prod uses one NAT per AZ
  cluster_name       = local.name
  tags               = local.tags
}

module "eks" {
  source                   = "../../modules/eks"
  cluster_name             = local.name
  kubernetes_version       = var.kubernetes_version
  vpc_id                   = module.vpc.vpc_id
  control_plane_subnet_ids = module.vpc.intra_subnet_ids
  node_subnet_ids          = module.vpc.private_subnet_ids
  public_access_cidrs      = var.api_allowed_cidrs
  admin_role_arns          = var.admin_role_arns
  node_capacity_type       = "SPOT" # dev: interruption-tolerant, ~70% cheaper
  node_min                 = 2
  node_desired             = 2
  node_max                 = 5
  tags                     = local.tags
}

# ---- Container registry: immutable tags, scan on push, KMS-encrypted ------------
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "ecr_kms" {
  # checkov:skip=CKV_AWS_111: "*" in a key policy refers to this key only; root admin is the AWS default
  # checkov:skip=CKV_AWS_356: same as above
  # checkov:skip=CKV_AWS_109: same as above
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "ecr" {
  description         = "${local.name} ECR encryption"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.ecr_kms.json
  tags                = local.tags
}

resource "aws_ecr_repository" "app" {
  for_each             = toset(["llm-security-gateway", "login-risk-model"])
  name                 = "${var.project}/${each.value}"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
  tags = local.tags
}

resource "aws_ecr_lifecycle_policy" "app" {
  for_each   = aws_ecr_repository.app
  repository = each.value.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Expire untagged images after 14 days"
      selection    = { tagStatus = "untagged", countType = "sinceImagePushed", countUnit = "days", countNumber = 14 }
      action       = { type = "expire" }
    }]
  })
}

# ---- GitHub Actions -> AWS via OIDC (no long-lived access keys in CI) -------------
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
  tags            = local.tags
}

data "aws_iam_policy_document" "github_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Only the main branch of this repo may assume the role.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "github_ci" {
  name                 = "${local.name}-github-ci"
  assume_role_policy   = data.aws_iam_policy_document.github_assume.json
  max_session_duration = 3600
  tags                 = local.tags
}

data "aws_iam_policy_document" "github_ci" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid = "EcrPush"
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage", "ecr:DescribeImages",
    ]
    resources = [for r in aws_ecr_repository.app : r.arn]
  }
}

resource "aws_iam_role_policy" "github_ci" {
  role   = aws_iam_role.github_ci.id
  policy = data.aws_iam_policy_document.github_ci.json
}
