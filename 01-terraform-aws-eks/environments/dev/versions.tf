terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.74"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Remote state: versioned + encrypted S3 bucket, native S3 locking (Terraform >= 1.10),
  # so no DynamoDB lock table is needed. Create the bucket once, then: terraform init.
  backend "s3" {
    bucket       = "CHANGE-ME-tfstate-secure-ai"
    key          = "dev/terraform.tfstate"
    region       = "eu-central-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      cost_center = "platform"
    }
  }
}
