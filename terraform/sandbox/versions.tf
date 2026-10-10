# The sandbox (docs/sandbox-spec.md) is its own Terraform root, with its own
# state, beside the main stack in terraform/. Two reasons:
#
#   - It is applied only while in use (spec §10, decided 2026-10-09), and
#     turning it on or off should never be an apply of the main stack, which
#     needs the GitHub App variables every time and holds everything else.
#   - Nothing in it depends on the main stack yet. When the pipeline starts
#     calling it (spec §9 step 2), it will do so by name, and a pipeline run
#     while the sandbox is down reports that rather than failing to plan.
#
# `active` is the switch. Off, the root keeps only what costs nothing while
# idle; on, it adds the interface endpoints (network.tf). DNS Firewall stays
# on either way.
terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      Component   = "sandbox"
      ManagedBy   = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name   = "${var.project}-${var.environment}-sandbox"
  region = data.aws_region.current.name
  # Every interface endpoint exists only while active; nothing else does.
  active = var.active
}
