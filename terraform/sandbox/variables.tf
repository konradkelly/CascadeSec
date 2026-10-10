variable "aws_region" {
  description = "AWS region to deploy into. Must match the main stack's only once the pipeline calls the sandbox."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name (e.g. dev)"
  type        = string
  default     = "dev"
}

variable "project" {
  description = "Project name, used as a resource-naming prefix"
  type        = string
  default     = "iacposture"
}

variable "active" {
  description = "Whether the sandbox can run anything. True adds the five interface endpoints (~$0.05/hour together); false removes them and leaves only what costs nothing while idle. Tasks cannot start while false: there is no route to ECR. scripts/sandbox.py up/down flips it (docs/sandbox-spec.md §10)."
  type        = bool
  default     = false
}

variable "task_cpu" {
  description = "Fargate CPU units for both task definitions. 1024 = 1 vCPU."
  type        = number
  default     = 1024
}

variable "task_memory" {
  description = "Fargate memory (MiB) for both task definitions."
  type        = number
  default     = 2048
}
