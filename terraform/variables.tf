variable "cdk_synthesis" {
  description = "Whether a GitHub run synthesizes the CDK apps it finds in the sandbox (docs/sandbox-spec.md §9 step 2). Needs terraform/sandbox applied; while the sandbox is switched off, apps are reported as not synthesized. Off, they are reported as not enabled and nothing is called."
  type        = bool
  default     = false
}

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name (e.g. dev, prod)"
  type        = string
  default     = "dev"
}

variable "project" {
  description = "Project name, used as a resource-naming prefix"
  type        = string
  default     = "iacposture"
}

variable "mapping_agent_model" {
  description = "Anthropic model ID for mapping-agent. Haiku since 2026-11-21: the mapping eval (corpus/eval/README.md) gave the same 181 of 181 on it as on claude-opus-5, at about a 44th of the cost, because the corpus offers each rule only controls that are right for every finding it raises. Re-run that eval before changing it."
  type        = string
  default     = "claude-haiku-5-5"
}

variable "remediation_agent_model" {
  description = "Anthropic model ID for remediation-agent. Sonnet since 2026-11-22: one run each on an 11-case subset (docs/completion.md, phase 2 step 2) found its fixes as good as claude-opus-5's in all but one held draft, at about a third of the remediation cost, while claude-opus-5-5 cost more than either. Sonnet states fewer assumptions, and the gates hold only what is stated, so the fix eval must count passed fixes that should have been held. Re-run that comparison before changing it."
  type        = string
  default     = "claude-sonnet-5-5"
}

variable "context_agent_model" {
  description = "Anthropic model ID for context-agent. Defaults to Opus: reading a repository to answer a question with a correct citation is closer to remediation's task than to mapping's. Override to trade answer quality for cost."
  type        = string
  default     = "claude-opus-5"
}

variable "alarm_email" {
  description = "Address to subscribe to the alarms SNS topic. SNS emails a confirmation link that must be clicked before anything is delivered; until then the alarms still fire, they just reach nobody. Leave null to create the topic with no subscriber."
  type        = string
  default     = null
}

variable "dashboard_extra_origins" {
  description = "Origins allowed to call the review API and complete a Cognito login, in addition to the CloudFront distribution (which is always allowed). Defaults to the Vite dev server so `npm run dev` works against deployed infrastructure; set to [] for an environment that should only be reachable through CloudFront. Note these are browser conventions, not access control -- the JWT authorizer in api_gateway.tf is what actually gates the API."
  type        = list(string)
  default     = ["http://localhost:5173"]
}

variable "remediation_concurrency" {
  description = "How many files the pipeline remediates at once (the Map state's MaxConcurrency). Each iteration is a stream of model calls plus a scanner invocation per finding, so this bounds Anthropic API throughput and concurrent scanner cold starts rather than Lambda capacity."
  type        = number
  default     = 4
}

variable "max_drafts_per_file" {
  description = "How many fixes one pipeline run may draft for one file (remediation-agent's MAX_DRAFTS_PER_FILE). Superseded findings cost nothing and do not count. Past the budget a finding is written not-drafted with the reason and picked up by the next run. Sized from measurement (multi-iac-spec §5): a Kubernetes Deployment's ~22 mapped findings need ~5 distinct edits when the model drafts a block completely, ~16 when it drafts one field at a time; 8 is the backstop between the two, not the expected path."
  type        = number
  default     = 8
}

variable "github_app_id" {
  description = "The CascadeSec GitHub App's App ID (App settings -> General -> About). The issuer of the JWT github-gateway signs with KMS. Not a secret -- it is useless without the private key -- but the App is private to its account, so it cannot be looked up and must be given, e.g. `terraform apply -var github_app_id=123456`."
  type        = string
}

variable "github_app_key_alias" {
  description = "KMS alias of the App's private key, as created by scripts/import_github_app_key.py. Terraform only looks the key up: the provider cannot create a key with imported material, and the material should not pass through state (docs/ci-integration-spec.md §4.1)."
  type        = string
  default     = "alias/iacposture-dev-github-app"
}

variable "github_writer_app_id" {
  description = "App ID of the write-back App, \"CascadeSec Fixes\" (docs/write-back-spec.md §4): Contents write, no webhooks, installed per repository. Null leaves write-back undeployed -- no github-committer, and review-api answers a commit request with 503 -- so this can be applied before the App is registered and its key imported."
  type        = string
  default     = null
}

variable "github_writer_app_key_alias" {
  description = "KMS alias of the write-back App's private key, imported with scripts/import_github_app_key.py --alias. Only github-committer can sign with it; github-gateway's key stays read-and-report."
  type        = string
  default     = "alias/iacposture-dev-github-app-writer"
}
