output "active" {
  description = "Whether the interface endpoints exist, i.e. whether a run can start."
  value       = local.active
}

output "state_machine_arn" {
  value = aws_sfn_state_machine.sandbox_run.arn
}

output "cluster_arn" {
  value = aws_ecs_cluster.sandbox.arn
}

output "ecr_repository_url" {
  description = "Where sandbox/image/build-image.sh pushes."
  value       = aws_ecr_repository.node22.repository_url
}

output "sandbox_bucket" {
  value = aws_s3_bucket.sandbox.bucket
}

output "task_log_group" {
  value = aws_cloudwatch_log_group.tasks.name
}
