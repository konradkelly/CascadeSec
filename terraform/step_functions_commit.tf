# The commit state machine (docs/github-first-review-spec.md §3.4): what a
# Commit fixes click on the CascadeSec check run starts.
#
# webhook-receiver can start executions and do nothing else, and that stays
# true: it gains StartExecution on this machine, not an invoke of the
# committer or a table write. The machine asks github-committer to commit
# the offer the clicked check run showed, and waits for the answer, then
# hands the answer to github-gateway to report on the PR. The writer App
# holds Contents write and no Checks permission, so the committer cannot
# report there itself, and should not be given one.
#
# Input (webhook-receiver's build_commit_input):
#   { pr_id, check_run_id, sender: {login, id}, github: {...} }
# The execution name is (PR, check run, "commit"): a redelivered webhook or
# a second click on the same check run starts nothing.

locals {
  commit_machine_name = "${var.project}-${var.environment}-commit"

  commit_definition = {
    Comment = "A Commit fixes click: commit the clicked check run's offer as github-committer, then report the outcome on the PR as github-gateway."
    StartAt = "Commit"
    States = {
      # Synchronous: the outcome is what Report needs. The committer is
      # written for retries (a claimed request is checked against the
      # branch for its own trailer before anything is redone), so a
      # transient failure is retried like any other stage's.
      Commit = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.lambda_function_names.github_committer}"
          Payload = {
            source             = "github"
            "pr_id.$"          = "$.pr_id"
            "check_run_id.$"   = "$.check_run_id"
            "sender.$"         = "$.sender"
            "github.$"         = "$.github"
            "clicked_at.$"     = "$$.Execution.StartTime"
            "execution_name.$" = "$$.Execution.Name"
          }
        }
        ResultSelector = { "result.$" = "$.Payload" }
        ResultPath     = "$.commit"
        Retry          = [local.transient_retry]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          ResultPath  = "$.error"
          Next        = "MarkFailed"
        }]
        Next = "Report"
      }

      # The committer raised past its retries. Its request would sit at
      # "committing" and nothing on the PR would say so: the committer
      # marks it failed -- it finds the request by the same click, since
      # the request id is derived from it -- and Report still runs.
      MarkFailed = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.lambda_function_names.github_committer}"
          Payload = {
            action           = "mark_failed"
            source           = "github"
            "pr_id.$"        = "$.pr_id"
            "check_run_id.$" = "$.check_run_id"
            "sender.$"       = "$.sender"
            "github.$"       = "$.github"
            "clicked_at.$"   = "$$.Execution.StartTime"
            "error.$"        = "$.error"
          }
        }
        ResultSelector = { "result.$" = "$.Payload" }
        ResultPath     = "$.commit"
        Retry          = [local.transient_retry]
        Next           = "Report"
      }

      # Code-produced text only: the outcome per file, the commit link, and
      # who clicked.
      Report = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.github_gateway.arn
          Payload = {
            action           = "report_commit"
            "pr_id.$"        = "$.pr_id"
            "check_run_id.$" = "$.check_run_id"
            "sender.$"       = "$.sender"
            "github.$"       = "$.github"
            "commit.$"       = "$.commit.result"
          }
        }
        ResultPath = null
        Retry      = [local.transient_retry]
        End        = true
      }
    }
  }
}

resource "aws_iam_role" "commit_machine" {
  count              = local.write_back_enabled ? 1 : 0
  name               = "${local.commit_machine_name}-role"
  assume_role_policy = data.aws_iam_policy_document.states_assume_role.json
}

data "aws_iam_policy_document" "commit_machine" {
  count = local.write_back_enabled ? 1 : 0

  # The committer and the gateway's report, nothing else. No table access:
  # the committer records the request itself.
  statement {
    sid     = "InvokeCommitterAndReport"
    actions = ["lambda:InvokeFunction"]
    resources = [
      aws_lambda_function.github_committer[0].arn,
      aws_lambda_function.github_gateway.arn,
    ]
  }
  statement {
    sid = "LogDelivery"
    actions = [
      "logs:CreateLogDelivery",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "XRayWrite"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "commit_machine" {
  count  = local.write_back_enabled ? 1 : 0
  name   = "${local.commit_machine_name}-policy"
  role   = aws_iam_role.commit_machine[0].id
  policy = data.aws_iam_policy_document.commit_machine[0].json
}

resource "aws_cloudwatch_log_group" "commit_machine" {
  count             = local.write_back_enabled ? 1 : 0
  name              = "/aws/vendedlogs/states/${local.commit_machine_name}"
  retention_in_days = 14
}

resource "aws_sfn_state_machine" "commit" {
  count    = local.write_back_enabled ? 1 : 0
  name     = local.commit_machine_name
  role_arn = aws_iam_role.commit_machine[0].arn
  type     = "STANDARD"

  definition = jsonencode(local.commit_definition)

  tracing_configuration {
    enabled = true
  }

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.commit_machine[0].arn}:*"
    include_execution_data = false
    level                  = "ERROR"
  }

  depends_on = [aws_iam_role_policy.commit_machine]
}

# A failed commit execution is a click nobody was told the outcome of.
resource "aws_cloudwatch_metric_alarm" "commit_machine_failed" {
  count               = local.write_back_enabled ? 1 : 0
  alarm_name          = "${local.commit_machine_name}-failed"
  alarm_description   = "a Commit fixes execution failed; the PR may show no outcome for the click"
  namespace           = "AWS/States"
  metric_name         = "ExecutionsFailed"
  dimensions          = { StateMachineArn = aws_sfn_state_machine.commit[0].arn }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]
}
