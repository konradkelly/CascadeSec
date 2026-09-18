# The pipeline: scan -> map -> remediate, as one Step Functions execution per
# PR (spec §4.4 steps 3-5; §8.2 item 5). Until this existed no stage triggered
# the next -- scripts/scan.py made three synchronous invokes in a row, and
# remediation-agent looped over every finding in one 900s invocation.
#
# Step Functions rather than the DynamoDB stream §4.4 also allows, for three
# reasons that are all the same reason. Remediation is chained per file: each
# fix is drafted on the previous verified one, so the unit of fan-out is the
# *file*, and within a file the order matters. A stream delivers per-item
# events with no per-file ordering, no bounded concurrency, and no "this PR
# is done" -- and it would fire on every status write review-api makes, too.
# A Map state over files gives all three, plus an execution you can open in
# the console and see where a PR got to.
#
# Standard, not Express: an execution runs for as long as remediation takes,
# which is minutes per file, and Express caps at five.
#
# Input:  { "pr_id": "...", "s3_prefix": "scans/<pr_id>/", "remediate": true }
#         remediate is optional; false stops after map. There is no type
#         parameter: the scanner reports what it finds, per file.
# Output: the input plus "scan" (finding_count, scan_errors, preserved_count,
#         no_longer_detected_count), "map"
#         (mapped_count, skipped_count, error_count, files) and "remediation" (one entry
#         per file, remediation-agent's final counts for it).

locals {
  pipeline_name = "${var.project}-${var.environment}-pipeline"

  # Errors the Lambda integration raises for reasons that have nothing to do
  # with the function's code: throttling, a transient service fault, a
  # dropped connection. Worth a retry. A function's own exception (a
  # ScannerError, a KeyError) surfaces under its own name and is not in this
  # list -- retrying it would just fail the same way, and for remediation it
  # would spend model calls doing so.
  lambda_transient_errors = [
    "Lambda.ServiceException",
    "Lambda.AWSLambdaException",
    "Lambda.SdkClientException",
    "Lambda.TooManyRequestsException",
  ]
  transient_retry = {
    ErrorEquals     = local.lambda_transient_errors
    IntervalSeconds = 5
    MaxAttempts     = 3
    BackoffRate     = 2
  }

  pipeline_definition = {
    Comment = "IaCPosture v1 pipeline: scan a Terraform snapshot, map findings to controls, remediate one file at a time."
    StartAt = "Scan"
    States = {
      Scan = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.iac_scanner.arn
          Payload = {
            "pr_id.$"     = "$.pr_id"
            "s3_prefix.$" = "$.s3_prefix"
            persist       = true
          }
        }
        # The scanner also returns every finding. They are in DynamoDB
        # already; carrying them in execution state would only push a large
        # PR toward the 256KB state limit.
        ResultSelector = {
          "finding_count.$"            = "$.Payload.finding_count"
          "scan_errors.$"              = "$.Payload.scan_errors"
          "preserved_count.$"          = "$.Payload.preserved_count"
          "no_longer_detected_count.$" = "$.Payload.no_longer_detected_count"
        }
        ResultPath = "$.scan"
        Retry = [
          local.transient_retry,
          # Lambda.Unknown is how a function timeout arrives. For the scanner
          # that is almost always a cold start -- checkov's import alone is
          # 50-100s -- and the retry lands on a warm container. Once: a scan
          # that times out warm is a snapshot too big for the function.
          {
            ErrorEquals     = ["Lambda.Unknown"]
            IntervalSeconds = 10
            MaxAttempts     = 1
          },
        ]
        Next = "MapToControls"
      }

      MapToControls = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.mapping_agent.arn
          Payload = {
            "pr_id.$" = "$.pr_id"
          }
        }
        ResultSelector = {
          "mapped_count.$"  = "$.Payload.mapped_count"
          "skipped_count.$" = "$.Payload.skipped_count"
          "error_count.$"   = "$.Payload.error_count"
          "files.$"         = "$.Payload.files"
        }
        ResultPath = "$.map"
        Retry      = [local.transient_retry]
        Next       = "ShouldRemediate"
      }

      # Remediation is the stage that costs money -- a model call and a
      # self-check scan per finding -- so the input can opt out of it, and
      # there is no point entering the Map with nothing to iterate.
      ShouldRemediate = {
        Type = "Choice"
        Choices = [
          {
            And = [
              { Variable = "$.remediate", IsPresent = true },
              { Variable = "$.remediate", BooleanEquals = false },
            ]
            Next = "SkipRemediation"
          },
          {
            Variable      = "$.map.mapped_count"
            NumericEquals = 0
            Next          = "SkipRemediation"
          },
        ]
        Default = "Remediate"
      }

      SkipRemediation = {
        Type       = "Pass"
        Result     = []
        ResultPath = "$.remediation"
        End        = true
      }

      # One iteration per file. Files are independent of each other -- a fix
      # only ever edits the file its finding is in -- so they can run in
      # parallel; findings within a file cannot, which is why the iteration
      # is the file and the loop over its findings stays inside the handler.
      Remediate = {
        Type           = "Map"
        ItemsPath      = "$.map.files"
        MaxConcurrency = var.remediation_concurrency
        ItemSelector = {
          "pr_id.$" = "$.pr_id"
          "file.$"  = "$$.Map.Item.Value"
        }
        ItemProcessor = {
          ProcessorConfig = { Mode = "INLINE" }
          StartAt         = "RemediateFile"
          States = {
            # The whole state is the payload, and the whole reply is the next
            # state: remediation-agent's output is a continuation token. On
            # the first pass that is {pr_id, file}; after a yield it is that
            # plus the counts so far, `remaining`, and `resume_from`.
            RemediateFile = {
              Type     = "Task"
              Resource = "arn:aws:states:::lambda:invoke"
              Parameters = {
                FunctionName = aws_lambda_function.remediation_agent.arn
                "Payload.$"  = "$"
              }
              OutputPath = "$.Payload"
              # Transient errors only. A timeout (Lambda.Unknown) is not
              # retried: the handler yields before its clock runs out
              # precisely so that never happens, and a retry after it did
              # would re-run from a stale resume point.
              Retry = [local.transient_retry]
              Next  = "MoreInThisFile"
            }
            MoreInThisFile = {
              Type = "Choice"
              Choices = [
                {
                  Variable           = "$.remaining"
                  NumericGreaterThan = 0
                  Next               = "RemediateFile"
                },
              ]
              Default = "FileDone"
            }
            FileDone = {
              Type = "Succeed"
            }
          }
        }
        ResultPath = "$.remediation"
        End        = true
      }
    }
  }
}

# ---------- role ----------

data "aws_iam_policy_document" "states_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "pipeline" {
  name               = "${local.pipeline_name}-role"
  assume_role_policy = data.aws_iam_policy_document.states_assume_role.json
}

data "aws_iam_policy_document" "pipeline" {
  # The three stages, and nothing else -- not review-api, and not the
  # scanner's self-check path (remediation-agent's own role holds that).
  statement {
    sid     = "InvokeStages"
    actions = ["lambda:InvokeFunction"]
    resources = [
      aws_lambda_function.iac_scanner.arn,
      aws_lambda_function.mapping_agent.arn,
      aws_lambda_function.remediation_agent.arn,
    ]
  }
  # Step Functions delivers its logs through a CloudWatch Logs "log
  # delivery", which needs these account-level actions rather than a
  # PutLogEvents on one group. No resource-scoped ARNs exist for them.
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
  # Spec §4.1's end-to-end trace: with tracing on here, the execution is the
  # root segment and each Lambda's Active-mode segment hangs off it.
  statement {
    sid       = "XRayWrite"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "pipeline" {
  name   = "${local.pipeline_name}-policy"
  role   = aws_iam_role.pipeline.id
  policy = data.aws_iam_policy_document.pipeline.json
}

# ---------- state machine ----------

# /aws/vendedlogs/ is the prefix CloudWatch exempts from the resource-policy
# size limit that log deliveries otherwise eat into. Not a style choice.
resource "aws_cloudwatch_log_group" "pipeline" {
  name              = "/aws/vendedlogs/states/${local.pipeline_name}"
  retention_in_days = 14
}

resource "aws_sfn_state_machine" "pipeline" {
  name     = local.pipeline_name
  role_arn = aws_iam_role.pipeline.arn
  type     = "STANDARD"

  definition = jsonencode(local.pipeline_definition)

  tracing_configuration {
    enabled = true
  }

  # ERROR only: the execution history already records every state
  # transition for 90 days, so ALL would duplicate it into a paid log group.
  # The failures are what an alarm and a person need to find.
  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.pipeline.arn}:*"
    include_execution_data = false
    level                  = "ERROR"
  }

  depends_on = [aws_iam_role_policy.pipeline]
}

output "pipeline_state_machine_arn" {
  value = aws_sfn_state_machine.pipeline.arn
}
