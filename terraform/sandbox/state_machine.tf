# sandbox-run (docs/sandbox-spec.md §7): one execution per run. Step
# Functions waits on the tasks; no Lambda ever does.
#
#   Prepare -> [Fetch] -> Execute -> Reap -> Collect
#
# Fetch and Execute catch everything and carry on, so Reap and Collect always
# run: a task that failed or timed out is still a task to stop and a result
# to read, and the leak test wants to see both phases even when one breaks.
#
# Input: {"kind": "leak-test" | "sleep", "phases": ["fetch", "execute"],
#         "timeout_seconds": 300}

locals {
  run_task = {
    for phase in ["fetch", "execute"] : phase => {
      Type     = "Task"
      Resource = "arn:aws:states:::ecs:runTask.sync"
      Parameters = {
        Cluster         = aws_ecs_cluster.sandbox.arn
        TaskDefinition  = aws_ecs_task_definition.phase[phase].arn
        LaunchType      = "FARGATE"
        PlatformVersion = "1.4.0"
        # How reap finds this run's tasks, whatever happened to this state.
        # (The integration does not accept StartedBy; Group it does, and
        # DescribeTasks reports it.)
        "Group.$" = "$.prepared.group"
        NetworkConfiguration = {
          AwsvpcConfiguration = {
            Subnets        = [aws_subnet.sandbox.id]
            SecurityGroups = [local.task_definitions[phase].security_group]
            AssignPublicIp = "DISABLED"
          }
        }
        Overrides = {
          ContainerOverrides = [{
            Name            = local.container_name
            "Environment.$" = "$.prepared.env.${phase}"
          }]
        }
      }
      TimeoutSecondsPath = "$.timeout_seconds"
      # Only fields every stopped task has: a missing one would fail the
      # selector with States.Runtime, which no Catch is sure to see.
      ResultSelector = {
        "task_arn.$"   = "$.TaskArn"
        "containers.$" = "$.Containers"
      }
      ResultPath = "$.tasks.${phase}"
      Catch = [{
        ErrorEquals = ["States.ALL"]
        ResultPath  = "$.errors.${phase}"
        Next        = phase == "fetch" ? "ExecuteWanted" : "Reap"
      }]
      Next = phase == "fetch" ? "ExecuteWanted" : "Reap"
    }
  }

  lambda_retry = {
    ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
    IntervalSeconds = 2
    MaxAttempts     = 3
    BackoffRate     = 2
  }

  sandbox_run_definition = {
    Comment = "One sandbox run: presign, fetch, execute, stop leftovers, read the result as hostile input."
    StartAt = "Prepare"
    States = {
      Prepare = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.dispatch.arn
          Payload = {
            action              = "prepare"
            "kind.$"            = "$.kind"
            "phases.$"          = "$.phases"
            "timeout_seconds.$" = "$.timeout_seconds"
          }
        }
        # The Lambda returns the run's whole initial state: {prepared,
        # timeout_seconds, tasks: {}, errors: {}}. The empty maps are there
        # so Collect's paths resolve whichever states ran.
        OutputPath = "$.Payload"
        Retry      = [local.lambda_retry]
        Next       = "FetchWanted"
      }
      FetchWanted = {
        Type    = "Choice"
        Choices = [{ Variable = "$.prepared.run_fetch", BooleanEquals = true, Next = "Fetch" }]
        Default = "ExecuteWanted"
      }
      Fetch = local.run_task["fetch"]
      ExecuteWanted = {
        Type    = "Choice"
        Choices = [{ Variable = "$.prepared.run_execute", BooleanEquals = true, Next = "Execute" }]
        Default = "Reap"
      }
      Execute = local.run_task["execute"]
      Reap = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.dispatch.arn
          Payload = {
            action    = "reap"
            "group.$" = "$.prepared.group"
          }
        }
        ResultSelector = { "reaped.$" = "$.Payload" }
        ResultPath     = "$.reap"
        Retry          = [local.lambda_retry]
        Next           = "Collect"
      }
      Collect = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.dispatch.arn
          Payload = {
            action     = "collect"
            "run_id.$" = "$.prepared.run_id"
            "kind.$"   = "$.prepared.kind"
            "phases.$" = "$.prepared.phases"
            "tasks.$"  = "$.tasks"
            "errors.$" = "$.errors"
            "reap.$"   = "$.reap.reaped"
          }
        }
        OutputPath = "$.Payload"
        Retry      = [local.lambda_retry]
        End        = true
      }
    }
  }
}

data "aws_iam_policy_document" "states_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sandbox_run" {
  name               = "${local.name}-run"
  assume_role_policy = data.aws_iam_policy_document.states_assume.json
}

data "aws_iam_policy_document" "sandbox_run" {
  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.dispatch.arn]
  }
  statement {
    # Any revision of the two families: a revision is created on every
    # image push, and the state machine names the current one.
    actions = ["ecs:RunTask"]
    resources = [
      for td in aws_ecs_task_definition.phase :
      "arn:aws:ecs:${local.region}:${data.aws_caller_identity.current.account_id}:task-definition/${td.family}:*"
    ]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.sandbox.arn]
    }
  }
  statement {
    actions   = ["ecs:StopTask", "ecs:DescribeTasks"]
    resources = ["arn:aws:ecs:${local.region}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.sandbox.name}/*"]
  }
  statement {
    # Passing the agent's role, never a task role: there is none to pass.
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.execution.arn]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
  statement {
    # How .sync learns that a task stopped: a managed EventBridge rule.
    actions   = ["events:PutTargets", "events:PutRule", "events:DescribeRule"]
    resources = ["arn:aws:events:${local.region}:${data.aws_caller_identity.current.account_id}:rule/StepFunctionsGetEventsForECSTaskRule"]
  }
}

resource "aws_iam_role_policy" "sandbox_run" {
  role   = aws_iam_role.sandbox_run.id
  policy = data.aws_iam_policy_document.sandbox_run.json
}

resource "aws_sfn_state_machine" "sandbox_run" {
  name       = "${local.name}-run"
  role_arn   = aws_iam_role.sandbox_run.arn
  type       = "STANDARD"
  definition = jsonencode(local.sandbox_run_definition)

  depends_on = [aws_iam_role_policy.sandbox_run]
}
