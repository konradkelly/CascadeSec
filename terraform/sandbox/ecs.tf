# The tasks themselves (docs/sandbox-spec.md §3, §4). Two task definitions on
# one image: fetch (CodeArtifact reachable, no user code) and execute (no
# route anywhere). Neither has a task role -- that absence is the point of
# choosing Fargate, and `task_role_arn` must never be set here.

resource "aws_ecs_cluster" "sandbox" {
  name = local.name
}

resource "aws_ecr_repository" "node22" {
  name                 = "${local.name}-node22"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "node22" {
  repository = aws_ecr_repository.node22.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep the last 5 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = { type = "expire" }
    }]
  })
}

# As for the scanner: `latest` resolved to a digest at plan time, so a task
# runs exactly the image the plan showed. First deploy, in order:
#   terraform -chdir=terraform/sandbox apply -target=aws_ecr_repository.node22
#   sandbox/image/build-image.sh
#   terraform -chdir=terraform/sandbox apply
data "aws_ecr_image" "node22" {
  repository_name = aws_ecr_repository.node22.name
  image_tag       = "latest"
}

resource "aws_cloudwatch_log_group" "tasks" {
  name              = "/ecs/${local.name}"
  retention_in_days = 7
}

# The execution role is the Fargate agent's, not the task's: it pulls the
# image and ships the logs, and the code in the container never sees it.
data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

data "aws_iam_policy_document" "execution" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = [aws_ecr_repository.node22.arn]
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.tasks.arn}:*"]
  }
}

resource "aws_iam_role_policy" "execution" {
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

locals {
  # The container name sandbox-run's Overrides address.
  container_name = "job"

  task_definitions = {
    fetch   = { security_group = aws_security_group.fetch.id }
    execute = { security_group = aws_security_group.execute.id }
  }
}

resource "aws_ecs_task_definition" "phase" {
  for_each = local.task_definitions

  family                   = "${local.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  # No task_role_arn. Without one there is no credentials endpoint in the
  # container and no AWS credentials anywhere in it (spec §3).

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  # Scratch space, writable, on the task's ephemeral storage. The image
  # declares both as VOLUMEs owned by the unprivileged user, so they start
  # empty and writable; everything else is the read-only image.
  volume {
    name = "work"
  }
  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([{
    name      = local.container_name
    image     = "${aws_ecr_repository.node22.repository_url}@${data.aws_ecr_image.node22.image_digest}"
    essential = true

    readonlyRootFilesystem = true
    user                   = "1000:1000"
    # No privileges to gain, nothing to add.
    linuxParameters = {
      capabilities       = { add = [], drop = ["ALL"] }
      initProcessEnabled = true
    }

    # Written out empty because ECS fills them in, and a definition that
    # does not round-trip is replaced on every plan.
    portMappings   = []
    systemControls = []
    volumesFrom    = []

    mountPoints = [
      { sourceVolume = "work", containerPath = "/work", readOnly = false },
      { sourceVolume = "tmp", containerPath = "/tmp", readOnly = false },
    ]

    # The phase is fixed by the task definition, not by the input: a run
    # cannot ask the execute task to behave as fetch.
    environment = [{ name = "SANDBOX_PHASE", value = each.key }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.tasks.name
        awslogs-region        = local.region
        awslogs-stream-prefix = each.key
      }
    }
  }])
}
