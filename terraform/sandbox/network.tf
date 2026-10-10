# The sandbox's network (docs/sandbox-spec.md §5): one private subnet with no
# internet gateway and no NAT, so there is no route out at all. What a task
# can reach is the VPC endpoints below, and only the ones its security group
# allows. The leak test (lambda/sandbox-dispatch/leak.py) is what says this
# file does what it claims; read it as the specification of this one.

resource "aws_vpc" "sandbox" {
  cidr_block = "10.42.0.0/24"
  # Both are needed for the interface endpoints' private DNS: a task resolves
  # logs.us-east-1.amazonaws.com and gets the endpoint's address, not AWS's.
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = local.name }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# One AZ (spec §5): every interface endpoint is charged per AZ, and a
# sandbox run that fails because its AZ is down is retried, not lost.
resource "aws_subnet" "sandbox" {
  vpc_id            = aws_vpc.sandbox.id
  cidr_block        = "10.42.0.0/25"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = { Name = local.name }
}

# The local route and the S3 gateway endpoint's prefix-list route, which the
# endpoint adds itself. Nothing else, ever: a 0.0.0.0/0 here is the whole
# containment gone.
resource "aws_route_table" "sandbox" {
  vpc_id = aws_vpc.sandbox.id
  tags   = { Name = local.name }
}

resource "aws_route_table_association" "sandbox" {
  subnet_id      = aws_subnet.sandbox.id
  route_table_id = aws_route_table.sandbox.id
}

# The default security group allows all egress and all traffic from itself.
# Nothing uses it, and nothing should be able to by omission.
resource "aws_default_security_group" "sandbox" {
  vpc_id = aws_vpc.sandbox.id
}

# --- Security groups -------------------------------------------------------
#
# Task to endpoint on 443, and nothing else. Both task groups need the agent
# endpoints (ECR to pull the image, Logs to ship stdout) because on Fargate
# platform 1.4 that traffic leaves through the task's own interface. The code
# in the task can reach them too, and holds no credentials to use them with.

resource "aws_security_group" "execute" {
  name        = "${local.name}-execute"
  description = "Sandbox execute task: agent endpoints and the S3 gateway only"
  vpc_id      = aws_vpc.sandbox.id
}

resource "aws_security_group" "fetch" {
  name        = "${local.name}-fetch"
  description = "Sandbox fetch task: as execute, plus the CodeArtifact endpoints"
  vpc_id      = aws_vpc.sandbox.id
}

resource "aws_security_group" "agent_endpoints" {
  name        = "${local.name}-agent-endpoints"
  description = "ECR and Logs interface endpoints, reachable from both task groups"
  vpc_id      = aws_vpc.sandbox.id
}

# A separate group so that CodeArtifact accepts the fetch task and nothing
# else: the execute task's egress rule would allow 443 to any endpoint, and
# it is this group's ingress that refuses it.
resource "aws_security_group" "codeartifact_endpoints" {
  name        = "${local.name}-codeartifact-endpoints"
  description = "CodeArtifact interface endpoints, reachable from the fetch task only"
  vpc_id      = aws_vpc.sandbox.id
}

resource "aws_vpc_security_group_egress_rule" "task_to_agent_endpoints" {
  for_each                     = { execute = aws_security_group.execute.id, fetch = aws_security_group.fetch.id }
  security_group_id            = each.value
  referenced_security_group_id = aws_security_group.agent_endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "task_to_s3" {
  for_each          = { execute = aws_security_group.execute.id, fetch = aws_security_group.fetch.id }
  security_group_id = each.value
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "fetch_to_codeartifact" {
  security_group_id            = aws_security_group.fetch.id
  referenced_security_group_id = aws_security_group.codeartifact_endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_ingress_rule" "agent_endpoints_from_task" {
  for_each                     = { execute = aws_security_group.execute.id, fetch = aws_security_group.fetch.id }
  security_group_id            = aws_security_group.agent_endpoints.id
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_ingress_rule" "codeartifact_from_fetch" {
  security_group_id            = aws_security_group.codeartifact_endpoints.id
  referenced_security_group_id = aws_security_group.fetch.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

# --- Endpoints ---------------------------------------------------------------

# Free, so it exists whether or not the sandbox is active. Its policy is the
# containment for S3: a task holds presigned URLs for its own two objects,
# and a URL for any other bucket -- the canary's, say -- goes nowhere.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.sandbox.id
  service_name      = "com.amazonaws.${local.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.sandbox.id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "OwnRuns"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:PutObject"]
        Resource  = "${aws_s3_bucket.sandbox.arn}/runs/*"
      },
      {
        # ECR serves image layers out of this AWS-owned bucket; without it
        # no task can start. Read-only, and AWS's, not anyone's data.
        Sid       = "EcrLayers"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject"]
        Resource  = "arn:aws:s3:::prod-${local.region}-starport-layer-bucket/*"
      },
      {
        # CodeArtifact keeps package assets in an AWS-owned bucket per
        # region; the fetch task's downloads come from it. The account id is
        # AWS's, from the CodeArtifact VPC documentation for us-east-1 --
        # the leak test's tarball control fails if it is wrong.
        Sid       = "CodeArtifactAssets"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject"]
        Resource  = "arn:aws:s3:::assets-193858265520-${local.region}/*"
      },
    ]
  })

  tags = { Name = "${local.name}-s3" }
}

locals {
  # What the Fargate agent needs to start a task in a subnet with no route
  # out: ECR (image manifest and auth) and Logs (the awslogs driver). Image
  # layers come over the S3 gateway above.
  agent_endpoints = {
    ecr_api = "ecr.api"
    ecr_dkr = "ecr.dkr"
    logs    = "logs"
  }
  codeartifact_endpoints = {
    codeartifact_api          = "codeartifact.api"
    codeartifact_repositories = "codeartifact.repositories"
  }
}

resource "aws_vpc_endpoint" "agent" {
  for_each            = local.active ? local.agent_endpoints : {}
  vpc_id              = aws_vpc.sandbox.id
  service_name        = "com.amazonaws.${local.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.sandbox.id]
  security_group_ids  = [aws_security_group.agent_endpoints.id]

  tags = { Name = "${local.name}-${each.key}" }
}

resource "aws_vpc_endpoint" "codeartifact" {
  for_each            = local.active ? local.codeartifact_endpoints : {}
  vpc_id              = aws_vpc.sandbox.id
  service_name        = "com.amazonaws.${local.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.sandbox.id]
  security_group_ids  = [aws_security_group.codeartifact_endpoints.id]

  tags = { Name = "${local.name}-${each.key}" }
}

# --- DNS Firewall ------------------------------------------------------------
#
# The VPC resolver answers for any public name, and a lookup is a way out
# even with no route: the query for <data>.attacker.example reaches the
# attacker's nameserver. So the resolver answers only for the names the
# agent and the fetch task need, and NXDOMAIN for everything else.
# Fail-closed: if the firewall cannot be evaluated, the query is refused.
#
# Always on, not behind `active` (changed 2026-10-10). It bills per query and
# per stored domain, nothing hourly, so idle it costs nothing -- and
# switching it with the endpoints went wrong: a `down` removed the
# association and left the rule group, the next `up` recreated the rules
# and not the association, and the leak test ran with the firewall
# detached (dns.example.com resolved). A VPC that is never without its
# firewall is also simply the safer default.

resource "aws_route53_resolver_firewall_domain_list" "allowed" {
  name = "${local.name}-allowed"
  # Fully qualified, trailing dot included: that is how the service stores
  # them, and anything else is a diff on every plan.
  domains = [
    "api.ecr.${local.region}.amazonaws.com.",
    "*.dkr.ecr.${local.region}.amazonaws.com.",
    "logs.${local.region}.amazonaws.com.",
    # S3, regional and global forms: presigned URLs are regional, but ECR's
    # layer redirect and CodeArtifact's assets may use either. Every name
    # under these is answered by AWS, not by whoever owns a bucket.
    "s3.${local.region}.amazonaws.com.",
    "*.s3.${local.region}.amazonaws.com.",
    "s3.amazonaws.com.",
    "*.s3.amazonaws.com.",
    "codeartifact.${local.region}.amazonaws.com.",
    "*.d.codeartifact.${local.region}.amazonaws.com.",
  ]
}

resource "aws_route53_resolver_firewall_domain_list" "everything" {
  name    = "${local.name}-everything"
  domains = ["*."]
}

resource "aws_route53_resolver_firewall_rule_group" "sandbox" {
  name = local.name
}

resource "aws_route53_resolver_firewall_rule" "allow" {
  name   = "allow-endpoints"
  action = "ALLOW"
  # By default the firewall also judges every name a lookup is redirected
  # to, and every allowed name redirects: an endpoint's private DNS name
  # aliases to vpce-....vpce.amazonaws.com, an S3 name to S3's own. Judged
  # one by one they are all refused, and no task can start (found
  # 2026-10-10: ECR auth and the layer bucket both "no such host"). Trusting
  # the redirect is safe here because every allowed name is AWS's, so
  # only AWS decides where it points.
  firewall_domain_redirection_action = "TRUST_REDIRECTION_DOMAIN"
  firewall_domain_list_id            = aws_route53_resolver_firewall_domain_list.allowed.id
  firewall_rule_group_id             = aws_route53_resolver_firewall_rule_group.sandbox.id
  priority                           = 100
}

resource "aws_route53_resolver_firewall_rule" "block" {
  name                    = "block-everything-else"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.everything.id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.sandbox.id
  priority                = 200
}

resource "aws_route53_resolver_firewall_rule_group_association" "sandbox" {
  name                   = local.name
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.sandbox.id
  vpc_id                 = aws_vpc.sandbox.id
  priority               = 101
}

resource "aws_route53_resolver_firewall_config" "sandbox" {
  resource_id        = aws_vpc.sandbox.id
  firewall_fail_open = "DISABLED"
}

# The firewall used to be counted with `active`; these keep whatever of it
# survived in state rather than destroying and recreating it.
moved {
  from = aws_route53_resolver_firewall_domain_list.allowed[0]
  to   = aws_route53_resolver_firewall_domain_list.allowed
}
moved {
  from = aws_route53_resolver_firewall_domain_list.everything[0]
  to   = aws_route53_resolver_firewall_domain_list.everything
}
moved {
  from = aws_route53_resolver_firewall_rule_group.sandbox[0]
  to   = aws_route53_resolver_firewall_rule_group.sandbox
}
moved {
  from = aws_route53_resolver_firewall_rule.allow[0]
  to   = aws_route53_resolver_firewall_rule.allow
}
moved {
  from = aws_route53_resolver_firewall_rule.block[0]
  to   = aws_route53_resolver_firewall_rule.block
}
moved {
  from = aws_route53_resolver_firewall_rule_group_association.sandbox[0]
  to   = aws_route53_resolver_firewall_rule_group_association.sandbox
}
