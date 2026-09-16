# A remediation that broke the file it was fixing.
#
# This is vulnerable-sample/main.tf with the security group's SSH ingress
# narrowed -- the correct fix -- but the `ingress` block's closing brace
# dropped along the way, so the file no longer parses.
#
# The shape matters: an agent asked to rewrite a whole file and return it
# fails this way, by losing a brace while editing, not by emitting something
# obviously non-Terraform. Every remaining line reads as a plausible fix.
#
# Unparseable means no findings, and no findings is what a cleared finding
# also looks like -- so this file is the self-check's false-pass case.

resource "aws_s3_bucket" "bad" {
  bucket = "my-insecure-bucket"
}

resource "aws_security_group" "bad" {
  name = "wide-open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
}
