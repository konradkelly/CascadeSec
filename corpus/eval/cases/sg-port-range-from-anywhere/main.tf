resource "aws_security_group" "nodes" {
  name        = "nodes"
  description = "Kubernetes nodes"

  ingress {
    description = "NodePort range"
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
