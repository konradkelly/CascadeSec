resource "aws_security_group" "web" {
  name        = "web"
  description = "Web tier"

  ingress {
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
