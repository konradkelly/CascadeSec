resource "aws_s3_bucket" "bad" {
  bucket = "my-insecure-bucket"
}

resource "aws_security_group" "bad" {
  name = "wide-open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
