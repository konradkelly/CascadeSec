terraform {
  encryption {
    key_provider "pbkdf2" "mykey" {
      passphrase = "this-is-a-long-enough-passphrase-1234"
    }
    method "aes_gcm" "mymethod" {
      keys = key_provider.pbkdf2.mykey
    }
    state {
      method = method.aes_gcm.mymethod
    }
  }
}

resource "aws_sqs_queue" "tofu" {
  name = "opentofu-plain-queue"
}
