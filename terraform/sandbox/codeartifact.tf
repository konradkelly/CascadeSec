# The only registry the fetch task can reach (docs/sandbox-spec.md §5): a
# pull-through mirror of npmjs and PyPI. Free while idle beyond storage of
# what has been fetched, so it stays when the sandbox is switched off, along
# with its cache.
#
# The fetch task has no credentials, so sandbox-dispatch hands it a
# CodeArtifact bearer token: fifteen minutes, and whatever the dispatch role
# may do -- which is why that role can read these repositories and nothing
# else in CodeArtifact (dispatch.tf).

resource "aws_codeartifact_domain" "sandbox" {
  domain = "${var.project}-${var.environment}"
}

resource "aws_codeartifact_repository" "npm" {
  repository = "npm-mirror"
  domain     = aws_codeartifact_domain.sandbox.domain

  external_connections {
    external_connection_name = "public:npmjs"
  }
}

resource "aws_codeartifact_repository" "pypi" {
  repository = "pypi-mirror"
  domain     = aws_codeartifact_domain.sandbox.domain

  external_connections {
    external_connection_name = "public:pypi"
  }
}
