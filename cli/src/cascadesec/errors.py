"""Exit codes (docs/cli-spec.md §5, §10) and the one exception that carries
them out of a command."""

OK = 0
# scan: findings at or above --fail-on. review: the API refused the action
# and said why (unmet prerequisites, a moved commit plan, not a committer).
REFUSED = 1
USAGE = 2
INCOMPLETE = 3
# Service error, auth failure, or timeout. Not being signed in is an auth
# failure: the command could not be attempted, which is not the same as the
# API refusing it.
SERVICE = 4


class CliError(Exception):
    def __init__(self, message, code=SERVICE):
        super().__init__(message)
        self.code = code
