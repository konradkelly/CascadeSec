import pytest

from cascadesec import prs
from cascadesec.errors import CliError


class FakeGitHub:
    def __init__(self, anonymous, authed=None):
        self.anonymous, self.authed = anonymous, authed
        self.calls = []

    def __call__(self, url, token):
        self.calls.append((url, token))
        return self.authed if token else self.anonymous


def no_gh():
    raise AssertionError("gh must not be asked for a token here")


def test_a_review_api_id_passes_through_untouched():
    assert prs.resolve("gh-1352957770-50", {}, github_get=FakeGitHub(None), gh_token=no_gh) == "gh-1352957770-50"
    assert prs.resolve("external-terragoat-s3-20260921T133700", {}, github_get=FakeGitHub(None),
                       gh_token=no_gh) == "external-terragoat-s3-20260921T133700"


@pytest.mark.parametrize("ref", ["konradkelly/cascadesec-testbed#4",
                                 "https://github.com/konradkelly/cascadesec-testbed/pull/4/files"])
def test_a_public_github_pr_resolves_anonymously(ref):
    github = FakeGitHub((200, {"id": 1388098412}))

    assert prs.resolve(ref, {}, github_get=github, gh_token=no_gh) == "gh-1388098412-4"
    assert github.calls == [("https://api.github.com/repos/konradkelly/cascadesec-testbed", None)]


def test_a_private_repo_retries_with_a_token():
    """GitHub answers 404, not 403, for a private repository it won't show."""
    github = FakeGitHub((404, None), (200, {"id": 7}))

    assert prs.resolve("o/private#1", {"GITHUB_TOKEN": "ghp_x"}, github_get=github, gh_token=no_gh) == "gh-7-1"
    assert github.calls[1][1] == "ghp_x"


def test_falls_back_to_the_gh_cli_token():
    github = FakeGitHub((404, None), (200, {"id": 7}))
    assert prs.resolve("o/private#1", {}, github_get=github, gh_token=lambda: "gho_y") == "gh-7-1"
    assert github.calls[1][1] == "gho_y"


def test_an_unseeable_repo_says_how_to_see_it():
    with pytest.raises(CliError) as e:
        prs.resolve("o/r#1", {}, github_get=FakeGitHub((404, None)), gh_token=lambda: None)
    assert e.value.code == 2
    assert "GITHUB_TOKEN" in str(e.value)


@pytest.mark.parametrize("ref", ["", "../etc", "a b", "o/r", "prs/x/findings"])
def test_anything_else_is_refused_before_it_reaches_a_url(ref):
    with pytest.raises(CliError) as e:
        prs.resolve(ref, {}, github_get=FakeGitHub(None), gh_token=no_gh)
    assert e.value.code == 2
