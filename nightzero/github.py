from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class GitHubIssue:
    number: int
    title: str
    url: str
    body: str
    default_branch: str


@dataclass(frozen=True)
class RepositoryEvidence:
    commit_sha: str
    commit_message: str
    path: str
    content: str


@dataclass(frozen=True)
class GitHubPullRequest:
    number: int
    url: str


class GitHubGateway:
    """GitHub API boundary for bounded investigation and remediation operations."""

    def get_issue(self, repository: str, issue_number: int) -> GitHubIssue:
        raise NotImplementedError

    def get_repository_evidence(self, repository: str, ref: str) -> RepositoryEvidence:
        raise NotImplementedError

    def create_branch(self, repository: str, branch: str, source_commit: str) -> None:
        raise NotImplementedError

    def commit_pricing_replacement(self, repository: str, branch: str, file_path: str, replacement: str) -> str:
        raise NotImplementedError

    def create_draft_pull_request(self, repository: str, branch: str, base: str, title: str, body: str) -> GitHubPullRequest:
        raise NotImplementedError

    def add_issue_comment(self, repository: str, issue_number: int, body: str) -> None:
        raise NotImplementedError


class GitHubApiGateway(GitHubGateway):
    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.environ.get("NIGHTZERO_GITHUB_TOKEN")
        if not self.token:
            raise ValueError("NIGHTZERO_GITHUB_TOKEN is required for GitHub investigation")

    def get_issue(self, repository: str, issue_number: int) -> GitHubIssue:
        issue = self._get(f"/repos/{repository}/issues/{issue_number}")
        repository_data = self._get(f"/repos/{repository}")
        return GitHubIssue(
            number=issue_number,
            title=issue["title"],
            url=issue["html_url"],
            body=issue.get("body") or "",
            default_branch=repository_data["default_branch"],
        )

    def get_repository_evidence(self, repository: str, ref: str) -> RepositoryEvidence:
        commits = self._get(f"/repos/{repository}/commits?sha={ref}&per_page=1")
        commit = commits[0]
        path = "demo_target/pricing.py"
        content = self._get(f"/repos/{repository}/contents/{path}?ref={ref}")
        return RepositoryEvidence(
            commit_sha=commit["sha"],
            commit_message=commit["commit"]["message"],
            path=path,
            content=base64.b64decode(content["content"]).decode("utf-8"),
        )

    def create_branch(self, repository: str, branch: str, source_commit: str) -> None:
        try:
            existing = self._get(f"/repos/{repository}/git/ref/heads/{branch}")
            if existing["object"]["sha"] != source_commit:
                raise RuntimeError(f"Branch {branch} already exists with a different commit")
            return
        except RuntimeError as error:
            if "HTTP Error 404" not in str(error):
                raise
        self._request("POST", f"/repos/{repository}/git/refs", {"ref": f"refs/heads/{branch}", "sha": source_commit})

    def commit_pricing_replacement(self, repository: str, branch: str, file_path: str, replacement: str) -> str:
        source = self._get(f"/repos/{repository}/contents/{file_path}?ref={branch}")
        original = base64.b64decode(source["content"]).decode("utf-8")
        patched = original.replace('return f"${cents // 100}.00"', replacement)
        if patched == original:
            raise RuntimeError("Verified pricing replacement was not found in the branch")
        result = self._request("PUT", f"/repos/{repository}/contents/{file_path}", {
            "message": "Fix checkout total decimal formatting",
            "content": base64.b64encode(patched.encode("utf-8")).decode("ascii"),
            "branch": branch,
            "sha": source["sha"],
        })
        return result["commit"]["sha"]

    def create_draft_pull_request(self, repository: str, branch: str, base: str, title: str, body: str) -> GitHubPullRequest:
        pull_request = self._request("POST", f"/repos/{repository}/pulls", {
            "title": title, "head": branch, "base": base, "body": body, "draft": True,
        })
        return GitHubPullRequest(pull_request["number"], pull_request["html_url"])

    def add_issue_comment(self, repository: str, issue_number: int, body: str) -> None:
        self._request("POST", f"/repos/{repository}/issues/{issue_number}/comments", {"body": body})

    def _get(self, path: str) -> dict | list:
        return self._request("GET", path)

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict | list:
        request = Request(
            f"https://api.github.com{path}",
            data=json.dumps(payload).encode("utf-8") if payload is not None else None,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "nightzero-agent",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(request, timeout=10) as response:
                return json.loads(response.read())
        except (HTTPError, URLError, json.JSONDecodeError) as error:
            raise RuntimeError(f"GitHub {method.lower()} failed: {error}") from error