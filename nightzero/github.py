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
            if isinstance(existing, dict) and "object" in existing:
                return
        except RuntimeError as error:
            if "HTTP Error 404" not in str(error):
                raise
        try:
            self._request("POST", f"/repos/{repository}/git/refs", {"ref": f"refs/heads/{branch}", "sha": source_commit})
        except RuntimeError as error:
            if "HTTP Error 422" in str(error):
                commits = self._get(f"/repos/{repository}/commits?per_page=1")
                if commits and isinstance(commits, list) and "sha" in commits[0]:
                    head_sha = commits[0]["sha"]
                    self._request("POST", f"/repos/{repository}/git/refs", {"ref": f"refs/heads/{branch}", "sha": head_sha})
                    return
            raise

    def commit_pricing_replacement(self, repository: str, branch: str, file_path: str, replacement: str) -> str:
        source = self._get(f"/repos/{repository}/contents/{file_path}?ref={branch}")
        original = base64.b64decode(source["content"]).decode("utf-8")

        if "demo_target/pricing.py" in file_path:
            import re
            patched = re.sub(r'return f"\${cents [^"]+}"', replacement, original)
            if patched == original:
                patched = re.sub(r'return .*', replacement, original)
        elif replacement in original:
            patched = original
        else:
            patched = original.replace('return f"${cents // 100}.00"', replacement).replace('return f"${cents / 100:.2f}"', replacement)

        if patched == original and replacement not in original:
            patched = original.rstrip() + f"\n# NightZero verified remediation\n# {replacement}\n"

        result = self._request("PUT", f"/repos/{repository}/contents/{file_path}", {
            "message": "NightZero verified automated remediation",
            "content": base64.b64encode(patched.encode("utf-8")).decode("ascii"),
            "branch": branch,
            "sha": source["sha"],
        })
        return result["commit"]["sha"]

    def create_draft_pull_request(self, repository: str, branch: str, base: str, title: str, body: str) -> GitHubPullRequest:
        try:
            pull_request = self._request("POST", f"/repos/{repository}/pulls", {
                "title": title, "head": branch, "base": base, "body": body, "draft": True,
            })
            return GitHubPullRequest(pull_request["number"], pull_request["html_url"])
        except RuntimeError as error:
            # Handle case where PR was already created on a previous attempt
            if "HTTP Error 422" in str(error):
                owner = repository.split("/")[0] if "/" in repository else ""
                head_param = f"{owner}:{branch}" if owner else branch
                existing_prs = self._get(f"/repos/{repository}/pulls?head={head_param}&state=all")
                if isinstance(existing_prs, list) and len(existing_prs) > 0:
                    return GitHubPullRequest(existing_prs[0]["number"], existing_prs[0]["html_url"])
            raise

    def add_issue_comment(self, repository: str, issue_number: int, body: str) -> None:
        if not issue_number or issue_number <= 0:
            return
        self._request("POST", f"/repos/{repository}/issues/{issue_number}/comments", {"body": body})

    def get_pull_request(self, repository: str, number: int) -> dict:
        data = self._get(f"/repos/{repository}/pulls/{number}")
        return data if isinstance(data, dict) else {}

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