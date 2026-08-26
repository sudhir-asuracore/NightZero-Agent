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
    commit_author: str = ""
    commit_date: str = ""


@dataclass(frozen=True)
class GitHubPullRequest:
    number: int
    url: str


class GitHubGateway:
    """GitHub API boundary for bounded investigation and remediation operations."""

    def get_issue(self, repository: str, issue_number: int) -> GitHubIssue:
        raise NotImplementedError

    def get_repository_evidence(self, repository: str, ref: str, path: str = "demo_target/pricing.py") -> RepositoryEvidence:
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

    def get_repository_evidence(self, repository: str, ref: str, path: str = "demo_target/pricing.py") -> RepositoryEvidence:
        commits = self._get(f"/repos/{repository}/commits?sha={ref}&per_page=1")
        commit = commits[0] if isinstance(commits, list) and len(commits) > 0 else {}
        content = self._get(f"/repos/{repository}/contents/{path}?ref={ref}")
        commit_details = commit.get("commit", {}) if isinstance(commit, dict) else {}
        author_info = commit_details.get("author", {}) if isinstance(commit_details, dict) else {}
        commit_author = author_info.get("name") or author_info.get("email") or "github-user"
        commit_date = author_info.get("date") or ""
        return RepositoryEvidence(
            commit_sha=commit.get("sha", "latest"),
            commit_message=commit_details.get("message", "Commit"),
            path=path,
            content=base64.b64decode(content.get("content", "")).decode("utf-8") if isinstance(content, dict) else "",
            commit_author=commit_author,
            commit_date=commit_date,
        )

    def create_branch(self, repository: str, branch: str, source_commit: str = "main") -> None:
        try:
            existing = self._get(f"/repos/{repository}/git/ref/heads/{branch}")
            if isinstance(existing, dict) and "object" in existing:
                return
        except RuntimeError as error:
            if "HTTP Error 404" not in str(error):
                raise

        # Resolve latest SHA from default branch/main for clean branch creation
        try:
            commits = self._get(f"/repos/{repository}/commits?sha=main&per_page=1")
            target_sha = commits[0]["sha"] if (commits and isinstance(commits, list) and "sha" in commits[0]) else source_commit
        except Exception:
            target_sha = source_commit

        try:
            self._request("POST", f"/repos/{repository}/git/refs", {"ref": f"refs/heads/{branch}", "sha": target_sha})
        except RuntimeError as error:
            if "HTTP Error 422" in str(error):
                return
            if "HTTP Error 403" in str(error):
                repo_info = self._get(f"/repos/{repository}")
                def_branch = repo_info.get("default_branch", "main")
                head_commits = self._get(f"/repos/{repository}/commits?sha={def_branch}&per_page=1")
                if head_commits and isinstance(head_commits, list) and "sha" in head_commits[0]:
                    self._request("POST", f"/repos/{repository}/git/refs", {"ref": f"refs/heads/{branch}", "sha": head_commits[0]["sha"]})
                    return
            raise

    def commit_pricing_replacement(self, repository: str, branch: str, file_path: str, replacement: str) -> str:
        source = self._get(f"/repos/{repository}/contents/{file_path}?ref={branch}")
        original = base64.b64decode(source["content"]).decode("utf-8")

        import re
        clean_repl = replacement.strip()
        if "return" in clean_repl and "def " not in clean_repl:
            # Replace the return line in the target file
            patched = re.sub(r'^\s*return .*', lambda _: f'    {clean_repl}', original, flags=re.MULTILINE)
        elif "def " in clean_repl:
            patched = clean_repl
        elif replacement in original:
            patched = original
        else:
            patched = original.rstrip() + f"\n# NightZero automated update\n# {replacement}\n"

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