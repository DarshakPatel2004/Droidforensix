"""GitHub scraper — official APIs, keyword-filtered to security-relevant repos.

Issues are searched via GraphQL; code/README mentions via the REST code
search (code search is not exposed in GraphQL). Raw results are cached in
SQLite. Respects the 10 req/min code-search limit with a fixed sleep.
"""

import logging
import time
from typing import Any, Dict, Iterator, List, Optional

import requests

logger = logging.getLogger(__name__)

API_BASE = "https://api.github.com"
GRAPHQL_ENDPOINT = f"{API_BASE}/graphql"
CACHE_VERSION = 2
CODE_SEARCH_INTERVAL_SECONDS = 7  # code search: 10 req/min for authenticated

ISSUES_QUERY = """
query($q: String!, $n: Int!) {
  search(query: $q, type: ISSUE, first: $n) {
    nodes {
      ... on Issue {
        url
        title
        createdAt
        body
        author { login }
        repository {
          nameWithOwner
          url
          description
          stargazerCount
          repositoryTopics(first: 10) { nodes { topic { name } } }
        }
      }
    }
  }
}
"""

REPO_KEYWORDS = ("malware", "c2", "indicator", "ioc")


class GitHubScraper:
    """Search GitHub for C2 indicator mentions in security-related repos."""

    def __init__(
        self,
        token: str,
        storage: Any,
        keywords: List[str] = list(REPO_KEYWORDS),
        min_stars: int = 0,
        max_results_per_query: int = 10,
    ):
        if not token:
            raise ValueError(
                "GitHub token missing: set GITHUB_TOKEN (repo scope recommended)"
            )
        self.token = token
        self.storage = storage
        self.keywords = [k.lower() for k in keywords]
        self.min_stars = min_stars
        self.max_results = max_results_per_query
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                # text-match media type: code search returns match fragments
                # with char indices, needed for snippets and line numbers
                "Accept": "application/vnd.github.text-match+json",
            }
        )

    def _cache_key(self, search_type: str, indicator: str) -> str:
        return f"github:{CACHE_VERSION}:{search_type}:{indicator}:{self.max_results}"

    def _query_graphql(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        resp = self.session.post(
            GRAPHQL_ENDPOINT,
            json={"query": query, "variables": variables},
            timeout=15,
        )
        if resp.status_code == 401:
            raise RuntimeError("Invalid GitHub token")
        if resp.status_code == 403:
            raise RuntimeError("GitHub rate limit exceeded")
        if resp.status_code == 429:
            time.sleep(30)
            return self._query_graphql(query, variables)
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("errors"):
            raise RuntimeError(f"GraphQL error: {payload['errors']}")
        return payload

    def _query_rest(self, path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        resp = self.session.get(f"{API_BASE}{path}", params=params, timeout=15)
        if resp.status_code == 401:
            raise RuntimeError("Invalid GitHub token")
        if resp.status_code == 429 or resp.status_code == 403:
            time.sleep(30)
            return self._query_rest(path, params)
        resp.raise_for_status()
        return resp.json()

    def _repo_is_relevant(self, repo: Dict[str, Any], enforce_min_stars: bool = True) -> bool:
        """Keyword gate: only malware/security repos carry attribution value."""
        if enforce_min_stars and repo.get("stargazerCount", 0) < self.min_stars:
            return False
        haystack = " ".join(
            [
                str(repo.get("nameWithOwner", "")),
                str(repo.get("description", "") or ""),
                " ".join(self._topic_names(repo.get("topics") or [])),
            ]
        ).lower()
        return any(keyword in haystack for keyword in self.keywords)

    @staticmethod
    def _topic_names(topics: List[Any]) -> List[str]:
        """Accept both GraphQL (dicts with topic.name) and string topic lists."""
        names = []
        for topic in topics:
            if isinstance(topic, str):
                names.append(topic)
            elif isinstance(topic, dict):
                nested = topic.get("topic")
                if isinstance(nested, dict):
                    names.append(str(nested.get("name", "")))
                elif nested:
                    names.append(str(nested))
        return names

    def _search_issues(self, indicator: str) -> List[Dict[str, Any]]:
        # Search the indicator alone; relevance is enforced by the repo
        # keyword gate below (GitHub search terms are AND-ed, so adding
        # "malware" here would match almost nothing).
        query = f'"{indicator}" in:title,body'
        payload = self._query_graphql(
            ISSUES_QUERY,
            {"q": query, "n": self.max_results},
        )
        nodes = payload["data"]["search"]["nodes"] or []
        records: List[Dict[str, Any]] = []
        for node in nodes:
            repo = node.get("repository", {})
            if not self._repo_is_relevant(repo):
                continue
            records.append(
                {
                    "url": node["url"],
                    "kind": "issue",
                    "created": node.get("createdAt", ""),
                    "username": (node.get("author") or {}).get("login", ""),
                    "body": "\n".join(
                        filter(None, [node.get("title", ""), node.get("body", "")])
                    ),
                    "repo_url": repo.get("url", ""),
                }
            )
        return records

    def _search_code(self, indicator: str) -> List[Dict[str, Any]]:
        # Indicator-only query; the repo keyword gate is applied to results.
        params = {
            "q": f'"{indicator}"',
            "per_page": self.max_results,
        }
        payload = self._query_rest("/search/code", params)
        records: List[Dict[str, Any]] = []
        for item in payload.get("items", []):
            repo = item.get("repository", {})
            repo_info = {
                "nameWithOwner": repo.get("full_name", ""),
                "description": repo.get("description", ""),
                "url": repo.get("html_url", ""),
            }
            # Code-search results omit stargazer counts; enforce the keyword
            # gate only (min_stars applies to issue results via GraphQL).
            if not self._repo_is_relevant(repo_info, enforce_min_stars=False):
                continue
            line_number, snippet = self._match_fragment(item)
            records.append(
                {
                    "url": f"{item.get('html_url', '')}#L{line_number}",
                    "kind": "code",
                    "created": item.get("updated_at", ""),
                    "username": "",
                    "body": snippet or item.get("name", ""),
                    "repo_url": repo.get("html_url", ""),
                    "path": item.get("path", ""),
                }
            )
        return records

    @staticmethod
    def _match_fragment(item: Dict[str, Any]) -> tuple:
        """Extract (line_number, snippet) from a code-search text match."""
        line_number, snippet = 1, ""
        for match in item.get("text_matches") or []:
            fragment = match.get("fragment", "")
            for fragment_match in match.get("matches", []):
                indices = fragment_match.get("indices") or [0, len(fragment)]
                start = max(0, indices[0])
                line_number = fragment.count("\n", 0, start) + 1
                snippet = fragment[max(0, start - 80) : start + 80]
                return line_number, snippet.replace("\n", " ").strip()
        return line_number, snippet

    def scrape_indicator(self, indicator: str) -> Iterator[Dict[str, Any]]:
        """Yield raw records for an indicator (issues then code, both cached)."""
        for search_type, fetcher in (
            ("issues", self._search_issues),
            ("code", self._search_code),
        ):
            key = self._cache_key(search_type, indicator)
            cached = self.storage.get_cache(key)
            if cached is not None:
                logger.debug("GitHub cache hit: %s %s", search_type, indicator)
                yield from cached
                continue
            try:
                raw = fetcher(indicator)
            except Exception as exc:
                logger.warning("GitHub %s search failed for %s: %s", search_type, indicator, exc)
                continue
            self.storage.set_cache(key, raw)
            logger.info("GitHub %s search %r -> %d records", search_type, indicator, len(raw))
            yield from raw
            if search_type == "code":
                time.sleep(CODE_SEARCH_INTERVAL_SECONDS)
