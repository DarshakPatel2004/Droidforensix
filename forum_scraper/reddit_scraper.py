"""Reddit scraper — official PRAW API, rate-limit friendly, cached.

Searches each configured subreddit for a C2 indicator, then scans the
comments of matching submissions for the same indicator (Reddit's search
API covers submissions only). Raw results are cached in SQLite so re-runs
never hit the API again.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

import praw
import prawcore

logger = logging.getLogger(__name__)

CACHE_VERSION = 1
MAX_COMMENTS_PER_POST = 100
RETRY_BACKOFF_SECONDS = 10
MAX_RETRIES = 3


class RedditScraper:
    """Search subreddits for C2 indicators using PRAW."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        user_agent: str,
        storage: Any,
        subreddits: List[str],
        min_score: int = 1,
        max_age_days: int = 180,
        max_posts_per_query: int = 25,
    ):
        if not all([client_id, client_secret, user_agent]):
            raise ValueError(
                "Reddit credentials missing: set REDDIT_CLIENT_ID, "
                "REDDIT_CLIENT_SECRET, REDDIT_USER_AGENT"
            )
        self._reddit = praw.Reddit(
            client_id=client_id,
            client_secret=client_secret,
            user_agent=user_agent,
        )
        self.storage = storage
        self.subreddits = subreddits
        self.min_score = min_score
        self.max_age_seconds = max_age_days * 24 * 3600
        self.max_posts_per_query = max_posts_per_query

    def _cache_key(self, subreddit: str, indicator: str) -> str:
        return f"reddit:{CACHE_VERSION}:{subreddit}:{indicator}:{self.max_posts_per_query}"

    def _fetch_raw(self, subreddit_name: str, indicator: str, retries: int = 0) -> List[Dict[str, Any]]:
        """Query the API once and return raw post/comment records."""
        raw: List[Dict[str, Any]] = []
        cutoff = time.time() - self.max_age_seconds
        subreddit = self._reddit.subreddit(subreddit_name)
        try:
            submissions = subreddit.search(
                query=indicator, sort="new", limit=self.max_posts_per_query
            )
            for submission in submissions:
                if self._too_old(submission.created_utc, cutoff):
                    continue
                if self._deleted_author(submission.author):
                    continue
                if getattr(submission, "score", 0) < self.min_score:
                    continue
                raw.append(
                    {
                        "kind": "post",
                        "url": f"https://www.reddit.com{submission.permalink}",
                        "subreddit": subreddit_name,
                        "created_utc": submission.created_utc,
                        "username": str(submission.author),
                        "body": f"{submission.title}\n{submission.selftext}".strip(),
                        "score": getattr(submission, "score", 0),
                    }
                )
                raw.extend(self._scan_comments(submission, indicator, cutoff))
        except prawcore.exceptions.ResponseException as exc:
            if exc.response.status_code == 429 and retries < MAX_RETRIES:
                logger.warning("Reddit rate limited; backing off and retrying")
                self._backoff_retry()
                return self._fetch_raw(subreddit_name, indicator, retries + 1)
            logger.warning(
                "Reddit API error %s on r/%s (indicator %s): %s",
                exc.response.status_code,
                subreddit_name,
                indicator,
                exc,
            )
        except Exception as exc:  # One broken subreddit must not kill the run
            logger.warning(
                "Failed to scrape r/%s for %s: %s", subreddit_name, indicator, exc
            )
        return raw

    def _scan_comments(
        self, submission: Any, indicator: str, cutoff: float
    ) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        try:
            submission.comments.replace_more(limit=0)
            comments = submission.comments.list()[:MAX_COMMENTS_PER_POST]
        except Exception as exc:
            logger.debug("Comment scan failed for %s: %s", submission.id, exc)
            return records
        for comment in comments:
            if not getattr(comment, "body", None):
                continue
            if self._too_old(comment.created_utc, cutoff):
                continue
            if self._deleted_author(comment.author):
                continue
            if getattr(comment, "score", 0) < self.min_score:
                continue
            if indicator.lower() not in comment.body.lower():
                continue
            records.append(
                {
                    "kind": "comment",
                    "url": f"https://www.reddit.com{comment.permalink}",
                    "subreddit": submission.subreddit.display_name,
                    "created_utc": comment.created_utc,
                    "username": str(comment.author),
                    "body": comment.body,
                    "score": getattr(comment, "score", 0),
                }
            )
        return records

    def _backoff_retry(self) -> None:
        time.sleep(RETRY_BACKOFF_SECONDS)

    @staticmethod
    def _too_old(created_utc: Optional[float], cutoff: float) -> bool:
        if created_utc is None:
            return True
        return created_utc < cutoff

    @staticmethod
    def _deleted_author(author: Optional[str]) -> bool:
        return author is None or str(author).lower() in ("[deleted]", "deleted")

    def scrape_indicator(self, indicator: str) -> Iterator[Dict[str, Any]]:
        """Yield raw records for an indicator across all subreddits (cached)."""
        for subreddit in self.subreddits:
            key = self._cache_key(subreddit, indicator)
            cached = self.storage.get_cache(key)
            if cached is not None:
                logger.debug("Cache hit for r/%s query %s", subreddit, indicator)
                yield from cached
                continue
            raw = self._fetch_raw(subreddit, indicator)
            self.storage.set_cache(key, raw)
            logger.info(
                "r/%s query %r -> %d raw records",
                subreddit,
                indicator,
                len(raw),
            )
            yield from raw


def utc_iso(created_utc: float) -> str:
    return datetime.fromtimestamp(created_utc, tz=timezone.utc).isoformat()
