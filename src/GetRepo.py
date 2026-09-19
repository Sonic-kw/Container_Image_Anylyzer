import requests
from requests.adapters import HTTPAdapter
from requests_cache import CachedSession
from urllib3.util import Retry
from dataclasses import dataclass
from pathlib import Path
import logging
from typing import Any
from dotenv import load_dotenv
import os


HUB_API     = "https://hub.docker.com/v2"
HUB_LIBRARY = HUB_API + "/repositories/library/"                 # Krok 1
HUB_SEARCH  = HUB_API + "/search/repositories/"                  # Krok 1
PAGE_SIZE  = 100
MAX_PAGE=200
TIMEOUT    = (10, 30)
USER_AGENT = "pwr-thesis-fetcher/0.1"
MANIFEST_ACCEPT = ("application/vnd.oci.image.index.v1+json,"
                   "application/vnd.docker.distribution.manifest.list.v2+json")
SEARCH_QUERIES = [
    "alpine", "slim", "python", "node",
    "java", "nginx", "postgres", "redis",
]
load_dotenv()
token = os.environ["DOCKER_HUB_PAT"]
log = logging.getLogger("hub_catalog")


@dataclass(frozen=True, slots=True)
class HttpClient:
    namespace: str
    name: str
    pull_count: int | None
    star_count: int | None
    last_updated: str | None
    is_official: bool
    source: str
    query: str | None
    fetched_at: str
    raw: dict[str, Any]

def build_session(cache_name: str = "cache/hub_api") -> requests.Session:
    retry = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        respect_retry_after_header=True,
    )
    Path(cache_name).parent.mkdir(parents=True, exist_ok=True)
    session: requests.Session = CachedSession(cache_name, backend="sqlite", expire_after=24 * 3600)
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session

def main():
    session = build_session()
    total = build_catalog(session, SEARCH_QUERIES, "results/catalog.jsonl", 2)







