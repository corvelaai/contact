import argparse
import base64
import concurrent.futures
import hashlib
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, urlparse

import requests
from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# Configuration — deliberately mirrors the repository's environment names.
# ---------------------------------------------------------------------------

TIMEOUT = int(os.getenv("CONTACTUPDATE_TIMEOUT", "15"))
RETRIES = int(os.getenv("CONTACTUPDATE_RETRIES", "2"))
RECENT_VIDEO_COUNT = int(os.getenv("CONTACTUPDATE_RECENT_VIDEOS", "20"))
MAX_ENUM_RESULTS = int(os.getenv("CONTACTUPDATE_MAX_ENUM_RESULTS", "150"))
MAX_PROFILES = int(os.getenv("CONTACTUPDATE_MAX_PROFILES", "60"))
USER_AGENT = os.getenv(
    "CONTACTUPDATE_USER_AGENT",
    "echoguard-osnit/1.0",
)

SCRAPECREATORS_API_KEY = os.getenv("SCRAPECREATORS_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY")

TELEGRAM_QUERY_BOTS = [
    x.strip().lstrip("@").lower()
    for x in os.getenv(
        "TELEGRAM_QUERY_BOTS",
        "peckin_check_bot,maigret",
    ).split(",")
    if x.strip()
]
TELEGRAM_BOT_MESSAGE_TEMPLATES = [
    x.strip()
    for x in os.getenv(
        "TELEGRAM_BOT_MESSAGE_TEMPLATES",
        "@{username}|/check {username}|{username}",
    ).split("|")
    if x.strip()
]
MAX_TELEGRAM_BOT_RESPONSES = int(
    os.getenv("MAX_TELEGRAM_BOT_RESPONSES", "4")
)

SHERLOCK_PATH = os.getenv("SHERLOCK_PATH", "sherlock")
MAIGRET_PATH = os.getenv("MAIGRET_PATH", "maigret")
TOKIE_PATH = os.getenv("TOKIE_PATH", "tookie-osint")
SHERLOCK_ENABLED = os.getenv("SHERLOCK_ENABLED", "false").lower() in {
    "1", "true", "yes", "on"
}
MAIGRET_ENABLED = os.getenv("MAIGRET_ENABLED", "false").lower() in {
    "1", "true", "yes", "on"
}
TOKIE_ENABLED = os.getenv("TOKIE_ENABLED", "false").lower() in {
    "1", "true", "yes", "on"
}

TELEGRAM_USERBOT_SESSION = os.getenv("TELEGRAM_USERBOT_SESSION")
TELEGRAM_USERBOT_API_ID = os.getenv("TELEGRAM_USERBOT_API_ID")
TELEGRAM_USERBOT_API_HASH = os.getenv("TELEGRAM_USERBOT_API_HASH")
TELEGRAM_USERBOT_PHONE = os.getenv("TELEGRAM_USERBOT_PHONE")

# The repository already restricts its userbot path to explicitly authorised
# accounts. Keep that behavior.
PRIVATE_LOOKUP_ENABLED = os.getenv(
    "PRIVATE_LOOKUP_ENABLED", "false"
).lower() in {"1", "true", "yes", "on"}
PRIVATE_LOOKUP_MODE = os.getenv(
    "PRIVATE_LOOKUP_MODE", "consented"
).strip().lower()
PRIVATE_LOOKUP_SELF_ONLY = os.getenv(
    "PRIVATE_LOOKUP_SELF_ONLY", "true"
).lower() in {"1", "true", "yes", "on"}
PRIVATE_LOOKUP_ALLOWLIST = [
    x.strip().lstrip("@").lower()
    for x in os.getenv("PRIVATE_LOOKUP_ALLOWLIST", "").split(",")
    if x.strip()
]
TELEGRAM_SELF_USERNAME = os.getenv(
    "TELEGRAM_SELF_USERNAME", ""
).strip().lstrip("@").lower()


# ---------------------------------------------------------------------------
# Logging / HTTP
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
LOG = logging.getLogger("contactupdate")


class HTTP:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.cache: Dict[str, Tuple[float, requests.Response]] = {}

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        timeout = kwargs.pop("timeout", TIMEOUT)
        cache_key = method.upper() + ":" + url + ":" + json.dumps(
            kwargs.get("params", {}),
            sort_keys=True,
            default=str,
        )

        cached = self.cache.get(cache_key)
        if cached and time.time() - cached[0] < 45:
            return cached[1]

        for attempt in range(RETRIES + 1):
            try:
                r = self.session.request(
                    method,
                    url,
                    timeout=timeout,
                    **kwargs,
                )
                if r.status_code in {429, 500, 502, 503, 504} and attempt < RETRIES:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                self.cache[cache_key] = (time.time(), r)
                return r
            except requests.RequestException as exc:
                if attempt >= RETRIES:
                    LOG.debug("HTTP failed %s: %s", url, exc)
                    return None
                time.sleep(0.75 * (attempt + 1))
        return None

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)


HTTPX = HTTP()


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    kind: str
    value: str
    source: str
    url: Optional[str] = None
    score: float = 0.0
    context: Optional[str] = None

    def key(self) -> str:
        return "|".join([
            self.kind.lower(),
            self.value.lower(),
            self.source.lower(),
            (self.url or "").lower(),
        ])


@dataclass
class Profile:
    platform: str
    username: str
    url: str = ""
    display_name: str = ""
    bio: str = ""
    recent_posts: str = ""
    avatar: str = ""
    verified: bool = False
    user_id: Optional[str] = None
    links: List[str] = field(default_factory=list)
    videos: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    status: str = "ok"
    error: Optional[str] = None

    def all_text(self) -> str:
        pieces = [
            self.display_name,
            self.bio,
            self.recent_posts,
        ]
        for video in self.videos:
            pieces.extend([
                str(video.get("description") or ""),
                " ".join(video.get("hashtags") or []),
                str(video.get("music") or ""),
            ])
        return " ".join(x for x in pieces if x).strip()


# ---------------------------------------------------------------------------
# Exact repository extraction helpers, improved with deduplication.
# ---------------------------------------------------------------------------

PHONE_PATTERNS = [
    re.compile(
        r"(?:tel:|phone|mobile|telephone|call|whatsapp)\s*[:=]?\s*"
        r"(\+?[0-9][0-9\s().-]{7,}[0-9])",
        re.I,
    ),
    re.compile(r"wa\.me/(?:\+)?([0-9]{9,15})", re.I),
    re.compile(r"(?<!\d)(\+256(?:[\s().-]*\d){9})(?!\d)"),
    re.compile(r"(?<!\d)(0[7-9](?:[\s().-]*\d){8})(?!\d)"),
    re.compile(
        r"(?<!\d)(\+[1-9][0-9](?:[\s().-]*[0-9]){8,13})(?!\d)"
    ),
]

EMAIL_PATTERNS = [
    re.compile(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        re.I,
    ),
    re.compile(
        r"mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        re.I,
    ),
]

CONTACT_INDICATORS = [
    "contact me", "email me", "call me", "whatsapp", "telegram",
    "wa.me", "t.me", "mailto:", "tel:", "business inquiry",
    "for bookings", "reach me", "get in touch", "hire me",
    "collaborate", "sponsor",
]


def normalize_phone_number(raw: str) -> str:
    if not raw:
        return ""
    value = str(raw).strip()
    value = re.sub(
        r"^(?:tel:|call:|phone:|mobile:|whatsapp:|wa\.me/)",
        "",
        value,
        flags=re.I,
    )
    value = re.sub(r"[?#].*$", "", value)
    had_plus = value.startswith("+")
    digits = re.sub(r"\D", "", value)

    if len(digits) == 10 and digits.startswith("0"):
        return "+256" + digits[1:]
    if len(digits) == 9 and digits[0] in "789":
        return "+256" + digits
    if len(digits) == 12 and digits.startswith("256"):
        return "+" + digits
    if 10 <= len(digits) <= 15 and had_plus:
        return "+" + digits
    return digits


def is_plausible_phone(number: str) -> bool:
    if not number:
        return False
    digits = re.sub(r"\D", "", number)
    if len(digits) < 9 or len(digits) > 15:
        return False
    if re.fullmatch(r"(\d)\1+", digits):
        return False
    if digits in {
        "1234567890",
        "123456789012",
        "9876543210",
        "987654321098",
    }:
        return False
    if re.fullmatch(r"(?:0?256)0+", digits):
        return False
    if digits.startswith("256"):
        return bool(re.fullmatch(r"256[7-9]\d{8}", digits))
    if digits.startswith("0"):
        return bool(re.fullmatch(r"0[7-9]\d{8}", digits))
    return number.strip().startswith("+") and 10 <= len(digits) <= 15


def phone_context_score(text: str, index: int, match: str) -> int:
    before = text[max(0, index - 90):index].lower()
    after = text[index + len(match):index + len(match) + 90].lower()
    context = before + " " + after
    score = 0

    if re.search(
        r"phone|mobile|telephone|tel|call|whatsapp|contact|reach|"
        r"viber|booking|business inquiry|wa\.me",
        context,
        re.I,
    ):
        score += 60
    if re.search(r"tel:|wa\.me/", before, re.I):
        score += 35
    if re.search(
        r"\b(?:id|user.?id|video.?id|post.?id|order|timestamp|"
        r"duration|views|likes|count|cursor|offset)\b",
        context,
        re.I,
    ):
        score -= 80
    return score


def normalize_email_candidate(raw: str) -> str:
    return (
        re.sub(r"\s+", "", raw)
        .replace("mailto:", "")
        .replace("[at]", "@")
        .replace("(at)", "@")
        .lower()
    )


def is_well_formed_email(email: str) -> bool:
    return bool(
        re.fullmatch(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            email,
        )
    )


def extract_contact_info(text: str) -> Dict[str, Any]:
    """
    Same core extraction approach as the repository:
      - obfuscated email normalization
      - email regexes
      - strong phone patterns
      - generic international +number pattern
      - context scoring
      - potential-contact indicators
    """
    extracted = {
        "emails": [],
        "phoneNumbers": [],
        "potentialContacts": [],
        "phoneEvidence": [],
    }
    if not text:
        return extracted

    normalized_text = (
        text.replace("[at]", "@")
        .replace("(at)", "@")
        .replace("[dot]", ".")
        .replace("(dot)", ".")
    )
    normalized_text = re.sub(r"\s+at\s+", "@", normalized_text, flags=re.I)
    normalized_text = re.sub(r"\s+dot\s+", ".", normalized_text, flags=re.I)

    for pattern in EMAIL_PATTERNS:
        for m in pattern.finditer(normalized_text):
            email = normalize_email_candidate(m.group(0))
            if is_well_formed_email(email) and email not in extracted["emails"]:
                extracted["emails"].append(email)

    candidates = []
    strong_patterns = [
        re.compile(r"tel:\s*\+?[0-9][0-9\s().-]{7,}[0-9]", re.I),
        re.compile(r"wa\.me/(?:\+)?[0-9]{9,15}", re.I),
        re.compile(
            r"(?:whatsapp\s*(?:number|me|contact)?|phone|mobile|"
            r"telephone|tel|call|contact(?:\s+me)?|reach\s+me)"
            r"\s*[:=]?\s*\+?[0-9][0-9\s().-]{7,}[0-9]",
            re.I,
        ),
        re.compile(r"\+256(?:[\s().-]*[0-9]){9}"),
        re.compile(r"0[7-9](?:[\s().-]*[0-9]){8}"),
    ]

    for pattern in strong_patterns:
        for m in pattern.finditer(normalized_text):
            candidates.append({
                "raw": m.group(0),
                "index": m.start(),
                "strong": True,
            })

    generic = re.compile(r"\+[1-9][0-9](?:[\s().-]*[0-9]){8,13}")
    for m in generic.finditer(normalized_text):
        candidates.append({
            "raw": m.group(0),
            "index": m.start(),
            "strong": False,
        })

    seen = set()
    for candidate in sorted(
        candidates,
        key=lambda x: (x["strong"], x["index"]),
        reverse=True,
    ):
        normalized = normalize_phone_number(candidate["raw"])
        if not is_plausible_phone(normalized) or normalized in seen:
            continue

        score = (
            (70 if candidate["strong"] else 20)
            + phone_context_score(
                normalized_text,
                candidate["index"],
                candidate["raw"],
            )
        )
        if score < 50:
            continue

        seen.add(normalized)
        context = normalized_text[
            max(0, candidate["index"] - 80):
            candidate["index"] + len(candidate["raw"]) + 80
        ]
        extracted["phoneNumbers"].append(normalized)
        extracted["phoneEvidence"].append({
            "number": normalized,
            "score": score,
            "raw": candidate["raw"],
            "context": context,
        })

    lower = normalized_text.lower()
    extracted["potentialContacts"] = [
        indicator
        for indicator in CONTACT_INDICATORS
        if indicator in lower
    ]
    return extracted


# ---------------------------------------------------------------------------
# HTML/public profile extraction.
# ---------------------------------------------------------------------------

def clean_url(url: str) -> str:
    return (url or "").strip().rstrip(".,;:!?)]}>'\"")


def fetch_profile_text(url: str) -> Dict[str, Any]:
    r = HTTPX.get(url)
    if not r or not r.ok:
        return {
            "success": False,
            "url": url,
            "text": "",
            "links": [],
            "title": "",
            "description": "",
        }

    html = r.text or ""
    soup = BeautifulSoup(html, "html.parser")

    snippets = []
    title = ""
    description = ""

    if soup.title:
        title = soup.title.get_text(" ", strip=True)
        if title:
            snippets.append(title)

    for attr in [
        {"property": "og:description"},
        {"name": "description"},
        {"property": "twitter:description"},
    ]:
        node = soup.find("meta", attrs=attr)
        if node and node.get("content"):
            value = node.get("content", "").strip()
            description = description or value
            snippets.append(value)

    body = soup.get_text(" ", strip=True)
    if body:
        snippets.append(re.sub(r"\s+", " ", body)[:12000])

    links = []
    for a in soup.find_all("a", href=True):
        href = a.get("href", "")
        if href.startswith(("http://", "https://")):
            links.append(clean_url(href))

    return {
        "success": True,
        "url": url,
        "text": " ".join(snippets),
        "links": sorted(set(links)),
        "title": title,
        "description": description,
    }


# ---------------------------------------------------------------------------
# ScrapeCreators — EXACT API endpoints/parameter names from repository.
# ---------------------------------------------------------------------------

def scrape_tiktok_profile(username: str) -> Optional[Profile]:
    if not SCRAPECREATORS_API_KEY:
        LOG.error("SCRAPECREATORS_API_KEY is required for TikTok API mode.")
        return None

    url = "https://api.scrapecreators.com/v1/tiktok/profile"
    try:
        r = HTTPX.get(
            url,
            headers={
                "x-api-key": SCRAPECREATORS_API_KEY,
                "Accept": "application/json",
            },
            params={"handle": username.lstrip("@")},
            timeout=15,
        )
        if r and r.ok:
            data = r.json()
            user = data.get("user") or {}
            if user:
                unique = user.get("uniqueId") or username.lstrip("@")
                return Profile(
                    platform="TikTok",
                    username=unique,
                    display_name=user.get("nickname") or "",
                    bio=user.get("signature") or "",
                    avatar=user.get("avatarMedium")
                    or user.get("avatarThumb")
                    or "",
                    verified=bool(user.get("verified")),
                    user_id=str(user.get("id")) if user.get("id") else None,
                    url=f"https://www.tiktok.com/@{unique}",
                    raw=data,
                )
    except Exception as exc:
        LOG.error("TikTok profile API error: %s", exc)

    # Same repository fallback: public TikTok page.
    url = f"https://www.tiktok.com/@{quote(username.lstrip('@'))}"
    page = fetch_profile_text(url)
    if page["success"] and page["text"]:
        return Profile(
            platform="TikTok",
            username=username.lstrip("@"),
            url=url,
            bio=page["description"] or page["text"],
            display_name=page["title"],
            links=page["links"],
        )
    return None


def scrape_tiktok_videos(username: str) -> Optional[Dict[str, Any]]:
    if not SCRAPECREATORS_API_KEY:
        return None

    url = "https://api.scrapecreators.com/v1/tiktok/videos"
    try:
        r = HTTPX.get(
            url,
            headers={
                "x-api-key": SCRAPECREATORS_API_KEY,
                "Accept": "application/json",
            },
            params={
                "handle": username.lstrip("@"),
                "count": RECENT_VIDEO_COUNT,
            },
            timeout=15,
        )
        if not r or not r.ok:
            return None

        data = r.json()
        videos = data.get("videos") or []
        video_data = []

        for video in videos:
            hashtags = video.get("hashtags") or []
            if isinstance(hashtags, str):
                hashtags = [hashtags]

            video_data.append({
                "id": video.get("id") or video.get("video_id"),
                "description": video.get("description")
                or video.get("text")
                or "",
                "hashtags": hashtags,
                "music": video.get("music") or "",
                "thumbnail": video.get("cover")
                or video.get("thumbnail")
                or "",
                "url": video.get("play") or video.get("url") or "",
                "createTime": video.get("createTime")
                or video.get("created_at"),
            })

        all_text = " ".join(
            f"{v['description']} {' '.join(v['hashtags'])} {v['music']}"
            for v in video_data
        )

        return {
            "platform": "TikTok",
            "username": username.lstrip("@"),
            "videoCount": len(video_data),
            "videos": video_data,
            "allText": all_text,
            "totalHashtags": sum(
                len(v["hashtags"]) for v in video_data
            ),
            "raw": data,
        }
    except Exception as exc:
        LOG.error("TikTok videos API error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Cross-platform APIs from the repository.
# ---------------------------------------------------------------------------

def scrape_twitter_profile(username: str) -> Optional[Profile]:
    clean = username.lstrip("@")
    if SCRAPECREATORS_API_KEY:
        try:
            r = HTTPX.post(
                "https://api.scrapecreators.com/v1/twitter/search",
                json={
                    "query": f"from:{clean}",
                    "count": 10,
                },
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {SCRAPECREATORS_API_KEY}",
                },
                timeout=15,
            )
            if r and r.ok:
                data = r.json()
                tweets = data.get("data") or []
                if tweets:
                    text = " ".join(
                        t.get("text") or t.get("content") or ""
                        for t in tweets
                    )
                    return Profile(
                        platform="Twitter/X",
                        username=clean,
                        url=f"https://x.com/{clean}",
                        recent_posts=text,
                        raw=data,
                    )
        except Exception as exc:
            LOG.debug("Twitter API error: %s", exc)

    url = f"https://x.com/{quote(clean)}"
    page = fetch_profile_text(url)
    if page["success"] and page["text"]:
        return Profile(
            platform="Twitter/X",
            username=clean,
            url=url,
            bio=page["description"] or page["text"],
            recent_posts=page["text"],
            links=page["links"],
        )
    return None


def scrape_youtube_profile(username: str) -> Optional[Profile]:
    clean = username.lstrip("@")

    if YOUTUBE_API_KEY:
        try:
            r = HTTPX.get(
                "https://www.googleapis.com/youtube/v3/search",
                params={
                    "part": "snippet",
                    "q": clean,
                    "type": "channel",
                    "maxResults": 5,
                    "key": YOUTUBE_API_KEY,
                },
                timeout=15,
            )
            if r and r.ok:
                items = r.json().get("items") or []
                if items:
                    channel = items[0]
                    snippet = channel.get("snippet") or {}
                    channel_id = (
                        channel.get("id", {}).get("channelId")
                        or ""
                    )
                    return Profile(
                        platform="YouTube",
                        username=clean,
                        display_name=snippet.get("title") or "",
                        bio=snippet.get("description") or "",
                        url=(
                            f"https://www.youtube.com/channel/"
                            f"{channel_id}"
                        ),
                        raw=channel,
                    )
        except Exception as exc:
            LOG.debug("YouTube API error: %s", exc)

    for url in [
        f"https://www.youtube.com/@{quote(clean)}",
        f"https://www.youtube.com/user/{quote(clean)}",
        f"https://www.youtube.com/c/{quote(clean)}",
    ]:
        page = fetch_profile_text(url)
        if page["success"] and page["text"]:
            return Profile(
                platform="YouTube",
                username=clean,
                url=url,
                display_name=page["title"],
                bio=page["description"] or page["text"],
                links=page["links"],
            )
    return None


def scrape_instagram_profile(username: str) -> Optional[Profile]:
    clean = username.lstrip("@")
    url = f"https://www.instagram.com/{quote(clean)}/"
    page = fetch_profile_text(url)

    if not page["success"]:
        return None

    return Profile(
        platform="Instagram",
        username=clean,
        url=url,
        display_name=page["title"],
        bio=page["description"] or page["text"],
        links=page["links"],
    )


def scrape_telegram_profile(username: str) -> Optional[Profile]:
    clean = username.lstrip("@")
    for url in [
        f"https://t.me/{quote(clean)}",
        f"https://telegram.me/{quote(clean)}",
    ]:
        page = fetch_profile_text(url)
        if page["success"] and page["text"]:
            return Profile(
                platform="Telegram",
                username=clean,
                url=url,
                display_name=page["title"],
                bio=page["description"] or page["text"],
                links=page["links"],
            )
    return None


# ---------------------------------------------------------------------------
# Existing Sherlock / Maigret / Tookie enumeration path.
# ---------------------------------------------------------------------------

def run_command(args: List[str], timeout: int = 30) -> Dict[str, Any]:
    try:
        p = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return {
            "returncode": p.returncode,
            "stdout": p.stdout or "",
            "stderr": p.stderr or "",
        }
    except Exception as exc:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
        }


def parse_enumerator_output(stdout: str, username: str) -> List[Dict[str, Any]]:
    found = []

    try:
        parsed = json.loads(stdout)
        if isinstance(parsed, list):
            values = parsed
        elif isinstance(parsed, dict):
            values = list(parsed.values())
        else:
            values = []

        for item in values:
            if isinstance(item, dict) and item.get("url"):
                found.append({
                    "platform": item.get("site") or item.get("platform"),
                    "url": item["url"],
                    "username": item.get("username") or username,
                })
    except Exception:
        pass

    if not found:
        urls = re.findall(
            r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+",
            stdout,
        )
        for url in urls:
            found.append({
                "platform": None,
                "url": clean_url(url),
                "username": username,
            })

    unique = {}
    for item in found:
        unique[item["url"]] = item
    return list(unique.values())[:MAX_ENUM_RESULTS]


def enumerate_accounts(username: str) -> List[Dict[str, Any]]:
    clean = username.lstrip("@")
    tools = []

    if SHERLOCK_ENABLED:
        tools.append(("sherlock", SHERLOCK_PATH))
    if MAIGRET_ENABLED:
        tools.append(("maigret", MAIGRET_PATH))
    if TOKIE_ENABLED:
        tools.append(("tookie", TOKIE_PATH))

    results = []
    for name, executable in tools:
        LOG.info("Enumerator: %s", name)
        args = [executable, clean, "--json"]
        result = run_command(args, timeout=60)

        if result["returncode"] != 0:
            LOG.debug("%s failed: %s", name, result["stderr"][:500])
            continue

        results.extend(
            parse_enumerator_output(result["stdout"], clean)
        )

    unique = {}
    for item in results:
        unique[item["url"]] = item
    return list(unique.values())[:MAX_ENUM_RESULTS]


# ---------------------------------------------------------------------------
# Direct profile discovery retained from JS repository.
# ---------------------------------------------------------------------------

def build_direct_profile_guesses(username: str) -> List[Dict[str, str]]:
    clean = username.lstrip("@")
    return [
        {
            "platform": "Twitter/X",
            "url": f"https://twitter.com/{clean}",
            "username": clean,
        },
        {
            "platform": "Instagram",
            "url": f"https://www.instagram.com/{clean}/",
            "username": clean,
        },
        {
            "platform": "YouTube",
            "url": f"https://www.youtube.com/@{clean}",
            "username": clean,
        },
        {
            "platform": "YouTube",
            "url": f"https://www.youtube.com/user/{clean}",
            "username": clean,
        },
        {
            "platform": "Telegram",
            "url": f"https://t.me/{clean}",
            "username": clean,
        },
        {
            "platform": "Telegram",
            "url": f"https://telegram.me/{clean}",
            "username": clean,
        },
        {
            "platform": "Facebook",
            "url": f"https://www.facebook.com/{clean}",
            "username": clean,
        },
    ]


def extract_external_profile_urls(text: str) -> List[Dict[str, str]]:
    urls = set(
        clean_url(x)
        for x in re.findall(
            r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+",
            text or "",
            re.I,
        )
    )
    found = []

    for url in urls:
        low = url.lower()
        platform = None
        username = None

        patterns = [
            (
                "Twitter/X",
                re.compile(
                    r"(?:twitter\.com|x\.com)/"
                    r"(?!intent|share|hashtag|search|i/)([^/?&]+)",
                    re.I,
                ),
            ),
            (
                "Instagram",
                re.compile(
                    r"instagram\.com/(?:#!/)?@?([^/?&]+)",
                    re.I,
                ),
            ),
            (
                "YouTube",
                re.compile(
                    r"youtube\.com/(?:@|user/|channel/|c/)([^/?&]+)",
                    re.I,
                ),
            ),
            (
                "Telegram",
                re.compile(
                    r"(?:t\.me|telegram\.me)/([^/?&]+)",
                    re.I,
                ),
            ),
            (
                "WhatsApp",
                re.compile(
                    r"(?:wa\.me/|whatsapp\.com/send\?phone=)(\+?\d+)",
                    re.I,
                ),
            ),
            (
                "Facebook",
                re.compile(
                    r"(?:facebook\.com|fb\.com)/"
                    r"(?!sharer|dialog|share|story\.php)([^/?&]+)",
                    re.I,
                ),
            ),
        ]

        for name, pattern in patterns:
            match = pattern.search(low)
            if match:
                platform = name
                username = match.group(1)
                break

        if platform:
            found.append({
                "platform": platform,
                "url": url,
                "username": username or "",
            })

    return found


# ---------------------------------------------------------------------------
# Telegram bot cascade — same bot/message flow as repository.
# ---------------------------------------------------------------------------

def telegram_bot_query(
    bot_username: str,
    username: str,
) -> Dict[str, Any]:
    """
    Uses a configured Telethon/Pyrogram user session to message the configured
    bot. This is kept as the repository's existing bot-query path.
    """
    if not (
        TELEGRAM_USERBOT_SESSION
        and TELEGRAM_USERBOT_API_ID
        and TELEGRAM_USERBOT_API_HASH
    ):
        return {
            "found": False,
            "source": "telegram_query_bot",
            "bot": bot_username,
            "note": "Telegram userbot session not configured.",
        }

    parsed_any = {"phone_number": None, "email": None}

    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession

        client = TelegramClient(
            StringSession(TELEGRAM_USERBOT_SESSION),
            int(TELEGRAM_USERBOT_API_ID),
            TELEGRAM_USERBOT_API_HASH,
        )
        client.connect()

        if not client.is_user_authorized():
            client.disconnect()
            return {
                "found": False,
                "source": "telegram_query_bot",
                "bot": bot_username,
                "note": "Telegram userbot session is not authorized.",
            }

        entity = client.get_entity(bot_username)

        for template in TELEGRAM_BOT_MESSAGE_TEMPLATES:
            message = template.format(username=username.lstrip("@"))
            try:
                client.send_message(entity, message)
                response = client.get_response(
                    entity,
                    timeout=15,
                )
                text = response.text if response else ""
                parsed = extract_contact_info(text)
                parsed_any["phone_number"] = (
                    parsed["phoneNumbers"][0]
                    if parsed["phoneNumbers"] else None
                )
                parsed_any["email"] = (
                    parsed["emails"][0]
                    if parsed["emails"] else None
                )
                if parsed_any["phone_number"] or parsed_any["email"]:
                    client.disconnect()
                    return {
                        "found": True,
                        "phone_number": parsed_any["phone_number"],
                        "email": parsed_any["email"],
                        "source": "telegram_query_bot",
                        "bot": bot_username,
                        "message": text.strip(),
                        "template": template,
                    }
            except Exception as exc:
                LOG.debug(
                    "Telegram bot %s template failed: %s",
                    bot_username,
                    exc,
                )

        client.disconnect()

    except ImportError:
        return {
            "found": False,
            "source": "telegram_query_bot",
            "bot": bot_username,
            "note": "Telethon is not installed.",
        }
    except Exception as exc:
        LOG.debug("Telegram bot lookup failed: %s", exc)

    return {
        "found": False,
        "source": "telegram_query_bot",
        "bot": bot_username,
        "note": "No public contact returned by configured bot.",
    }


def lookup_telegram_query_bots(username: str) -> Dict[str, Any]:
    results = []
    for bot in TELEGRAM_QUERY_BOTS:
        result = telegram_bot_query(bot, username)
        results.append(result)
        if result.get("found"):
            return {
                "found": True,
                "source": "telegram_query_bots",
                "phone_number": result.get("phone_number"),
                "email": result.get("email"),
                "details": result,
                "bot_results": results,
            }
    return {
        "found": False,
        "source": "telegram_query_bots",
        "bot_results": results,
    }


# ---------------------------------------------------------------------------
# AI — exact provider family used by repository, improved parsing.
# ---------------------------------------------------------------------------

def extract_json_object(text: str) -> Dict[str, Any]:
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        pass

    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return {}

    try:
        return json.loads(match.group(0))
    except Exception:
        return {}


def analyze_contact_info_with_ai(
    username: str,
    data: Dict[str, Any],
    extraction: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Uses Gemini first, then Groq, matching the repository's provider order.
    AI receives the collected public evidence and evaluates whether extracted
    contacts are plausibly associated with the supplied public profile.
    """
    evidence = {
        "username": username,
        "primaryProfile": data.get("primaryProfile"),
        "primaryVideos": data.get("primaryVideos"),
        "foundProfiles": data.get("foundProfiles", [])[:40],
        "crossPlatform": data.get("crossPlatform", [])[:20],
        "extraction": extraction,
    }

    prompt = """You are an OSINT evidence-analysis assistant.
Analyze ONLY the public evidence supplied below.

Do not invent contact information.
Do not infer a private phone number from unrelated information.
For each extracted phone/email, assess whether the evidence supports that it
is publicly associated with the queried account.

Return valid JSON only:
{
  "email": {
    "value": null,
    "confidence": 0,
    "source": "",
    "validated": false,
    "notes": []
  },
  "phone": {
    "value": null,
    "confidence": 0,
    "source": "",
    "validated": false,
    "notes": []
  },
  "overallConfidence": 0,
  "analysisNotes": [],
  "identitySignals": [],
  "crossPlatformMatches": []
}

Confidence is 0-100 and represents evidence quality, not certainty of
identity. Publicly explicit contact information should score higher than a
weak contextual association.

PUBLIC EVIDENCE:
""" + json.dumps(evidence, ensure_ascii=False, default=str)

    if GEMINI_API_KEY:
        try:
            r = HTTPX.post(
                "https://generativelanguage.googleapis.com/v1beta/"
                "models/gemini-flash-latest:generateContent",
                params={"key": GEMINI_API_KEY},
                json={
                    "contents": [{
                        "parts": [{"text": prompt}],
                    }],
                    "generationConfig": {
                        "temperature": 0.1,
                        "responseMimeType": "application/json",
                    },
                },
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            if r and r.ok:
                candidates = r.json().get("candidates") or []
                if candidates:
                    parts = (
                        candidates[0]
                        .get("content", {})
                        .get("parts", [])
                    )
                    text = "".join(
                        p.get("text", "")
                        for p in parts
                        if isinstance(p, dict)
                    )
                    parsed = extract_json_object(text)
                    if parsed:
                        parsed["provider"] = "gemini"
                        return parsed
        except Exception as exc:
            LOG.debug("Gemini analysis failed: %s", exc)

    if GROQ_API_KEY:
        try:
            r = HTTPX.post(
                "https://api.groq.com/openai/v1/chat/completions",
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are an OSINT evidence-analysis expert. "
                                "Return valid JSON only."
                            ),
                        },
                        {
                            "role": "user",
                            "content": prompt,
                        },
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.1,
                    "max_tokens": 1200,
                },
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json",
                },
                timeout=30,
            )
            if r and r.ok:
                choices = r.json().get("choices") or []
                if choices:
                    text = (
                        choices[0]
                        .get("message", {})
                        .get("content", "")
                    )
                    parsed = extract_json_object(text)
                    if parsed:
                        parsed["provider"] = "groq"
                        return parsed
        except Exception as exc:
            LOG.debug("Groq analysis failed: %s", exc)

    # Deterministic fallback; no fabricated contact data.
    return {
        "provider": "deterministic",
        "email": {
            "value": extraction["emails"][0]
            if extraction["emails"] else None,
            "confidence": 90 if extraction["emails"] else 0,
            "source": "public text extraction",
            "validated": bool(extraction["emails"]),
            "notes": [],
        },
        "phone": {
            "value": extraction["phoneNumbers"][0]
            if extraction["phoneNumbers"] else None,
            "confidence": min(
                100,
                int(
                    extraction["phoneEvidence"][0]["score"]
                    if extraction["phoneEvidence"] else 0
                ),
            ),
            "source": "public text extraction",
            "validated": bool(extraction["phoneNumbers"]),
            "notes": [],
        },
        "overallConfidence": 80 if (
            extraction["emails"] or extraction["phoneNumbers"]
        ) else 0,
        "analysisNotes": [
            "AI provider unavailable; deterministic evidence scoring used."
        ],
        "identitySignals": [],
        "crossPlatformMatches": [],
    }


# ---------------------------------------------------------------------------
# Correlation / scoring.
# ---------------------------------------------------------------------------

def normalize_username(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lstrip("@").lower())


def text_tokens(text: str) -> set:
    return {
        x.lower()
        for x in re.findall(r"[a-zA-Z0-9_@.-]{3,}", text or "")
        if not x.lower().startswith(("http", "www"))
    }


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0

    aa = normalize_username(a)
    bb = normalize_username(b)
    if aa and aa == bb:
        return 100.0

    ta = text_tokens(a)
    tb = text_tokens(b)
    if not ta or not tb:
        return 0.0

    overlap = len(ta & tb) / max(1, len(ta | tb))
    return round(overlap * 100, 2)


def extract_profile_evidence(profile: Profile) -> List[Evidence]:
    out = []
    text = profile.all_text()
    extraction = extract_contact_info(text)

    for email in extraction["emails"]:
        out.append(Evidence(
            "public_email",
            email,
            profile.platform,
            profile.url,
            99,
            "explicitly present in retrieved public text",
        ))

    for phone_info in extraction["phoneEvidence"]:
        out.append(Evidence(
            "public_phone",
            phone_info["number"],
            profile.platform,
            profile.url,
            phone_info["score"],
            phone_info["context"],
        ))

    for url in re.findall(
        r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+",
        text,
        re.I,
    ):
        out.append(Evidence(
            "public_url",
            clean_url(url),
            profile.platform,
            profile.url,
            95,
        ))

    for item in extract_external_profile_urls(text):
        out.append(Evidence(
            "platform_link",
            f"{item['platform']}:{item['username']}",
            profile.platform,
            profile.url,
            97,
        ))

    return out


def correlate_profiles(
    primary: Profile,
    candidate: Profile,
) -> Dict[str, Any]:
    score = 0
    signals = []

    a = normalize_username(primary.username)
    b = normalize_username(candidate.username)

    if a and b and a == b:
        score += 35
        signals.append({
            "signal": "exact_username",
            "points": 35,
        })
    elif a and b:
        # Compare normalized username prefixes / suffixes.
        common = similarity(primary.username, candidate.username)
        if common >= 70:
            score += 15
            signals.append({
                "signal": "similar_username",
                "points": 15,
            })

    bio_similarity = similarity(primary.all_text(), candidate.all_text())
    if bio_similarity >= 65:
        score += 25
        signals.append({
            "signal": "strong_text_overlap",
            "points": 25,
        })
    elif bio_similarity >= 40:
        score += 12
        signals.append({
            "signal": "partial_text_overlap",
            "points": 12,
        })

    primary_urls = {
        urlparse(x).netloc.lower().replace("www.", "")
        for x in re.findall(
            r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+",
            primary.all_text(),
        )
    }
    candidate_urls = {
        urlparse(x).netloc.lower().replace("www.", "")
        for x in re.findall(
            r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+",
            candidate.all_text(),
        )
    }
    shared_domains = primary_urls & candidate_urls
    if shared_domains:
        score += 25
        signals.append({
            "signal": "shared_external_domain",
            "points": 25,
            "domains": sorted(shared_domains),
        })

    primary_contacts = extract_contact_info(primary.all_text())
    candidate_contacts = extract_contact_info(candidate.all_text())

    shared_emails = set(primary_contacts["emails"]) & set(
        candidate_contacts["emails"]
    )
    if shared_emails:
        score += 35
        signals.append({
            "signal": "shared_public_email",
            "points": 35,
            "values": sorted(shared_emails),
        })

    shared_phones = set(primary_contacts["phoneNumbers"]) & set(
        candidate_contacts["phoneNumbers"]
    )
    if shared_phones:
        score += 35
        signals.append({
            "signal": "shared_public_phone",
            "points": 35,
            "values": sorted(shared_phones),
        })

    score = min(100, score)
    level = (
        "high" if score >= 75
        else "medium" if score >= 50
        else "low"
    )

    return {
        "score": score,
        "level": level,
        "signals": signals,
    }


# ---------------------------------------------------------------------------
# Main pipeline — preserves the repository's order.
# ---------------------------------------------------------------------------

def add_profile(
    profiles: List[Profile],
    profile: Optional[Profile],
    seen_urls: set,
) -> None:
    if not profile or not profile.url:
        return

    key = profile.url.rstrip("/").lower()
    if key in seen_urls:
        return

    seen_urls.add(key)
    profiles.append(profile)


def profile_from_enum(item: Dict[str, Any]) -> Optional[Profile]:
    platform = item.get("platform") or "discovered"
    url = item.get("url") or ""
    username = item.get("username") or ""

    page = fetch_profile_text(url)
    if not page["success"] or not page["text"]:
        return None

    return Profile(
        platform=platform,
        username=username,
        url=url,
        display_name=page["title"],
        bio=page["description"] or page["text"],
        links=page["links"],
    )


def run(username: str) -> Dict[str, Any]:
    started = time.time()
    clean = username.lstrip("@")

    LOG.info("ContactUpdate starting for @%s", clean)
    LOG.info("Phase 1: TikTok profile")

    primary = scrape_tiktok_profile(clean)
    if not primary:
        return {
            "success": False,
            "error": (
                "TikTok profile could not be retrieved. "
                "Check SCRAPECREATORS_API_KEY."
            ),
        }

    primary_videos = scrape_tiktok_videos(clean)

    if primary_videos:
        primary.videos = primary_videos["videos"]

    data = {
        "primaryPlatform": asdict(primary),
        "primaryVideos": primary_videos,
        "crossPlatform": [],
        "foundProfiles": [],
    }

    profiles: List[Profile] = []
    seen_urls = set()
    add_profile(profiles, primary, seen_urls)

    # Keep primary profile/video extraction first.
    primary_text = primary.all_text()
    extraction = extract_contact_info(primary_text)

    LOG.info(
        "TikTok: %d videos, %d public emails, %d public phones",
        len(primary.videos),
        len(extraction["emails"]),
        len(extraction["phoneNumbers"]),
    )

    # The original repository returns early when primary contact data exists.
    # Preserve the process, but still record a complete structured result.
    primary_contact_found = bool(
        extraction["emails"] or extraction["phoneNumbers"]
    )

    ai_primary = analyze_contact_info_with_ai(
        clean,
        {
            **data,
            "foundProfiles": [asdict(primary)],
        },
        extraction,
    ) if primary_contact_found else None

    # Cross-platform phase when primary data does not already contain contact.
    if not primary_contact_found:
        LOG.info("Phase 2: cross-platform enumeration")

        enum_results = enumerate_accounts(clean)
        LOG.info("Enumeration returned %d candidates", len(enum_results))

        # Fetch enumerated public profiles concurrently.
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [
                pool.submit(profile_from_enum, item)
                for item in enum_results[:MAX_ENUM_RESULTS]
            ]
            for future in concurrent.futures.as_completed(futures):
                try:
                    add_profile(
                        profiles,
                        future.result(),
                        seen_urls,
                    )
                except Exception as exc:
                    LOG.debug("Enumerator profile failed: %s", exc)

        # Direct profile guesses / inbound links from primary text.
        direct = build_direct_profile_guesses(clean)
        direct += extract_external_profile_urls(primary_text)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = []
            for item in direct:
                url = item.get("url", "")
                if not url or url.rstrip("/").lower() in seen_urls:
                    continue
                futures.append(pool.submit(
                    profile_from_enum,
                    item,
                ))
            for future in concurrent.futures.as_completed(futures):
                try:
                    add_profile(
                        profiles,
                        future.result(),
                        seen_urls,
                    )
                except Exception as exc:
                    LOG.debug("Direct profile failed: %s", exc)

        # Exact cross-platform APIs from the repository.
        LOG.info("Cross-platform API phase")

        api_jobs = {
            "twitter": lambda: scrape_twitter_profile(clean),
            "youtube": lambda: scrape_youtube_profile(clean),
            "instagram": lambda: scrape_instagram_profile(clean),
            "telegram": lambda: scrape_telegram_profile(clean),
        }

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            future_map = {
                pool.submit(fn): name
                for name, fn in api_jobs.items()
            }
            for future in concurrent.futures.as_completed(future_map):
                name = future_map[future]
                try:
                    profile = future.result()
                    if profile:
                        add_profile(profiles, profile, seen_urls)
                        LOG.info("%s profile discovered", name)
                except Exception as exc:
                    LOG.debug("%s failed: %s", name, exc)

        profiles = profiles[:MAX_PROFILES]

    # Build aggregate data after all discovered profiles.
    data["foundProfiles"] = [asdict(p) for p in profiles]
    data["crossPlatform"] = [
        asdict(p) for p in profiles if p.platform != "TikTok"
    ]

    aggregate_text = " ".join(
        p.all_text() for p in profiles
    )
    cross_extraction = extract_contact_info(aggregate_text)

    LOG.info(
        "Aggregate extraction: %d emails, %d phones",
        len(cross_extraction["emails"]),
        len(cross_extraction["phoneNumbers"]),
    )

    ai_cross = analyze_contact_info_with_ai(
        clean,
        data,
        cross_extraction,
    )

    # Telegram bot cascade stays after cross-platform extraction.
    telegram_result = None
    if not cross_extraction["phoneNumbers"]:
        LOG.info("No phone in public cross-platform data; Telegram cascade")
        telegram_result = lookup_telegram_query_bots(clean)

    if telegram_result and telegram_result.get("found"):
        if telegram_result.get("phone_number"):
            normalized = normalize_phone_number(
                telegram_result["phone_number"]
            )
            if is_plausible_phone(normalized):
                cross_extraction["phoneNumbers"].append(normalized)

        if telegram_result.get("email"):
            email = normalize_email_candidate(
                telegram_result["email"]
            )
            if is_well_formed_email(email):
                cross_extraction["emails"].append(email)

        cross_extraction["phoneNumbers"] = sorted(
            set(cross_extraction["phoneNumbers"])
        )
        cross_extraction["emails"] = sorted(
            set(cross_extraction["emails"])
        )

    # Evidence collection.
    evidence_map: Dict[str, Evidence] = {}
    for profile in profiles:
        for evidence in extract_profile_evidence(profile):
            evidence_map[evidence.key()] = evidence

    if telegram_result:
        if telegram_result.get("phone_number"):
            normalized = normalize_phone_number(
                telegram_result["phone_number"]
            )
            if normalized:
                e = Evidence(
                    "telegram_public_result",
                    normalized,
                    "telegram_query_bot",
                    score=80,
                )
                evidence_map[e.key()] = e
        if telegram_result.get("email"):
            e = Evidence(
                "telegram_public_result",
                telegram_result["email"],
                "telegram_query_bot",
                score=70,
            )
            evidence_map[e.key()] = e

    # Correlate all discovered public profiles to primary.
    matches = []
    for profile in profiles:
        if profile.url.rstrip("/").lower() == primary.url.rstrip("/").lower():
            continue

        comparison = correlate_profiles(primary, profile)
        matches.append({
            "platform": profile.platform,
            "username": profile.username,
            "url": profile.url,
            "displayName": profile.display_name,
            "comparison": comparison,
        })

    matches.sort(
        key=lambda x: x["comparison"]["score"],
        reverse=True,
    )

    # Final confidence: preserve AI if present, but don't let AI manufacture
    # contacts not present in extraction.
    final_email = (
        cross_extraction["emails"][0]
        if cross_extraction["emails"] else None
    )
    final_phone = (
        cross_extraction["phoneNumbers"][0]
        if cross_extraction["phoneNumbers"] else None
    )

    ai = ai_cross or ai_primary or {}
    ai_email = ai.get("email") or {}
    ai_phone = ai.get("phone") or {}

    result = {
        "success": True,
        "version": "7.5",
        "username": clean,
        "platform": "TikTok",
        "timestamp": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(),
        ),
        "elapsedSeconds": round(time.time() - started, 2),
        "searchFlow": [
            "TikTok profile API",
            "TikTok recent videos API",
            "primary contact extraction",
            "cross-platform enumeration",
            "direct public profile discovery",
            "Twitter/X API",
            "YouTube API",
            "Instagram public profile",
            "Telegram public profile",
            "aggregate contact extraction",
            "Telegram bot cascade",
            "AI evidence analysis",
        ],
        "primaryProfile": asdict(primary),
        "primaryVideos": primary_videos,
        "foundAccounts": matches,
        "contactInfo": {
            "email": {
                "address": final_email,
                "confidence": (
                    ai_email.get("confidence")
                    if final_email
                    else 0
                ),
                "source": (
                    ai_email.get("source")
                    or "public cross-platform extraction"
                    if final_email
                    else None
                ),
                "validated": bool(final_email),
                "notes": ai_email.get("notes", []),
            },
            "phone": {
                "number": final_phone,
                "confidence": (
                    ai_phone.get("confidence")
                    if final_phone
                    else 0
                ),
                "source": (
                    ai_phone.get("source")
                    or "public cross-platform extraction"
                    if final_phone
                    else None
                ),
                "validated": (
                    is_plausible_phone(final_phone)
                    if final_phone
                    else False
                ),
                "notes": ai_phone.get("notes", []),
            },
            "overallConfidence": ai.get(
                "overallConfidence",
                0,
            ),
            "analysisNotes": ai.get(
                "analysisNotes",
                [],
            ),
            "rawExtraction": cross_extraction,
        },
        "aiAnalysis": ai,
        "telegramCascade": telegram_result,
        "evidence": [
            asdict(x)
            for x in evidence_map.values()
        ],
        "stats": {
            "profilesScraped": len(profiles),
            "platforms": sorted(
                set(p.platform for p in profiles)
            ),
            "videosAnalyzed": len(primary.videos),
            "totalTextAnalyzed": len(aggregate_text),
            "emailsExtracted": len(
                cross_extraction["emails"]
            ),
            "phonesExtracted": len(
                cross_extraction["phoneNumbers"]
            ),
            "evidenceItems": len(evidence_map),
            "highConfidenceMatches": sum(
                x["comparison"]["level"] == "high"
                for x in matches
            ),
        },
    }

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_report(result: Dict[str, Any]) -> None:
    if not result.get("success"):
        print(json.dumps(result, indent=2))
        return

    contact = result["contactInfo"]
    stats = result["stats"]

    print("\n" + "=" * 78)
    print("CONTACTUPDATE v7.5")
    print("=" * 78)
    print(f"Target       : @{result['username']} (TikTok)")
    print(
        f"Videos       : {stats['videosAnalyzed']}"
    )
    print(
        f"Profiles     : {stats['profilesScraped']}"
    )
    print(
        f"Platforms    : {', '.join(stats['platforms']) or 'none'}"
    )

    print("\nPUBLIC CONTACTS")
    print("-" * 78)
    print(
        "Email        :",
        contact["email"]["address"] or "not publicly found",
    )
    if contact["email"]["address"]:
        print(
            "Confidence   :",
            contact["email"]["confidence"],
        )
        print(
            "Source       :",
            contact["email"]["source"],
        )

    print(
        "Phone        :",
        contact["phone"]["number"] or "not publicly found",
    )
    if contact["phone"]["number"]:
        print(
            "Confidence   :",
            contact["phone"]["confidence"],
        )
        print(
            "Source       :",
            contact["phone"]["source"],
        )

    print("\nCROSS-PLATFORM MATCHES")
    print("-" * 78)
    for match in result["foundAccounts"][:30]:
        comparison = match["comparison"]
        print(
            f"{match['platform']:<12} "
            f"@{match['username']:<24} "
            f"{comparison['score']:>5}% "
            f"{comparison['level'].upper():<6} "
            f"{match['url']}"
        )

    print("\nAI")
    print("-" * 78)
    print(
        "Provider     :",
        result["aiAnalysis"].get("provider", "none"),
    )
    print(
        "Overall      :",
        contact["overallConfidence"],
    )

    print("\nSTATS")
    print("-" * 78)
    for key, value in stats.items():
        print(f"{key:<25}: {value}")

    print("=" * 78)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "ContactUpdate v7.5 — consolidated version of "
            "the CorvelaAI contactupdate workflow."
        )
    )
    parser.add_argument(
        "username",
        help="TikTok username, with or without @",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Write complete JSON result to FILE",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Print JSON instead of the terminal summary",
    )
    args = parser.parse_args()

    try:
        result = run(args.username)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        LOG.exception("Fatal error")
        result = {
            "success": False,
            "error": str(exc),
        }

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
                default=str,
            ),
            encoding="utf-8",
        )
        print(f"JSON written to {args.json}")

    if args.pretty:
        print(json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
            default=str,
        ))
    else:
        print_report(result)

    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
