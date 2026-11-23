import json
import re
from dataclasses import dataclass
from functools import lru_cache
from ipaddress import ip_address
from math import log1p
from urllib.parse import unquote, urlsplit

from domains import DATA, dns_name, split_site


MODEL_PATH = DATA / "model.json"
ENCODED_BYTE = re.compile(r"%[0-9a-f]{2}", re.I)
IPV6_ENDPOINT = re.compile(r"\[[0-9a-f:.]+\](?::[0-9]+)?", re.I)
FEATURE_NAMES = (
    "host_length", "site_name_length", "subdomains", "host_digits",
    "host_hyphens", "internationalized_host", "ip_host", "has_user_info",
    "has_port", "path_length_log", "path_segments", "path_digits_log",
    "query_length_log", "query_parameters", "encoded_bytes_log", "has_fragment",
    "starts_with_www", "suffix_length",
)


@dataclass
class URLResult:
    hostname: str
    site: str
    score: float
    flagged: bool


def parse_link(raw_url):
    url = raw_url.strip()
    if not url:
        raise ValueError("Paste a URL to check.")
    if re.search(r"[\s\\\x00-\x1f\x7f]", url) or len(url) > 16384:
        raise ValueError("Enter one URL of up to 16,384 characters without spaces or backslashes.")

    # urlsplit separates the destination from user info, the path, and the query.
    try:
        parts = urlsplit(url)
        raw_hostname = parts.hostname
        port = parts.port
    except ValueError as error:
        raise ValueError("The URL has an invalid hostname or port.") from error
    if parts.scheme not in {"http", "https"} or not raw_hostname:
        raise ValueError("Enter a full web URL starting with http:// or https://.")

    endpoint = parts.netloc.rsplit("@", 1)[-1]
    bracketed = endpoint.startswith("[")
    if endpoint.endswith(":") or port == 0 or (bracketed and not IPV6_ENDPOINT.fullmatch(endpoint)):
        raise ValueError("The URL has an invalid hostname or port.")
    if not bracketed and ("[" in endpoint or "]" in endpoint):
        raise ValueError("The URL has an invalid hostname.")
    decoded_host = unquote(raw_hostname, errors="strict")
    try:
        address = ip_address(decoded_host.removesuffix("."))
    except ValueError:
        return parts, dns_name(decoded_host), False
    if (address.version == 6) != bracketed:
        raise ValueError("IPv6 addresses must use brackets.")
    return parts, str(address), True


def extract_features(raw_url):
    # Training and the GUI use the same URL measurements in the same order.
    parts, hostname, is_ip = parse_link(raw_url)
    name, suffix = (hostname, "") if is_ip else split_site(hostname)
    site = f"{name}.{suffix}" if name and suffix else hostname
    subdomains = 0 if is_ip else hostname.count(".") - site.count(".")
    # Both forms of a site homepage have the same empty path.
    path = parts.path if parts.path.strip("/") else ""
    query = parts.query

    # Log lengths give very long paths and queries less influence.
    features = (
        len(hostname), len(name), subdomains, sum(c.isdigit() for c in hostname),
        hostname.count("-"), int("xn--" in hostname), int(is_ip),
        int(parts.username is not None), int(parts.port is not None),
        log1p(len(path)), sum(bool(segment) for segment in path.split("/")),
        log1p(sum(c.isdigit() for c in path)), log1p(len(query)),
        query.count("&") + 1 if query else 0,
        log1p(len(ENCODED_BYTE.findall(parts.netloc + path + query))),
        int(bool(parts.fragment)), int(hostname.startswith("www.")), len(suffix),
    )
    return hostname, site, features


@dataclass
class PhishingModel:
    nodes: list[dict]
    threshold: float

    def score(self, features):
        # Start at the root and follow the learned checks to a leaf.
        node = self.nodes[0]
        while "feature" in node:
            branch = "left" if features[node["feature"]] <= node["cutoff"] else "right"
            node = self.nodes[node[branch]]
        return node["score"]


@lru_cache(maxsize=1)
def load_model():
    saved = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    if saved["features"] != list(FEATURE_NAMES) or "nodes" not in saved:
        raise ValueError("The saved model is out of date. Run train.py again.")
    return PhishingModel(saved["nodes"], saved["threshold"])


def analyze_url(raw_url):
    hostname, site, features = extract_features(raw_url)
    model = load_model()
    score = model.score(features)
    return URLResult(hostname, site, score, score >= model.threshold)
