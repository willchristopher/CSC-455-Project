import re
from functools import lru_cache
from pathlib import Path

import idna


DATA = Path(__file__).resolve().parent / "data"
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def dns_name(hostname):
    """Return the lowercase ASCII name, validating internationalized labels."""
    hostname = hostname.lower()
    if not hostname.isascii() or "xn--" in hostname:
        hostname = idna.encode(hostname, uts46=True, std3_rules=True).decode("ascii")
    hostname = hostname.removesuffix(".")
    labels = hostname.split(".")
    if len(hostname) > 253 or not all(DNS_LABEL.fullmatch(label) for label in labels):
        raise ValueError("The URL has an invalid hostname.")
    return hostname


def load_suffixes():
    # The bundled Public Suffix List includes hosted sites and multi-part suffixes.
    exact, wildcard, exceptions = set(), set(), set()
    for line in (DATA / "public_suffix_list.dat").read_text(encoding="utf-8").splitlines():
        rule = line.strip()
        if not rule or rule.startswith("//"):
            continue
        if rule.startswith("!"):
            exceptions.add(dns_name(rule[1:]))
        elif rule.startswith("*."):
            wildcard.add(dns_name(rule[2:]))
        else:
            exact.add(dns_name(rule))
    return exact, wildcard, exceptions


EXACT_SUFFIXES, WILDCARD_SUFFIXES, EXCEPTIONS = load_suffixes()


@lru_cache(maxsize=16384)
def split_site(hostname):
    """Split a DNS name into its registrable label and public suffix."""
    labels = hostname.split(".")
    suffixes = [".".join(labels[index:]) for index in range(len(labels))]
    for index, suffix in enumerate(suffixes):
        if suffix in EXCEPTIONS:
            return labels[index], suffixes[index + 1]
    for index, suffix in enumerate(suffixes):
        wildcard = index + 1 < len(suffixes) and suffixes[index + 1] in WILDCARD_SUFFIXES
        if suffix in EXACT_SUFFIXES or wildcard or index == len(labels) - 1:
            return labels[index - 1] if index else "", suffix


