#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 CSP HEADER CHECKER (CSPX)
 Content-Security-Policy and security-header analysis - CLI + Web App
--------------------------------------------------------------------------------
 Author  : Karanam Shrivasta
 GitHub  : https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta/
 Version : 1.0.0
--------------------------------------------------------------------------------
 WHAT THIS DOES
   Fetches the response headers for a URL and analyses them the way a reviewer
   would: it parses the Content-Security-Policy directive by directive, applies
   the spec's fallback rules, and reports what the policy actually protects
   against rather than whether a header merely exists. It also grades HSTS,
   X-Frame-Options, Referrer-Policy, Permissions-Policy, the cross-origin
   isolation headers, cookie flags and information-disclosure headers.

   The analyser is a pure function over a set of headers, so you can lint a
   policy string with no network access at all:
       cspx lint --policy "default-src 'self'; script-src 'unsafe-inline'"

 WHAT THIS IS NOT
   - Not a vulnerability scanner and not an exploit tool. It makes ordinary GET
     requests, exactly like opening the page in a browser, and reads only the
     response headers.
   - Not a guarantee. A grade of A means the headers look right; it says nothing
     about the application behind them. Headers are one control among many.
   - Not a substitute for reading your own policy. This tool explains its
     reasoning so you can disagree with it.

 REQUEST BEHAVIOUR
   One request per URL, plus one per redirect hop (capped). No crawling, no
   parameter fuzzing, no authentication, no cookies sent. The User-Agent
   identifies the tool honestly. Bulk scans are rate limited by default.
   No API keys, no third-party services: nothing is sent anywhere except the
   site you name.

 SAFETY
   By default the tool refuses to connect to loopback, private, link-local or
   cloud-metadata addresses. Server-side request forgery is the standard way a
   URL-fetching tool gets abused, so private targets require an explicit
   --allow-private flag and are recorded in the log when used.

 DATA INTEGRITY PROMISE
   Every finding comes from a header actually returned by the server. A header
   that is absent is reported as absent - never assumed, never defaulted. If a
   request fails, the failure is recorded and no grade is produced, because a
   site that could not be reached has not been assessed.

 LEGAL DISCLAIMER
   Check sites you own or are authorised to test. Reading public response
   headers is ordinarily benign, but automated requests against systems you do
   not control may still breach a terms of service or local law. Findings are
   heuristics based on public guidance and the CSP specification; verify them
   before acting. Provided "as is" with no warranty; the author accepts no
   liability for any loss or damage arising from use or misuse of this software.
================================================================================
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import socket
import sqlite3
import ssl
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

APP_NAME = "CSP Header Checker"
APP_SHORT = "CSPX"
VERSION = "1.0.0"
AUTHOR = "Karanam Shrivasta"
GITHUB = "https://github.com/mrshrivasta"
LINKEDIN = "https://www.linkedin.com/in/karanam-shrivasta/"
DEFAULT_DB = os.environ.get("CSPX_DB", "cspx.db")
USER_AGENT = f"{APP_SHORT}/{VERSION} (+{GITHUB}; security header checker; one request per URL)"

DISCLAIMER_SHORT = (
    "Reads response headers only - one ordinary GET per URL, no crawling, no payloads, "
    "no API keys. Check sites you own or are authorised to test. A good grade means the "
    "headers look right, not that the application is secure."
)
DISCLAIMER_LONG = textwrap.dedent(
    """\
    AUTHORISED USE ONLY. This tool issues ordinary GET requests and reads the response
    headers, the same thing a browser does when you open the page. It sends no payloads,
    no credentials and no cookies, and it does not crawl. Even so, automated requests
    against systems you do not control may breach a terms of service or local law - check
    sites you own or are authorised to test. Findings are heuristics derived from the CSP
    specification and public hardening guidance; a grade of A means the headers look
    right, and says nothing about the application behind them. Verify every finding
    before acting on it. Provided "as is" with no warranty; the author accepts no
    liability for any loss or damage arising from use or misuse of this software."""
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 22.0, "high": 12.0, "medium": 6.0, "low": 2.0, "info": 0.0}
SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
             "low": "#3e9dd8", "info": "#8b8f9b"}
CAT_COLOR = {"CSP": "#9775fa", "Transport": "#30a46c", "Framing": "#22b8cf",
             "Privacy": "#f06595", "Isolation": "#4c6ef5", "Cookies": "#ffa94d",
             "Disclosure": "#8b8f9b", "Transport/Cookies": "#30a46c"}

# ---------------------------------------------------------------------------
# CSP specification tables
# ---------------------------------------------------------------------------

# Directives that fall back when absent, in the order the spec resolves them.
FALLBACK_CHAIN = {
    "script-src-elem": ["script-src", "default-src"],
    "script-src-attr": ["script-src", "default-src"],
    "style-src-elem": ["style-src", "default-src"],
    "style-src-attr": ["style-src", "default-src"],
    "worker-src": ["child-src", "script-src", "default-src"],
    "frame-src": ["child-src", "default-src"],
    "script-src": ["default-src"],
    "style-src": ["default-src"],
    "img-src": ["default-src"],
    "connect-src": ["default-src"],
    "font-src": ["default-src"],
    "media-src": ["default-src"],
    "object-src": ["default-src"],
    "manifest-src": ["default-src"],
    "child-src": ["default-src"],
    "prefetch-src": ["default-src"],
}

# Directives that do NOT inherit from default-src. Leaving these out leaves a
# genuine gap, which is the single most common CSP mistake.
NO_FALLBACK = {
    "base-uri", "form-action", "frame-ancestors", "sandbox", "report-uri", "report-to",
    "upgrade-insecure-requests", "block-all-mixed-content", "require-trusted-types-for",
    "trusted-types", "require-sri-for", "plugin-types", "navigate-to",
}

KNOWN_DIRECTIVES = set(FALLBACK_CHAIN) | NO_FALLBACK | {"default-src"}

# Only these take source expressions. report-uri takes URIs, sandbox takes tokens,
# require-trusted-types-for takes 'script', trusted-types takes policy names - running
# source-expression validation over those produces nonsense findings.
SOURCE_LIST_DIRECTIVES = set(FALLBACK_CHAIN) | {
    "default-src", "base-uri", "form-action", "frame-ancestors", "navigate-to"}

DEPRECATED_DIRECTIVES = {
    "block-all-mixed-content": "Removed from the spec. Use upgrade-insecure-requests, or "
                               "simply serve everything over HTTPS.",
    "plugin-types": "Removed from the spec along with plugin support. Use object-src 'none'.",
    "referrer": "Never standardised as a CSP directive. Use the Referrer-Policy header.",
    "navigate-to": "Dropped from the specification; no browser ships it.",
    "prefetch-src": "Dropped from the specification.",
    "report-uri": "Superseded by report-to (with the Reporting-Endpoints header), though it "
                  "is still worth keeping for older browsers.",
}

CSP_KEYWORDS = {
    "'none'", "'self'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'",
    "'unsafe-hashes'", "'report-sample'", "'wasm-unsafe-eval'", "'inline-speculation-rules'",
    "'unsafe-allow-redirects'",
}

DANGEROUS_SCHEMES_IN_SCRIPT = {"data:", "blob:", "filesystem:", "http:", "*"}

# Hosts that commonly host user-supplied or JSONP-capable JavaScript. Allowing one
# in script-src can hand an attacker a way around the policy. This list is short,
# public knowledge, and deliberately not exhaustive - it flags for review, it does
# not prove a bypass exists.
BYPASSABLE_HOSTS = {
    "ajax.googleapis.com": "hosts AngularJS and other libraries that can execute "
                           "attacker-controlled expressions",
    "www.google.com": "historically exposed JSONP endpoints",
    "www.googleapis.com": "JSONP endpoints",
    "apis.google.com": "JSONP endpoints",
    "accounts.google.com": "open JSONP endpoints have existed here",
    "cdnjs.cloudflare.com": "serves AngularJS and similar libraries usable for bypass",
    "cdn.jsdelivr.net": "serves arbitrary npm and GitHub content",
    "unpkg.com": "serves arbitrary npm packages",
    "storage.googleapis.com": "user-controlled buckets",
    "s3.amazonaws.com": "user-controlled buckets",
    "translate.googleapis.com": "JSONP endpoints",
}
BYPASSABLE_SUFFIXES = {
    ".amazonaws.com": "user-controlled storage buckets",
    ".cloudfront.net": "user-controlled distributions",
    ".blob.core.windows.net": "user-controlled storage",
    ".appspot.com": "user-deployed applications",
    ".firebaseio.com": "user-controlled data",
    ".herokuapp.com": "user-deployed applications",
    ".netlify.app": "user-deployed sites",
    ".pages.dev": "user-deployed sites",
    ".github.io": "user-published pages",
}

SECURITY_HEADERS = [
    ("content-security-policy", "CSP", "Controls which resources the page may load and "
     "execute. The primary defence against cross-site scripting."),
    ("content-security-policy-report-only", "CSP", "Reports violations without enforcing "
     "them. Useful while rolling a policy out; it protects nothing on its own."),
    ("strict-transport-security", "Transport", "Forces HTTPS for the whole host."),
    ("x-frame-options", "Framing", "Legacy clickjacking control, superseded by "
     "frame-ancestors."),
    ("x-content-type-options", "Disclosure", "Stops browsers MIME-sniffing a response into "
     "a different content type."),
    ("referrer-policy", "Privacy", "Controls how much of the URL is sent to other sites."),
    ("permissions-policy", "Privacy", "Controls access to camera, microphone, geolocation "
     "and similar features."),
    ("cross-origin-opener-policy", "Isolation", "Isolates the browsing context group."),
    ("cross-origin-embedder-policy", "Isolation", "Required for cross-origin isolation."),
    ("cross-origin-resource-policy", "Isolation", "Controls who may embed this resource."),
    ("x-xss-protection", "Disclosure", "Legacy XSS filter. Should be absent or set to 0; "
     "the filter itself introduced vulnerabilities."),
]

INFO_DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                           "x-generator", "x-drupal-cache", "x-runtime", "x-version"]

GRADE_BANDS = [(90, "A"), (80, "B"), (70, "C"), (55, "D"), (35, "E"), (0, "F")]


def grade_for(score: float) -> tuple[str, str]:
    for cut, letter in GRADE_BANDS:
        if score >= cut:
            return letter, {"A": "#30a46c", "B": "#5bb98b", "C": "#ffb224",
                            "D": "#f76808", "E": "#e5484d", "F": "#e5484d"}[letter]
    return "F", "#e5484d"


# =============================================================================
# SECTION 1 - Utilities
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ts_pretty(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return iso


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def html_escape(s) -> str:
    s = "" if s is None else str(s)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def fmt_duration(seconds) -> str:
    if seconds is None:
        return "-"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    return f"{seconds:.1f} s"


def fmt_maxage(seconds: int) -> str:
    if seconds <= 0:
        return "0"
    days = seconds / 86400.0
    if days >= 365:
        return f"{days / 365:.1f} years"
    if days >= 1:
        return f"{days:.0f} days"
    return f"{seconds} seconds"


# =============================================================================
# SECTION 2 - CSP parsing
# =============================================================================

class Source:
    """One source expression inside a directive, classified."""

    __slots__ = ("raw", "kind", "note")

    def __init__(self, raw: str):
        self.raw = raw
        self.kind, self.note = self._classify(raw)

    @staticmethod
    def _classify(tok: str) -> tuple[str, str]:
        low = tok.lower()
        if low in CSP_KEYWORDS:
            return "keyword", ""
        if low.startswith("'nonce-"):
            body = tok[7:-1] if tok.endswith("'") else tok[7:]
            if len(body) < 8:
                return "nonce", "nonce looks short; use at least 128 bits of randomness"
            return "nonce", ""
        if re.match(r"^'sha(256|384|512)-", low):
            return "hash", ""
        if low.startswith("'") and low.endswith("'"):
            return "invalid", ("unknown quoted keyword - browsers ignore it, which may "
                               "silently weaken the policy")
        if re.match(r"^[a-z][a-z0-9+.-]*:$", low):
            return "scheme", ""
        if tok == "*":
            return "wildcard", ""
        if re.match(r"^[a-z][a-z0-9+.-]*://", low) or re.match(r"^\*?[\w.-]+", tok):
            return "host", ""
        return "invalid", "not a recognisable source expression"

    def host_part(self) -> str:
        """Bare hostname for a host source, lowercased, without scheme/port/path."""
        if self.kind != "host":
            return ""
        v = self.raw
        if "://" in v:
            v = v.split("://", 1)[1]
        v = v.split("/", 1)[0]
        v = v.rsplit(":", 1)[0] if re.search(r":\d+$", v) else v
        return v.lower()

    def to_dict(self):
        return {"raw": self.raw, "kind": self.kind, "note": self.note}


class Policy:
    """A parsed Content-Security-Policy."""

    def __init__(self, raw: str, report_only: bool = False):
        self.raw = (raw or "").strip()
        self.report_only = report_only
        self.directives: dict[str, list[Source]] = {}
        self.order: list[str] = []
        self.parse_notes: list[str] = []
        self._parse()

    def _parse(self):
        if not self.raw:
            return
        for chunk in self.raw.split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            parts = chunk.split()
            name = parts[0].lower()
            values = parts[1:]
            if name in self.directives:
                self.parse_notes.append(
                    f"'{name}' appears more than once; browsers honour the first "
                    f"occurrence and ignore the rest")
                continue
            self.directives[name] = [Source(v) for v in values]
            self.order.append(name)

    # -- resolution ---------------------------------------------------------
    def effective(self, directive: str) -> tuple[list[Source] | None, str]:
        """Resolve a directive through the spec's fallback chain.

        Returns (sources, origin) where origin explains where the value came
        from: the directive itself, a fallback, or nothing at all.
        """
        if directive in self.directives:
            return self.directives[directive], directive
        for parent in FALLBACK_CHAIN.get(directive, []):
            if parent in self.directives:
                return self.directives[parent], parent
        return None, ""

    def has(self, directive: str) -> bool:
        return directive in self.directives

    def keywords(self, directive: str) -> set[str]:
        srcs, _ = self.effective(directive)
        return {s.raw.lower() for s in (srcs or []) if s.kind == "keyword"}

    def has_nonce_or_hash(self, directive: str) -> bool:
        srcs, _ = self.effective(directive)
        return any(s.kind in ("nonce", "hash") for s in (srcs or []))

    def is_none(self, directive: str) -> bool:
        srcs, _ = self.effective(directive)
        return bool(srcs) and len(srcs) == 1 and srcs[0].raw.lower() == "'none'"

    def to_dict(self):
        return {"raw": self.raw, "report_only": self.report_only,
                "directives": {k: [s.to_dict() for s in v] for k, v in self.directives.items()},
                "order": self.order, "parse_notes": self.parse_notes}


# =============================================================================
# SECTION 3 - Findings
# =============================================================================

def F(category, header, title, severity, description, evidence="", recommendation="",
      reference=""):
    return {"category": category, "header": header, "title": title, "severity": severity,
            "description": description, "evidence": str(evidence)[:2000],
            "recommendation": recommendation, "reference": reference}


def analyse_csp(policy: Policy, headers: dict, url: str) -> list[dict]:
    """Analyse a parsed policy. Pure function - no network, no globals."""
    out: list[dict] = []
    ro = policy.report_only
    tag = " (report-only, so this is not enforced)" if ro else ""
    spec = "https://www.w3.org/TR/CSP3/"

    if not policy.raw:
        return out

    for note in policy.parse_notes:
        out.append(F("CSP", "Content-Security-Policy", "Policy syntax problem", "medium",
                     "The policy contains something browsers will not read the way you "
                     "probably intend.", note,
                     "Remove the duplicate directive and keep a single definition.", spec))

    unknown = [d for d in policy.order if d not in KNOWN_DIRECTIVES]
    if unknown:
        out.append(F("CSP", "Content-Security-Policy", "Unrecognised directive", "low",
                     "Browsers ignore directives they do not know. A typo here silently "
                     "removes the protection you thought you had.",
                     ", ".join(unknown),
                     "Check the spelling against the CSP specification.", spec))

    for d in policy.order:
        if d in DEPRECATED_DIRECTIVES:
            out.append(F("CSP", "Content-Security-Policy", f"Deprecated directive: {d}", "low",
                         DEPRECATED_DIRECTIVES[d], f"{d} is present in the policy",
                         "Replace it with the modern equivalent.", spec))

    for name, srcs in policy.directives.items():
        if name not in SOURCE_LIST_DIRECTIVES:
            continue  # not a source list, so source-expression rules do not apply
        bad = [s for s in srcs if s.kind == "invalid"]
        for s in bad:
            out.append(F("CSP", "Content-Security-Policy",
                         f"Invalid source expression in {name}", "medium",
                         "A source browsers cannot parse is skipped, which can leave the "
                         "directive weaker than intended.",
                         f"{name} {s.raw}  -  {s.note}",
                         "Correct or remove the value.", spec))

    # ---- script-src: the core of XSS protection ----
    script, origin = policy.effective("script-src")
    if script is None:
        out.append(F("CSP", "Content-Security-Policy",
                     "No script-src and no default-src", "critical",
                     "Nothing restricts where scripts may come from, so the policy provides "
                     "no cross-site scripting protection at all." + tag,
                     "neither script-src nor default-src is present",
                     "Start with: default-src 'self'; script-src 'self'; object-src 'none'; "
                     "base-uri 'none'", spec))
    else:
        kw = policy.keywords("script-src")
        nonce_or_hash = policy.has_nonce_or_hash("script-src")
        via = "" if origin == "script-src" else f" (inherited from {origin})"
        if "'unsafe-inline'" in kw and not nonce_or_hash:
            out.append(F("CSP", "Content-Security-Policy",
                         "script-src allows 'unsafe-inline'", "critical",
                         "Inline scripts are permitted, which is exactly what a cross-site "
                         "scripting payload needs. This defeats the main purpose of the "
                         "policy." + tag,
                         f"script-src{via}: " + " ".join(s.raw for s in script),
                         "Remove 'unsafe-inline' and adopt nonces or hashes: "
                         "script-src 'nonce-<random>' 'strict-dynamic'",
                         "OWASP CSP Cheat Sheet"))
        elif "'unsafe-inline'" in kw and nonce_or_hash:
            out.append(F("CSP", "Content-Security-Policy",
                         "'unsafe-inline' present alongside a nonce or hash", "info",
                         "Browsers that support nonces ignore 'unsafe-inline' when one is "
                         "present, so this is a deliberate and correct fallback for very old "
                         "browsers rather than a weakness.",
                         f"script-src{via}: " + " ".join(s.raw for s in script),
                         "Safe to keep. Drop it once you no longer support CSP1-era browsers.",
                         spec))
        if "'unsafe-eval'" in kw:
            out.append(F("CSP", "Content-Security-Policy",
                         "script-src allows 'unsafe-eval'", "high",
                         "eval(), new Function() and string timers stay available, which "
                         "turns many otherwise harmless injections into code execution." + tag,
                         f"script-src{via} contains 'unsafe-eval'",
                         "Remove it and replace the code that needs eval. If a framework "
                         "requires it, prefer a build step that precompiles templates.", spec))
        if "'unsafe-hashes'" in kw:
            out.append(F("CSP", "Content-Security-Policy",
                         "script-src allows 'unsafe-hashes'", "medium",
                         "This permits hashed inline event handlers, which widens the "
                         "attack surface compared with plain hashes." + tag,
                         f"script-src{via} contains 'unsafe-hashes'",
                         "Move event handlers into external scripts and drop the keyword.",
                         spec))
        wildcards = [s for s in script if s.kind == "wildcard"]
        if wildcards:
            out.append(F("CSP", "Content-Security-Policy",
                         "script-src allows any host (*)", "critical",
                         "Scripts may be loaded from anywhere on the internet, so the "
                         "directive provides no meaningful restriction." + tag,
                         f"script-src{via}: " + " ".join(s.raw for s in script),
                         "Replace * with 'self' plus the specific origins you need.", spec))
        schemes = [s.raw.lower() for s in script if s.kind == "scheme"]
        risky = [s for s in schemes if s in DANGEROUS_SCHEMES_IN_SCRIPT]
        if "data:" in risky:
            out.append(F("CSP", "Content-Security-Policy",
                         "script-src allows the data: scheme", "critical",
                         "A data: URI is attacker-controllable, so this permits arbitrary "
                         "script execution." + tag,
                         f"script-src{via} contains data:",
                         "Remove data: from script-src entirely.", spec))
        for s in schemes:
            if s in ("https:", "http:"):
                out.append(F("CSP", "Content-Security-Policy",
                             f"script-src allows any host over {s[:-1]}", "high",
                             "A bare scheme permits every host using it, which is barely "
                             "narrower than a wildcard." + tag,
                             f"script-src{via} contains {s}",
                             "List the specific origins you load scripts from.", spec))
        strict_dynamic = "'strict-dynamic'" in kw
        host_srcs = [s for s in script if s.kind == "host"]
        if strict_dynamic:
            out.append(F("CSP", "Content-Security-Policy",
                         "script-src uses 'strict-dynamic'", "info",
                         "Trust is propagated from nonced scripts to the scripts they load, "
                         "and host allowlists are ignored by supporting browsers. This is the "
                         "recommended modern pattern.",
                         f"script-src{via}: " + " ".join(s.raw for s in script),
                         "Keep it. Host entries remain only as a fallback for old browsers.",
                         "Google CSP guidance"))
        elif host_srcs:
            flagged = []
            for s in host_srcs:
                h = s.host_part()
                if h in BYPASSABLE_HOSTS:
                    flagged.append(f"{s.raw} ({BYPASSABLE_HOSTS[h]})")
                else:
                    for suffix, why in BYPASSABLE_SUFFIXES.items():
                        if h.endswith(suffix):
                            flagged.append(f"{s.raw} ({why})")
                            break
            if flagged:
                out.append(F("CSP", "Content-Security-Policy",
                             "script-src allowlist includes a host known to be bypassable",
                             "medium",
                             "Allowing an origin that serves user-supplied or JSONP-capable "
                             "JavaScript can give an attacker a way to execute code within "
                             "your policy. This flags the host for review; it does not prove "
                             "a bypass exists today." + tag,
                             "; ".join(flagged),
                             "Pin to specific paths where possible, self-host the library, or "
                             "move to a nonce plus 'strict-dynamic' so the allowlist stops "
                             "mattering.",
                             "Google CSP Evaluator research"))
            wide = [s.raw for s in host_srcs if s.raw.startswith("*.")]
            if wide:
                out.append(F("CSP", "Content-Security-Policy",
                             "script-src trusts entire wildcard domains", "low",
                             "Every current and future subdomain is trusted, including any "
                             "that get delegated or taken over later." + tag,
                             ", ".join(wide),
                             "Name the exact subdomains you use.", spec))
        if not any([nonce_or_hash, strict_dynamic]) and script and not policy.is_none(
                "script-src"):
            out.append(F("CSP", "Content-Security-Policy",
                         "script-src relies on a host allowlist", "low",
                         "Allowlist policies are hard to keep correct and are the usual "
                         "source of CSP bypasses. Nonce-based policies do not have this "
                         "problem.",
                         f"script-src{via}: " + " ".join(s.raw for s in script),
                         "Move to: script-src 'nonce-<random>' 'strict-dynamic' https: "
                         "'unsafe-inline'", "Google CSP guidance"))

    # ---- object-src: plugin-based script execution ----
    obj, obj_origin = policy.effective("object-src")
    if obj is None:
        out.append(F("CSP", "Content-Security-Policy", "object-src is not restricted", "high",
                     "Without object-src (and with no default-src to inherit from), <object> "
                     "and <embed> can be used to execute script in older plugin contexts."
                     + tag, "neither object-src nor default-src is present",
                     "Add: object-src 'none'", spec))
    elif not policy.is_none("object-src"):
        out.append(F("CSP", "Content-Security-Policy", "object-src is not 'none'", "medium",
                     "Almost no site needs plugin content. Setting it to 'none' removes a "
                     "whole class of bypass." + tag,
                     f"object-src (from {obj_origin}): " + " ".join(s.raw for s in obj),
                     "Set: object-src 'none'", spec))

    # ---- base-uri: nonce hijacking ----
    if not policy.has("base-uri"):
        out.append(F("CSP", "Content-Security-Policy", "base-uri is not set", "medium",
                     "base-uri does not inherit from default-src. Without it, an injected "
                     "<base> tag can redirect every relative script URL to an attacker's "
                     "host, which defeats a nonce-based policy." + tag,
                     "base-uri absent (it does not fall back to default-src)",
                     "Add: base-uri 'none'  (or 'self' if you genuinely use <base>)",
                     "OWASP CSP Cheat Sheet"))
    elif not (policy.is_none("base-uri")
              or {s.raw.lower() for s in policy.directives["base-uri"]} == {"'self'"}):
        out.append(F("CSP", "Content-Security-Policy", "base-uri is permissive", "low",
                     "A broad base-uri weakens the protection against <base> tag injection.",
                     "base-uri " + " ".join(s.raw for s in policy.directives["base-uri"]),
                     "Prefer base-uri 'none' or 'self'.", spec))

    # ---- form-action ----
    if not policy.has("form-action"):
        out.append(F("CSP", "Content-Security-Policy", "form-action is not set", "low",
                     "form-action does not inherit from default-src. Without it, an injected "
                     "form can post credentials to an attacker's server." + tag,
                     "form-action absent (it does not fall back to default-src)",
                     "Add: form-action 'self'", spec))

    # ---- frame-ancestors vs X-Frame-Options ----
    xfo = headers.get("x-frame-options", "")
    if not policy.has("frame-ancestors"):
        sev = "medium" if not xfo else "low"
        out.append(F("CSP", "Content-Security-Policy", "frame-ancestors is not set", sev,
                     "frame-ancestors does not inherit from default-src. It is the modern "
                     "clickjacking control and it supersedes X-Frame-Options."
                     + (" X-Frame-Options is present, which still covers current browsers."
                        if xfo else "") + tag,
                     f"frame-ancestors absent; X-Frame-Options: {xfo or 'also absent'}",
                     "Add: frame-ancestors 'none'  (or 'self' if you frame your own pages)",
                     spec))

    # ---- default-src ----
    if not policy.has("default-src"):
        missing = [d for d in ("script-src", "style-src", "img-src", "connect-src",
                               "font-src", "object-src")
                   if not policy.has(d)]
        if missing:
            out.append(F("CSP", "Content-Security-Policy", "No default-src fallback", "medium",
                         "Directives that are absent have nothing to inherit from, so those "
                         "resource types are unrestricted." + tag,
                         "unrestricted: " + ", ".join(missing),
                         "Add a default-src (commonly 'self') so gaps fail closed.", spec))
    elif policy.is_none("default-src"):
        out.append(F("CSP", "Content-Security-Policy", "default-src 'none' as the base", "info",
                     "The policy denies everything by default and opens up only what is "
                     "listed. This is the strongest starting point.", "default-src 'none'",
                     "Keep it.", spec))

    # ---- style-src ----
    style, style_origin = policy.effective("style-src")
    if style is not None and "'unsafe-inline'" in policy.keywords("style-src") \
            and not policy.has_nonce_or_hash("style-src"):
        out.append(F("CSP", "Content-Security-Policy",
                     "style-src allows 'unsafe-inline'", "low",
                     "Inline styles are permitted. The risk is much lower than for scripts, "
                     "but it still enables some data-exfiltration and UI-redressing tricks."
                     + tag,
                     f"style-src (from {style_origin}) contains 'unsafe-inline'",
                     "Use nonces or hashes for styles too, if practical.", spec))

    # ---- reporting ----
    if not (policy.has("report-uri") or policy.has("report-to")):
        out.append(F("CSP", "Content-Security-Policy", "No violation reporting configured",
                     "low",
                     "Without reporting you cannot tell whether the policy is blocking real "
                     "attacks or breaking your own pages.",
                     "neither report-to nor report-uri is present",
                     "Add report-to (with a Reporting-Endpoints header), and report-uri "
                     "alongside it for older browsers.", spec))
    elif policy.has("report-to") and not headers.get("reporting-endpoints") \
            and not headers.get("report-to"):
        out.append(F("CSP", "Content-Security-Policy",
                     "report-to is set but no endpoint is defined", "low",
                     "report-to names a reporting group that must be defined by a "
                     "Reporting-Endpoints (or legacy Report-To) header. Without it, no "
                     "reports are delivered.",
                     "report-to " + " ".join(s.raw for s in policy.directives["report-to"]),
                     "Add a Reporting-Endpoints header defining that group.", spec))

    # ---- trusted types ----
    if not policy.has("require-trusted-types-for"):
        out.append(F("CSP", "Content-Security-Policy", "Trusted Types not required", "info",
                     "require-trusted-types-for 'script' blocks dangerous DOM sinks such as "
                     "innerHTML outright. It is the strongest available defence against "
                     "DOM-based XSS, though it needs application changes.",
                     "require-trusted-types-for absent",
                     "Consider: require-trusted-types-for 'script'; trusted-types default",
                     "https://web.dev/trusted-types/"))

    # ---- mixed content ----
    if url.startswith("https://") and not policy.has("upgrade-insecure-requests"):
        out.append(F("CSP", "Content-Security-Policy", "upgrade-insecure-requests not set",
                     "info",
                     "This directive silently upgrades any leftover http:// subresource URLs "
                     "to https://, which is a cheap safety net during migrations.",
                     "upgrade-insecure-requests absent",
                     "Add: upgrade-insecure-requests", spec))

    if ro:
        out.append(F("CSP", "Content-Security-Policy-Report-Only",
                     "Policy is report-only and is not enforced", "high",
                     "The browser reports violations but blocks nothing. Report-Only is the "
                     "right way to trial a policy, but it provides no protection while it is "
                     "the only policy present.",
                     "delivered as Content-Security-Policy-Report-Only",
                     "Once the reports are clean, serve the same policy in the enforcing "
                     "Content-Security-Policy header.", spec))
    return out


# =============================================================================
# SECTION 4 - The other security headers
# =============================================================================

def _parse_kv(value: str) -> dict:
    out = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().strip('"')
        else:
            out[part.lower()] = True
    return out


def analyse_cookies(cookies: list[str], is_https: bool) -> list[dict]:
    out = []
    for raw in cookies:
        attrs = _parse_kv(raw)
        name = raw.split("=", 1)[0].strip()
        missing = []
        if is_https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        samesite = attrs.get("samesite")
        if not samesite:
            missing.append("SameSite")
        if missing:
            sev = "high" if "HttpOnly" in missing or "Secure" in missing else "medium"
            why = {
                "Secure": "Secure keeps the cookie off plaintext connections",
                "HttpOnly": "HttpOnly keeps it away from JavaScript, so a cross-site "
                            "scripting bug cannot read it",
                "SameSite": "SameSite limits when the browser attaches it to cross-site "
                            "requests",
            }
            have = [f for f in ("Secure", "HttpOnly", "SameSite") if f not in missing]
            desc = ". ".join(why[m] for m in missing) + "."
            if have:
                desc += f" This cookie already sets {' and '.join(have)}."
            out.append(F("Cookies", "Set-Cookie", f"Cookie '{name}' is missing "
                         + " and ".join(missing), sev, desc, raw[:300],
                         f"Set-Cookie: {name}=...; Secure; HttpOnly; SameSite=Lax",
                         "OWASP Session Management Cheat Sheet"))
        elif isinstance(samesite, str) and samesite.lower() == "none" and "secure" not in attrs:
            out.append(F("Cookies", "Set-Cookie", f"Cookie '{name}' uses SameSite=None "
                         "without Secure", "high",
                         "Browsers reject SameSite=None unless Secure is also set, so this "
                         "cookie is being dropped.", raw[:300],
                         "Add Secure, or use SameSite=Lax.",
                         "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie"))
    return out


def analyse_headers(headers: dict, cookies: list[str], url: str,
                    meta_csp: str | None = None) -> list[dict]:
    """Grade everything except the CSP body itself. Pure function."""
    out: list[dict] = []
    is_https = url.lower().startswith("https://")
    mdn = "https://developer.mozilla.org/docs/Web/HTTP/Headers/"

    # ---- CSP presence ----
    csp = headers.get("content-security-policy")
    cspro = headers.get("content-security-policy-report-only")
    if not csp and not cspro and not meta_csp:
        out.append(F("CSP", "Content-Security-Policy", "No Content-Security-Policy", "critical",
                     "The page ships no policy, so the browser applies no restriction on "
                     "where scripts, styles or frames may come from. This is the single "
                     "largest gap in this report.",
                     "neither the header nor a <meta http-equiv> policy was found",
                     "Start in report-only mode: "
                     "Content-Security-Policy-Report-Only: default-src 'self'; "
                     "object-src 'none'; base-uri 'none'",
                     "OWASP CSP Cheat Sheet"))
    if meta_csp and not csp:
        out.append(F("CSP", "Content-Security-Policy", "Policy delivered by <meta> tag only",
                     "medium",
                     "A meta-tag policy works, but it cannot use frame-ancestors, "
                     "report-uri or sandbox, and it only applies to content parsed after the "
                     "tag. The header is strictly better.",
                     f"<meta http-equiv=\"Content-Security-Policy\" content=\"{meta_csp[:180]}\">",
                     "Move the policy into a response header.", mdn + "Content-Security-Policy"))
    if csp and cspro:
        out.append(F("CSP", "Content-Security-Policy", "Both enforcing and report-only "
                     "policies are present", "info",
                     "This is the normal pattern for trialling a stricter policy: the "
                     "enforcing one protects users while the report-only one collects data "
                     "on what the stricter version would break.",
                     f"enforced: {csp[:90]}...  |  report-only: {cspro[:90]}...",
                     "No action needed.", ""))

    # ---- HSTS ----
    hsts = headers.get("strict-transport-security")
    if is_https:
        if not hsts:
            out.append(F("Transport", "Strict-Transport-Security", "No HSTS header", "high",
                         "Without HSTS a browser will still try plain HTTP first if a user "
                         "types the bare hostname, which leaves room for an interception "
                         "attack on that first request.",
                         "header absent on an HTTPS response",
                         "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                         mdn + "Strict-Transport-Security"))
        else:
            attrs = _parse_kv(hsts)
            try:
                max_age = int(str(attrs.get("max-age", "0")).strip())
            except (ValueError, TypeError):
                max_age = -1
            if max_age < 0:
                out.append(F("Transport", "Strict-Transport-Security", "HSTS max-age is "
                             "malformed", "medium",
                             "A max-age browsers cannot parse means the whole header is "
                             "ignored.", hsts, "Use an integer number of seconds.",
                             mdn + "Strict-Transport-Security"))
            elif max_age == 0:
                out.append(F("Transport", "Strict-Transport-Security", "HSTS max-age is 0",
                             "medium",
                             "max-age=0 tells the browser to forget the HSTS policy. That is "
                             "correct when deliberately turning HSTS off, and a mistake "
                             "otherwise.", hsts, "Set max-age=31536000 to enable it.",
                             mdn + "Strict-Transport-Security"))
            elif max_age < 15552000:
                out.append(F("Transport", "Strict-Transport-Security", "HSTS max-age is short",
                             "low",
                             f"max-age is {fmt_maxage(max_age)}. Six months (15552000) is the "
                             "usual minimum, and preload lists require one year.", hsts,
                             "Raise it to 31536000 once you are confident in your HTTPS setup.",
                             mdn + "Strict-Transport-Security"))
            if "includesubdomains" not in attrs:
                out.append(F("Transport", "Strict-Transport-Security",
                             "HSTS does not cover subdomains", "low",
                             "Subdomains stay reachable over plain HTTP, and a cookie set "
                             "there can often affect the parent domain.", hsts,
                             "Add includeSubDomains once every subdomain serves HTTPS.",
                             mdn + "Strict-Transport-Security"))
    elif hsts:
        out.append(F("Transport", "Strict-Transport-Security", "HSTS sent over plain HTTP",
                     "low", "Browsers ignore HSTS on an unencrypted response, so this header "
                     "has no effect here.", hsts,
                     "Serve the site over HTTPS and send HSTS there.",
                     mdn + "Strict-Transport-Security"))
    if not is_https:
        out.append(F("Transport", "-", "Checked over plain HTTP", "high",
                     "The URL was fetched without TLS, so every header in this report - and "
                     "everything else on the page - can be altered in transit.",
                     url, "Serve the site over HTTPS and redirect HTTP to it.", ""))

    # ---- framing ----
    xfo = (headers.get("x-frame-options") or "").strip()
    if xfo:
        val = xfo.upper()
        if val.startswith("ALLOW-FROM"):
            out.append(F("Framing", "X-Frame-Options", "X-Frame-Options uses ALLOW-FROM",
                         "medium",
                         "No current browser supports ALLOW-FROM, so this provides no "
                         "protection at all.", xfo,
                         "Use CSP frame-ancestors instead.", mdn + "X-Frame-Options"))
        elif val not in ("DENY", "SAMEORIGIN"):
            out.append(F("Framing", "X-Frame-Options", "X-Frame-Options value is not valid",
                         "medium", "Anything other than DENY or SAMEORIGIN is ignored.", xfo,
                         "Use DENY unless you frame your own pages.",
                         mdn + "X-Frame-Options"))
    elif not headers.get("content-security-policy", ""):
        out.append(F("Framing", "X-Frame-Options", "No clickjacking protection", "medium",
                     "Neither X-Frame-Options nor a CSP frame-ancestors directive is present, "
                     "so the page can be embedded in a hostile frame.",
                     "both X-Frame-Options and CSP are absent",
                     "Content-Security-Policy: frame-ancestors 'none'  (plus "
                     "X-Frame-Options: DENY for older browsers)", mdn + "X-Frame-Options"))

    # ---- content type sniffing ----
    xcto = (headers.get("x-content-type-options") or "").strip().lower()
    if not xcto:
        out.append(F("Disclosure", "X-Content-Type-Options", "No X-Content-Type-Options",
                     "medium",
                     "Browsers may guess a response's type from its contents, which can turn "
                     "an uploaded file into executable script.",
                     "header absent", "X-Content-Type-Options: nosniff",
                     mdn + "X-Content-Type-Options"))
    elif xcto != "nosniff":
        out.append(F("Disclosure", "X-Content-Type-Options", "X-Content-Type-Options is not "
                     "'nosniff'", "low", "Only the exact value 'nosniff' has any effect.",
                     xcto, "X-Content-Type-Options: nosniff", mdn + "X-Content-Type-Options"))

    # ---- referrer ----
    ref = (headers.get("referrer-policy") or "").strip().lower()
    leaky = {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin", ""}
    if not ref:
        out.append(F("Privacy", "Referrer-Policy", "No Referrer-Policy", "low",
                     "The browser default varies, and on some setups the full URL - including "
                     "any path or query that identifies a user - is sent to third-party sites.",
                     "header absent", "Referrer-Policy: strict-origin-when-cross-origin",
                     mdn + "Referrer-Policy"))
    elif ref in leaky:
        sev = "medium" if ref == "unsafe-url" else "low"
        out.append(F("Privacy", "Referrer-Policy", f"Referrer-Policy '{ref}' leaks URLs", sev,
                     "This value sends more of the URL to other origins than is usually "
                     "intended.", ref, "Referrer-Policy: strict-origin-when-cross-origin",
                     mdn + "Referrer-Policy"))

    # ---- permissions policy ----
    if not headers.get("permissions-policy") and not headers.get("feature-policy"):
        out.append(F("Privacy", "Permissions-Policy", "No Permissions-Policy", "low",
                     "Powerful features such as camera, microphone and geolocation are left "
                     "at their defaults for the page and everything it embeds.",
                     "header absent",
                     "Permissions-Policy: camera=(), microphone=(), geolocation=()",
                     mdn + "Permissions-Policy"))
    elif headers.get("feature-policy") and not headers.get("permissions-policy"):
        out.append(F("Privacy", "Feature-Policy", "Uses the deprecated Feature-Policy header",
                     "low", "Feature-Policy was renamed to Permissions-Policy and the old "
                     "name is being dropped.", headers.get("feature-policy", "")[:200],
                     "Send Permissions-Policy instead.", mdn + "Permissions-Policy"))

    # ---- cross-origin isolation ----
    coop = (headers.get("cross-origin-opener-policy") or "").strip().lower()
    if not coop:
        out.append(F("Isolation", "Cross-Origin-Opener-Policy", "No COOP header", "low",
                     "Without COOP, a page you open (or that opens you) keeps a reference to "
                     "your window, which is the basis of several cross-window attacks.",
                     "header absent", "Cross-Origin-Opener-Policy: same-origin",
                     mdn + "Cross-Origin-Opener-Policy"))
    if not headers.get("cross-origin-resource-policy"):
        out.append(F("Isolation", "Cross-Origin-Resource-Policy", "No CORP header", "info",
                     "CORP lets you state who may embed this resource, which limits "
                     "speculative cross-origin leaks.", "header absent",
                     "Cross-Origin-Resource-Policy: same-origin",
                     mdn + "Cross-Origin-Resource-Policy"))

    # ---- legacy XSS filter ----
    xxp = (headers.get("x-xss-protection") or "").strip()
    if xxp and not xxp.startswith("0"):
        out.append(F("Disclosure", "X-XSS-Protection", "Legacy XSS filter is enabled", "low",
                     "The old browser XSS filter is removed from every current browser, and "
                     "in its day it introduced vulnerabilities of its own. Setting it to 1 "
                     "achieves nothing today and was actively harmful in the past.", xxp,
                     "Remove the header, or send X-XSS-Protection: 0. Rely on CSP instead.",
                     mdn + "X-XSS-Protection"))

    # ---- information disclosure ----
    leaks = []
    for h in INFO_DISCLOSURE_HEADERS:
        v = headers.get(h)
        if v and re.search(r"\d+\.\d+", v):
            leaks.append(f"{h}: {v}")
        elif h in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version") and v:
            leaks.append(f"{h}: {v}")
    if leaks:
        out.append(F("Disclosure", "Server", "Server software and version disclosed", "low",
                     "Version banners let an attacker match your stack against known "
                     "vulnerabilities without probing for them. Removing them is not a "
                     "defence on its own, but it is free.",
                     "; ".join(leaks[:6]),
                     "Suppress or genericise these headers at the web server or proxy.", ""))

    out.extend(analyse_cookies(cookies, is_https))
    return out


def score_findings(findings: list[dict]) -> tuple[float, dict]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    penalty = sum(SEV_WEIGHT[s] * counts[s] for s in SEVERITIES)
    return round(clamp(100.0 - penalty, 0.0, 100.0), 1), counts


def analyse_all(headers: dict, cookies: list[str], url: str,
                meta_csp: str | None = None) -> dict:
    """Full analysis of one response. Pure function over headers - this is what
    makes offline linting and deterministic testing possible."""
    csp_raw = headers.get("content-security-policy")
    ro_raw = headers.get("content-security-policy-report-only")
    findings = analyse_headers(headers, cookies, url, meta_csp)
    policies = []
    if csp_raw:
        p = Policy(csp_raw, report_only=False)
        policies.append(p)
        findings += analyse_csp(p, headers, url)
    elif meta_csp:
        p = Policy(meta_csp, report_only=False)
        policies.append(p)
        findings += analyse_csp(p, headers, url)
    if ro_raw:
        p = Policy(ro_raw, report_only=True)
        policies.append(p)
        if not csp_raw:
            findings += analyse_csp(p, headers, url)
    score, counts = score_findings(findings)
    grade, colour = grade_for(score)
    return {"findings": findings, "score": score, "counts": counts, "grade": grade,
            "grade_colour": colour, "policies": policies,
            "policy": policies[0] if policies else None}


# =============================================================================
# SECTION 5 - Fetching (with an SSRF guard)
# =============================================================================

BLOCKED_REASONS = {
    "loopback": "loopback address",
    "private": "private (RFC1918) address",
    "link-local": "link-local address",
    "metadata": "cloud instance metadata service",
    "reserved": "reserved address",
    "multicast": "multicast address",
}


def classify_ip(ip: str) -> str | None:
    """Return a reason string when an address should not be fetched by default."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if str(addr) in ("169.254.169.254", "fd00:ec2::254"):
        return BLOCKED_REASONS["metadata"]
    if addr.is_loopback:
        return BLOCKED_REASONS["loopback"]
    if addr.is_link_local:
        return BLOCKED_REASONS["link-local"]
    if addr.is_private:
        return BLOCKED_REASONS["private"]
    if addr.is_multicast:
        return BLOCKED_REASONS["multicast"]
    if addr.is_reserved or addr.is_unspecified:
        return BLOCKED_REASONS["reserved"]
    return None


def resolve_host(host: str) -> tuple[list[str], str | None]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return [], f"DNS lookup failed: {e}"
    ips = sorted({i[4][0] for i in infos})
    return ips, None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Handle redirects ourselves so each hop can be recorded and re-checked."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalise_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    return raw


def fetch(url: str, timeout: float = 15.0, max_redirects: int = 5,
          allow_private: bool = False, insecure: bool = False,
          method: str = "GET", read_bytes: int = 65536,
          user_agent: str = USER_AGENT) -> dict:
    """Fetch response headers. One request per hop, no cookies, no credentials."""
    url = normalise_url(url)
    chain, hops = [], 0
    t0 = time.time()
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect,
                                         urllib.request.HTTPSHandler(context=ctx))
    current = url
    while True:
        parsed = urllib.parse.urlsplit(current)
        if parsed.scheme not in ("http", "https"):
            return {"ok": False, "url": url, "error": f"unsupported scheme "
                    f"'{parsed.scheme or '(none)'}' - only http and https are fetched",
                    "chain": chain}
        host = parsed.hostname
        if not host:
            return {"ok": False, "url": url, "error": "no hostname in URL", "chain": chain}
        ips, dns_err = resolve_host(host)
        if dns_err:
            return {"ok": False, "url": url, "error": dns_err, "chain": chain}
        blocked = [(ip, classify_ip(ip)) for ip in ips]
        bad = [(ip, why) for ip, why in blocked if why]
        if bad and not allow_private:
            ip, why = bad[0]
            return {"ok": False, "url": url, "chain": chain,
                    "error": (f"refusing to connect to {host} ({ip}): {why}. Fetching "
                              f"internal addresses is how a URL checker gets turned into a "
                              f"server-side request forgery tool. Pass --allow-private if "
                              f"this is your own host and you meant it.")}
        req = urllib.request.Request(current, method=method, headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en",
        })
        try:
            resp = opener.open(req, timeout=timeout)
            status = resp.status
            raw_headers = resp.headers
            body = b""
            if method == "GET":
                try:
                    body = resp.read(read_bytes)
                except Exception:
                    body = b""
            resp.close()
        except urllib.error.HTTPError as e:
            status = e.code
            raw_headers = e.headers
            try:
                body = e.read(read_bytes)
            except Exception:
                body = b""
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            hint = ""
            if isinstance(reason, ssl.SSLError) or "CERTIFICATE" in str(reason).upper():
                hint = (" TLS verification failed. This tool does not silently disable "
                        "certificate checking; use --insecure only for a host you control "
                        "and know is using a self-signed certificate.")
            return {"ok": False, "url": url, "chain": chain,
                    "error": f"request failed: {reason}.{hint}"}
        except Exception as e:
            return {"ok": False, "url": url, "chain": chain, "error": f"request failed: {e}"}

        chain.append({"url": current, "status": status, "ip": ips[0] if ips else "",
                      "location": raw_headers.get("Location", "")})
        if status in (301, 302, 303, 307, 308) and raw_headers.get("Location"):
            hops += 1
            if hops > max_redirects:
                return {"ok": False, "url": url, "chain": chain,
                        "error": f"more than {max_redirects} redirects"}
            current = urllib.parse.urljoin(current, raw_headers["Location"])
            continue

        headers = {}
        for k, v in raw_headers.items():
            k = k.lower()
            headers[k] = f"{headers[k]}, {v}" if k in headers else v
        cookies = raw_headers.get_all("Set-Cookie") or []
        meta_csp = None
        if body:
            text = body.decode("utf-8", "replace")
            m = re.search(
                r"""<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>""",
                text, re.I)
            if m:
                c = re.search(r"""content\s*=\s*["']([^"']+)["']""", m.group(0), re.I)
                if c:
                    meta_csp = c.group(1).strip()
        return {"ok": True, "url": url, "final_url": current, "status": status,
                "headers": headers, "header_pairs": [(k, v) for k, v in raw_headers.items()],
                "cookies": cookies, "meta_csp": meta_csp, "chain": chain,
                "ip": chain[0]["ip"] if chain else "", "host": host,
                "duration": time.time() - t0, "error": None,
                "private_target": bool(bad)}


# =============================================================================
# SECTION 6 - Database
# =============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, url TEXT NOT NULL, final_url TEXT, host TEXT, ip TEXT,
    status_code INTEGER, ok INTEGER DEFAULT 0, error TEXT, duration_ms INTEGER,
    redirects INTEGER DEFAULT 0, redirect_chain TEXT,
    score REAL, grade TEXT, mode TEXT DEFAULT 'live',
    csp_present INTEGER DEFAULT 0, csp_report_only INTEGER DEFAULT 0,
    csp_raw TEXT, csp_report_only_raw TEXT, meta_csp TEXT,
    headers_json TEXT, cookies_json TEXT, private_target INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0, critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0,
    medium INTEGER DEFAULT 0, low INTEGER DEFAULT 0, info INTEGER DEFAULT 0, note TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    category TEXT, header TEXT, title TEXT, severity TEXT, description TEXT,
    evidence TEXT, recommendation TEXT, reference TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS directives (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    report_only INTEGER DEFAULT 0, name TEXT, sources TEXT, source_count INTEGER,
    kinds TEXT, present INTEGER DEFAULT 1, inherited_from TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT, message TEXT, scan_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_find_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_dir_scan ON directives(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""

_DB_PATH = DEFAULT_DB


def set_db_path(p: str) -> None:
    global _DB_PATH
    _DB_PATH = p


def db_path() -> str:
    return _DB_PATH


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or _DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()


def q(sql: str, args: tuple = (), conn=None) -> list[sqlite3.Row]:
    own = conn is None
    conn = conn or connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        if own:
            conn.close()


def q1(sql: str, args: tuple = (), conn=None):
    rows = q(sql, args, conn)
    return rows[0] if rows else None


def log_event(level: str, source: str, message: str, scan_id=None, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute("INSERT INTO events (ts, level, source, message, scan_id) VALUES (?,?,?,?,?)",
                     (now_iso(), level.upper(), source,
                      " ".join(str(message).split())[:1000], scan_id))
        conn.commit()
    except Exception:
        pass
    finally:
        if own:
            conn.close()


def save_scan(fetched: dict, analysis: dict | None, mode: str = "live",
              note: str = "") -> int:
    conn = connect()
    try:
        init_db(conn)
        ok = fetched.get("ok", False)
        headers = fetched.get("headers", {}) or {}
        counts = (analysis or {}).get("counts", {s: 0 for s in SEVERITIES})
        findings = (analysis or {}).get("findings", [])
        chain = fetched.get("chain", [])
        cur = conn.execute(
            "INSERT INTO scans (ts, url, final_url, host, ip, status_code, ok, error,"
            " duration_ms, redirects, redirect_chain, score, grade, mode, csp_present,"
            " csp_report_only, csp_raw, csp_report_only_raw, meta_csp, headers_json,"
            " cookies_json, private_target, total_findings, critical, high, medium, low,"
            " info, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), fetched.get("url", ""), fetched.get("final_url"),
             fetched.get("host"), fetched.get("ip"), fetched.get("status"), int(ok),
             fetched.get("error"), int((fetched.get("duration") or 0) * 1000),
             max(len(chain) - 1, 0), json.dumps(chain),
             (analysis or {}).get("score"), (analysis or {}).get("grade"), mode,
             int(bool(headers.get("content-security-policy"))),
             int(bool(headers.get("content-security-policy-report-only"))),
             headers.get("content-security-policy"),
             headers.get("content-security-policy-report-only"),
             fetched.get("meta_csp"), json.dumps(headers),
             json.dumps(fetched.get("cookies", [])),
             int(bool(fetched.get("private_target"))), len(findings),
             counts.get("critical", 0), counts.get("high", 0), counts.get("medium", 0),
             counts.get("low", 0), counts.get("info", 0), note))
        sid = cur.lastrowid
        for f in findings:
            conn.execute("INSERT INTO findings (scan_id, category, header, title, severity,"
                         " description, evidence, recommendation, reference)"
                         " VALUES (?,?,?,?,?,?,?,?,?)",
                         (sid, f["category"], f["header"], f["title"], f["severity"],
                          f["description"], f["evidence"], f["recommendation"],
                          f["reference"]))
        for p in (analysis or {}).get("policies", []):
            for name in p.order:
                srcs = p.directives[name]
                conn.execute("INSERT INTO directives (scan_id, report_only, name, sources,"
                             " source_count, kinds, present, inherited_from)"
                             " VALUES (?,?,?,?,?,?,?,?)",
                             (sid, int(p.report_only), name,
                              " ".join(s.raw for s in srcs), len(srcs),
                              ",".join(sorted({s.kind for s in srcs})), 1, None))
            # record the directives that are only reachable through a fallback
            for name in FALLBACK_CHAIN:
                if name in p.directives:
                    continue
                srcs, origin = p.effective(name)
                if srcs is not None:
                    conn.execute("INSERT INTO directives (scan_id, report_only, name, sources,"
                                 " source_count, kinds, present, inherited_from)"
                                 " VALUES (?,?,?,?,?,?,?,?)",
                                 (sid, int(p.report_only), name,
                                  " ".join(s.raw for s in srcs), len(srcs),
                                  ",".join(sorted({s.kind for s in srcs})), 0, origin))
        conn.commit()
        if ok:
            log_event("INFO", "check",
                      f"Scan #{sid}: {fetched.get('url')} -> {fetched.get('status')} "
                      f"grade {(analysis or {}).get('grade')} "
                      f"({(analysis or {}).get('score')}/100), {len(findings)} findings",
                      sid, conn)
        else:
            log_event("ERROR", "check",
                      f"Scan #{sid}: {fetched.get('url')} failed - {fetched.get('error')}",
                      sid, conn)
        if fetched.get("private_target"):
            log_event("WARN", "ssrf-guard",
                      f"Scan #{sid} targeted a private address with --allow-private: "
                      f"{fetched.get('host')} ({fetched.get('ip')})", sid, conn)
        return sid
    finally:
        conn.close()


def latest_scan_id(conn=None):
    row = q1("SELECT id FROM scans WHERE ok=1 ORDER BY id DESC LIMIT 1", (), conn)
    if row:
        return row["id"]
    row = q1("SELECT id FROM scans ORDER BY id DESC LIMIT 1", (), conn)
    return row["id"] if row else None


def scan_summary(scan_id: int, conn=None):
    row = q1("SELECT * FROM scans WHERE id=?", (scan_id,), conn)
    if not row:
        return None
    d = dict(row)
    d["grade_colour"] = grade_for(d["score"] or 0)[1]
    return d


# =============================================================================
# SECTION 7 - Charts (hand-drawn SVG: no CDN, no JS charting library, offline)
# =============================================================================

def svg_pie(items, size=200, title="Findings by severity", fmt=lambda v: f"{v:g}"):
    items = [(l, float(v), c) for (l, v, c) in items if v and v > 0]
    total = sum(v for _, v, _ in items)
    if total <= 0:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    cx = cy = size / 2
    r_out, r_in = size / 2 - 10, size / 2 - 46
    parts, legend, angle = [], [], -90.0
    for label, value, color in items:
        sweep = 360.0 * value / total
        if abs(sweep - 360.0) < 1e-9:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.2f}" fill="none" '
                         f'stroke="{color}" stroke-width="{r_out - r_in:.2f}"/>')
        else:
            a0, a1 = math.radians(angle), math.radians(angle + sweep)
            x0, y0 = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
            x1, y1 = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
            x2, y2 = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
            x3, y3 = cx + r_in * math.cos(a0), cy + r_in * math.sin(a0)
            lg = 1 if sweep > 180 else 0
            parts.append(f'<path d="M {x0:.2f} {y0:.2f} A {r_out:.2f} {r_out:.2f} 0 {lg} 1 '
                         f'{x1:.2f} {y1:.2f} L {x2:.2f} {y2:.2f} A {r_in:.2f} {r_in:.2f} 0 '
                         f'{lg} 0 {x3:.2f} {y3:.2f} Z" fill="{color}">'
                         f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></path>')
        angle += sweep
        legend.append(f'<div class="lg"><i style="background:{color}"></i>'
                      f'<span>{html_escape(label)}</span><b>{html_escape(fmt(value))}</b>'
                      f'<em>{100.0 * value / total:.0f}%</em></div>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<div class="chart-row"><svg viewBox="0 0 {size} {size}" width="{size}" '
            f'height="{size}" role="img" aria-label="{html_escape(title)}">{"".join(parts)}'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" class="pie-n">'
            f'{html_escape(fmt(total))}</text></svg>'
            f'<div class="legend">{"".join(legend)}</div></div></figure>')


def svg_bar(items, width=430, title="By category", color="#9775fa",
            fmt=lambda v: f"{v:g}", maxv=None):
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items or all(v <= 0 for _, v in items):
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    row_h, gap, pad_l, pad_t = 23, 8, 148, 8
    height = pad_t * 2 + len(items) * (row_h + gap)
    mx = maxv or max(v for _, v in items) or 1
    bw = width - pad_l - 86
    rows = []
    for i, (label, value) in enumerate(items):
        y = pad_t + i * (row_h + gap)
        w = max(2.0, bw * value / mx)
        lbl = label if len(label) <= 20 else label[:19] + "\u2026"
        rows.append(
            f'<text x="{pad_l - 10}" y="{y + row_h * 0.7:.1f}" text-anchor="end" class="bl">'
            f'{html_escape(lbl)}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="{row_h}" rx="4" fill="{color}">'
            f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></rect>'
            f'<text x="{pad_l + bw + 8:.1f}" y="{y + row_h * 0.7:.1f}" class="bv">'
            f'{html_escape(fmt(value))}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" '
            f'aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


def svg_columns(items, width=470, height=210, title="Score history", ymax=100.0):
    if not items:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    pad_l, pad_b, pad_t, pad_r = 40, 26, 16, 8
    pw, ph = width - pad_l - pad_r, height - pad_t - pad_b
    slot = pw / len(items)
    bw = min(34.0, slot * 0.62)
    bars, grid = [], []
    for f in (0, 0.5, 1.0):
        y = pad_t + ph - ph * f
        grid.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" y2="{y:.1f}" '
                    f'class="gl"/><text x="{pad_l - 7}" y="{y + 4:.1f}" text-anchor="end" '
                    f'class="bl">{ymax * f:g}</text>')
    for i, (label, value, color) in enumerate(items):
        h = ph * clamp(float(value), 0, ymax) / ymax
        x = pad_l + slot * i + (slot - bw) / 2
        y = pad_t + ph - h
        bars.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{max(h, 1):.1f}" rx="3" '
            f'fill="{color}"><title>{html_escape(label)}: {value:g}</title></rect>'
            f'<text x="{x + bw / 2:.1f}" y="{y - 4:.1f}" text-anchor="middle" class="bv">'
            f'{value:g}</text>'
            f'<text x="{x + bw / 2:.1f}" y="{height - 8}" text-anchor="middle" class="bl">'
            f'{html_escape(label)}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" '
            f'aria-label="{html_escape(title)}">{"".join(grid)}{"".join(bars)}</svg></figure>')


def svg_gauge(score, grade, size=160):
    colour = grade_for(score)[1]
    r = size / 2 - 14
    cx = cy = size / 2
    circ = 2 * math.pi * r
    return (f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" '
            f'aria-label="Grade {grade}, score {score} of 100">'
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="#262a33" '
            f'stroke-width="13"/>'
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="{colour}" '
            f'stroke-width="13" stroke-linecap="round" '
            f'stroke-dasharray="{circ * clamp(score, 0, 100) / 100:.2f} {circ:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"/>'
            f'<text x="{cx}" y="{cy + 6}" text-anchor="middle" class="g-g" fill="{colour}">'
            f'{html_escape(grade)}</text>'
            f'<text x="{cx}" y="{cy + 26}" text-anchor="middle" class="g-l">'
            f'{score:g}/100</text></svg>')


def svg_matrix(rows, width=980, title="Header adoption across all checked sites"):
    """rows: (header, present_count, total). A compact adoption strip."""
    rows = [r for r in rows if r[2]]
    if not rows:
        return f'<div class="chart-empty">{html_escape(title)}: no successful scans yet</div>'
    cell_h, gap, pad_l = 22, 6, 250
    height = 10 + len(rows) * (cell_h + gap)
    bw = width - pad_l - 70
    out = []
    for i, (name, present, total) in enumerate(rows):
        y = 5 + i * (cell_h + gap)
        pct = 100.0 * present / total
        colour = "#30a46c" if pct >= 80 else ("#ffb224" if pct >= 40 else "#e5484d")
        out.append(
            f'<text x="{pad_l - 10}" y="{y + cell_h * 0.7:.1f}" text-anchor="end" class="bl">'
            f'{html_escape(name)}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{cell_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{max(2.0, bw * pct / 100):.1f}" '
            f'height="{cell_h}" rx="4" fill="{colour}"><title>{html_escape(name)}: '
            f'{present} of {total} sites</title></rect>'
            f'<text x="{pad_l + bw + 8}" y="{y + cell_h * 0.7:.1f}" class="bv">'
            f'{present}/{total}</text>')
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" '
            f'aria-label="{html_escape(title)}">{"".join(out)}</svg></figure>')


# =============================================================================
# SECTION 8 - Exports
# =============================================================================

def report_payload(scan_id=None, conn=None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        sid = scan_id or latest_scan_id(conn)
        scan = scan_summary(sid, conn) if sid else None
        return {
            "tool": APP_NAME, "version": VERSION, "author": AUTHOR,
            "generated_at": now_iso(), "disclaimer": DISCLAIMER_LONG,
            "method_note": (
                "Findings come from the response headers actually returned by the server. "
                "An absent header is reported as absent, never assumed. A grade reflects the "
                "headers only and says nothing about the application behind them."),
            "scan": scan,
            "findings": [dict(r) for r in q(
                "SELECT category,header,title,severity,description,evidence,recommendation,"
                "reference FROM findings WHERE scan_id=? ORDER BY CASE severity "
                "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                "WHEN 'low' THEN 3 ELSE 4 END, id", (sid,), conn)] if sid else [],
            "directives": [dict(r) for r in q(
                "SELECT name,sources,source_count,kinds,present,inherited_from,report_only "
                "FROM directives WHERE scan_id=? ORDER BY present DESC, name",
                (sid,), conn)] if sid else [],
            "headers": json.loads(scan["headers_json"]) if scan and scan["headers_json"] else {},
            "cookies_present": len(json.loads(scan["cookies_json"]))
                               if scan and scan["cookies_json"] else 0,
            "scans": [dict(r) for r in q("SELECT id,ts,url,status_code,ok,score,grade,"
                                         "total_findings FROM scans ORDER BY id DESC LIMIT 50",
                                         (), conn)],
        }
    finally:
        if own:
            conn.close()


def export_json(scan_id=None) -> str:
    return json.dumps(report_payload(scan_id), indent=2, default=str)


def export_csv(scan_id=None) -> str:
    conn = connect()
    try:
        sid = scan_id or latest_scan_id(conn)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow([f"# {APP_NAME} v{VERSION} by {AUTHOR}"])
        w.writerow([f"# scan_id={sid} generated={now_iso()}"])
        w.writerow([f"# {DISCLAIMER_SHORT}"])
        w.writerow(["severity", "category", "header", "title", "description", "evidence",
                    "recommendation", "reference"])
        for r in q("SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
                   "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                   "WHEN 'low' THEN 3 ELSE 4 END, id", (sid,), conn):
            w.writerow([r[k] for k in ("severity", "category", "header", "title",
                                       "description", "evidence", "recommendation",
                                       "reference")])
        return buf.getvalue()
    finally:
        conn.close()


def export_html(scan_id=None) -> str:
    conn = connect()
    try:
        p = report_payload(scan_id, conn)
        scan, esc = p["scan"], html_escape
        if not scan:
            return "<!doctype html><html><body><h1>No scans recorded</h1></body></html>"
        counts = {s: scan[s] or 0 for s in SEVERITIES}
        pie = svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])
        cats = {}
        for f in p["findings"]:
            cats[f["category"]] = cats.get(f["category"], 0) + 1
        bar = svg_bar(sorted(cats.items(), key=lambda x: -x[1]), title="Findings by area")
        gauge = svg_gauge(scan["score"] or 0, scan["grade"] or "F")
        frows = "".join(
            f'<tr><td><span class="pill" style="background:{SEV_COLOR[f["severity"]]}">'
            f'{esc(f["severity"].upper())}</span></td><td class="mono">{esc(f["header"])}</td>'
            f'<td><b>{esc(f["title"])}</b><div class="desc">{esc(f["description"])}</div>'
            + (f'<pre>{esc(f["evidence"])}</pre>' if f["evidence"] else "")
            + f'<div class="rec"><b>Fix:</b> {esc(f["recommendation"])}</div>'
            + (f'<div class="ref">{esc(f["reference"])}</div>' if f["reference"] else "")
            + "</td></tr>" for f in p["findings"])
        drows = "".join(
            f'<tr><td class="mono">{esc(d["name"])}'
            + ("" if d["present"] else
               f' <span class="tag">inherited from {esc(d["inherited_from"])}</span>')
            + f'</td><td class="mono">{esc(d["sources"] or "(empty)")}</td>'
              f'<td class="mono">{d["source_count"]}</td>'
              f'<td class="mono">{esc(d["kinds"])}</td></tr>' for d in p["directives"])
        hrows = "".join(
            f'<tr><td class="mono">{esc(k)}</td><td class="mono" style="word-break:break-all">'
            f'{esc(v[:400])}</td></tr>' for k, v in sorted(p["headers"].items()))
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_SHORT} report - {esc(scan['host'] or scan['url'])}</title><style>
 body{{font:14px/1.55 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e6e8ee}}
 .wrap{{max-width:1080px;margin:0 auto;padding:28px 20px 60px}}
 h1{{font-size:22px;margin:0 0 4px}} .meta{{color:#8b8f9b;font-size:12.5px;word-break:break-all}}
 h2{{font-size:12px;text-transform:uppercase;letter-spacing:.15em;color:#8b8f9b;
     margin:32px 0 12px;border-bottom:1px solid #262a33;padding-bottom:8px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}}
 .card{{background:#171a21;border:1px solid #262a33;border-radius:10px;padding:12px 14px}}
 .card .n{{font-size:23px;font-weight:700;font-family:ui-monospace,monospace}}
 .card .l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;color:#8b8f9b}}
 table{{width:100%;border-collapse:collapse;background:#171a21;border:1px solid #262a33;
        border-radius:10px;overflow:hidden;font-size:13px}}
 th{{text-align:left;font-size:10.5px;letter-spacing:.11em;text-transform:uppercase;
     color:#8b8f9b;padding:10px 12px;border-bottom:1px solid #262a33;background:#1c2029}}
 td{{padding:9px 12px;border-bottom:1px solid #1e222a;vertical-align:top}}
 .mono{{font-family:ui-monospace,Menlo,monospace;font-size:12px}}
 .pill{{color:#0f1115;font-weight:700;font-size:10px;padding:2px 8px;border-radius:20px}}
 .tag{{font-size:10px;border:1px solid #31363f;border-radius:5px;padding:1px 5px;color:#8b8f9b}}
 .desc{{color:#b6bac4;margin-top:4px;max-width:74ch}}
 .rec{{margin-top:6px;color:#8fd3b0;max-width:74ch}}
 .ref{{margin-top:4px;color:#6f7685;font-size:11.5px;font-family:ui-monospace,monospace}}
 pre{{background:#0f1115;border:1px solid #262a33;border-radius:6px;padding:8px;
      font-family:ui-monospace,monospace;font-size:11.5px;margin:7px 0 0;overflow:auto;
      white-space:pre-wrap;word-break:break-all;color:#b6bac4;max-height:180px}}
 .warn{{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:12px 14px;
        border-radius:10px;font-size:12.5px;margin:16px 0;white-space:pre-wrap}}
 .note{{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .charts{{display:flex;gap:20px;flex-wrap:wrap;align-items:center}}
 .chart{{margin:0;background:#171a21;border:1px solid #262a33;border-radius:10px;padding:14px 16px}}
 .chart figcaption{{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
   color:#8b8f9b;margin-bottom:10px;font-family:ui-monospace,monospace}}
 .chart-row{{display:flex;gap:16px;align-items:center;flex-wrap:wrap}}
 .chart-empty{{background:#171a21;border:1px dashed #31363f;border-radius:10px;padding:18px;
   color:#8b8f9b;font-size:12.5px}}
 .legend{{display:flex;flex-direction:column;gap:6px;min-width:150px}}
 .lg{{display:flex;align-items:center;gap:7px;font-size:12.5px}}
 .lg i{{width:11px;height:11px;border-radius:3px}} .lg span{{flex:1;text-transform:capitalize}}
 .lg em{{font-style:normal;color:#8b8f9b;font-size:11px}}
 text.bl{{fill:#8b8f9b;font:11px ui-monospace,monospace}}
 text.bv{{fill:#e6e8ee;font:11px ui-monospace,monospace}}
 rect.btrack{{fill:#1e222a}} line.gl{{stroke:#262a33;stroke-width:1}}
 text.pie-n{{fill:#e6e8ee;font:700 17px ui-monospace,monospace}}
 text.g-g{{font:700 34px ui-monospace,monospace}}
 text.g-l{{fill:#8b8f9b;font:11px ui-monospace,monospace}}
 footer{{margin-top:36px;color:#6f7685;font-size:12px;border-top:1px solid #262a33;padding-top:14px}}
 a{{color:#9775fa}}
</style></head><body><div class="wrap">
<h1>{APP_NAME} - report</h1>
<div class="meta">{esc(scan['url'])}
 {'&rarr; ' + esc(scan['final_url']) if scan['final_url'] != scan['url'] else ''}
 &middot; HTTP {scan['status_code']} &middot; {scan['duration_ms']} ms &middot;
 {ts_pretty(scan['ts'])}</div>
<div class="warn">{esc(DISCLAIMER_LONG)}</div>
<div class="note"><b>How to read this.</b> {esc(p['method_note'])}</div>
<div class="charts">{gauge}
 <div><div style="font-size:30px;font-weight:700">{esc(scan['grade'] or '-')}</div>
 <div class="meta">{scan['score']}/100 from {scan['total_findings']} findings</div></div></div>
<div class="grid">
 <div class="card"><div class="l">Critical</div>
  <div class="n" style="color:{SEV_COLOR['critical']}">{counts['critical']}</div></div>
 <div class="card"><div class="l">High</div>
  <div class="n" style="color:{SEV_COLOR['high']}">{counts['high']}</div></div>
 <div class="card"><div class="l">Medium</div>
  <div class="n" style="color:{SEV_COLOR['medium']}">{counts['medium']}</div></div>
 <div class="card"><div class="l">Low</div>
  <div class="n" style="color:{SEV_COLOR['low']}">{counts['low']}</div></div>
 <div class="card"><div class="l">Info</div><div class="n">{counts['info']}</div></div>
 <div class="card"><div class="l">CSP</div>
  <div class="n">{'yes' if scan['csp_present'] else ('report-only'
    if scan['csp_report_only'] else 'no')}</div></div>
</div>
<h2>Analytics</h2><div class="charts">{pie}{bar}</div>
<h2>Findings ({len(p['findings'])})</h2>
<table><tr><th>Severity</th><th>Header</th><th>Detail</th></tr>{frows}</table>
{'<h2>CSP directives</h2><table><tr><th>Directive</th><th>Sources</th><th>Count</th>'
 '<th>Kinds</th></tr>' + drows + '</table>' if drows else ''}
<h2>Response headers</h2>
<table><tr><th>Header</th><th>Value</th></tr>{hrows}</table>
<footer>Generated by {APP_NAME} v{VERSION} &middot; {AUTHOR} &middot;
 <a href="{GITHUB}">GitHub</a> &middot; <a href="{LINKEDIN}">LinkedIn</a><br>
 Headers are one control among many. This report does not assess the application behind
 them.</footer></div></body></html>"""
    finally:
        conn.close()


def analyse_policy_only(policy_str: str, report_only: bool = False) -> dict:
    """Lint a policy string with no network access and no other headers involved."""
    p = Policy(policy_str, report_only=report_only)
    findings = analyse_csp(p, {}, "https://example.invalid/")
    score, counts = score_findings(findings)
    grade, colour = grade_for(score)
    return {"findings": findings, "score": score, "counts": counts, "grade": grade,
            "grade_colour": colour, "policies": [p], "policy": p}


# =============================================================================
# SECTION 9 - Web application (5 pages, no CDN, no JavaScript libraries)
# =============================================================================

CSS = """
:root{
  --bg:#0f1115; --panel:#171a21; --panel-2:#1c2029; --line:#262a33; --line-2:#31363f;
  --tx:#e6e8ee; --tx-dim:#8b8f9b; --tx-mid:#b6bac4; --accent:#9775fa; --ok:#30a46c;
  --warn:#ffb224; --crit:#e5484d;
  --mono:ui-monospace,SFMono-Regular,'JetBrains Mono',Menlo,Consolas,'Courier New',monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
  font:14px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
header.top{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:9}
.hd{max-width:1180px;margin:0 auto;padding:12px 20px;display:flex;align-items:center;gap:16px;
  flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:-.4px;font-size:15px}
.brand b{color:var(--accent)}
.brand small{display:block;font-weight:400;font-size:10.5px;letter-spacing:.14em;
  text-transform:uppercase;color:var(--tx-dim)}
nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
nav a{font-family:var(--mono);font-size:12px;letter-spacing:.06em;text-transform:uppercase;
  padding:7px 11px;border-radius:6px;color:var(--tx-dim)}
nav a:hover{background:var(--panel-2);color:var(--tx);text-decoration:none}
nav a.on{background:var(--accent);color:#0b0d10;font-weight:600}
.wrap{max-width:1180px;margin:0 auto;padding:20px 20px 70px}
.banner{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:10px 14px;
  border-radius:9px;font-size:12.3px;margin-bottom:14px;line-height:1.5}
.banner.info{background:#12202a;border-color:#1c4a5e;color:#a8d8e8}
.banner.bad{background:#2a1216;border-color:#6b2229;color:#ffc9cd}
.banner b{color:#fff}
h1{font-size:19px;margin:0 0 3px;letter-spacing:-.3px}
h2{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
  color:var(--tx-dim);margin:28px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.sub{color:var(--tx-dim);font-size:12.5px;margin-bottom:14px;word-break:break-all}
.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.btn{font-family:var(--mono);font-size:12px;padding:8px 13px;border-radius:7px;cursor:pointer;
  border:1px solid var(--line-2);background:var(--panel-2);color:var(--tx);display:inline-block}
.btn:hover{border-color:var(--accent);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#0b0d10;font-weight:700}
select,input[type=text],input[type=number],textarea{font-family:var(--mono);font-size:12px;
  padding:7px 9px;background:var(--panel-2);color:var(--tx);border:1px solid var(--line-2);
  border-radius:7px}
input[type=text]{min-width:260px} textarea{width:100%;min-height:90px;line-height:1.5}
label.chk{font-family:var(--mono);font-size:12px;color:var(--tx-dim);display:flex;gap:5px;
  align-items:center}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.card .l{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
  color:var(--tx-dim)}
.card .n{font-size:24px;font-weight:700;line-height:1.3;font-family:var(--mono)}
.card .s{font-size:11.5px;color:var(--tx-dim)}
.hero{display:flex;gap:24px;align-items:center;flex-wrap:wrap;background:var(--panel);
  border:1px solid var(--line);border-radius:12px;padding:16px 20px}
.hero .meta{flex:1;min-width:250px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 14px;font-size:12.5px}
.kv dt{color:var(--tx-dim);font-family:var(--mono);font-size:11px;letter-spacing:.07em;
  text-transform:uppercase}
.kv dd{margin:0;word-break:break-all}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
  border-radius:11px;overflow:hidden;font-size:13px}
th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.12em;
  text-transform:uppercase;color:var(--tx-dim);padding:10px 12px;border-bottom:1px solid var(--line);
  background:var(--panel-2);white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid #1e222a;vertical-align:top}
tr:last-child td{border-bottom:none} tr:hover td{background:#1b1f27}
.mono{font-family:var(--mono);font-size:12px}
.num{font-family:var(--mono);font-size:12px;text-align:right}
.pill{display:inline-block;color:#0b0d10;font-weight:700;font-size:10px;padding:2px 8px;
  border-radius:20px;letter-spacing:.06em;font-family:var(--mono);white-space:nowrap}
.tag{display:inline-block;font-family:var(--mono);font-size:10.5px;padding:1px 6px;border-radius:5px;
  border:1px solid var(--line-2);color:var(--tx-dim)}
.tag.good{border-color:#1e5138;color:#7fd9ab} .tag.bad{border-color:#5a2326;color:#ff9b9e}
.tag.key{border-color:#4a3a6b;color:#c4b0f0} .tag.nonce{border-color:#1e5138;color:#7fd9ab}
.tag.hash{border-color:#1e5138;color:#7fd9ab} .tag.scheme{border-color:#5a4a1c;color:#ffd9a0}
.tag.wildcard{border-color:#5a2326;color:#ff9b9e} .tag.invalid{border-color:#5a2326;color:#ff9b9e}
.desc{color:var(--tx-mid);margin-top:4px;max-width:76ch}
.rec{margin-top:6px;color:#8fd3b0;font-size:12.5px;max-width:76ch}
.ref{margin-top:4px;color:#6f7685;font-size:11.5px;font-family:var(--mono)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:8px 10px;
  font-family:var(--mono);font-size:11.5px;margin:7px 0 0;max-height:180px;overflow:auto;
  white-space:pre-wrap;word-break:break-all;color:var(--tx-mid)}
details summary{cursor:pointer;color:var(--tx-dim);font-size:12px;font-family:var(--mono)}
.charts{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start}
.chart{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:11px;
  padding:14px 16px}
.chart.wide{width:100%}
.chart figcaption{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;
  text-transform:uppercase;color:var(--tx-dim);margin-bottom:10px}
.chart-row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.chart-empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;
  padding:20px;color:var(--tx-dim);font-size:12.5px;flex:1;min-width:250px}
.legend{display:flex;flex-direction:column;gap:6px;min-width:150px}
.lg{display:flex;align-items:center;gap:7px;font-size:12.5px}
.lg i{width:11px;height:11px;border-radius:3px;flex:none}
.lg span{flex:1;text-transform:capitalize} .lg b{font-family:var(--mono)}
.lg em{font-style:normal;color:var(--tx-dim);font-family:var(--mono);font-size:11px}
text.bl{fill:#8b8f9b;font:11px var(--mono)} text.bv{fill:#e6e8ee;font:11px var(--mono)}
rect.btrack{fill:#1e222a} line.gl{stroke:#262a33;stroke-width:1}
text.pie-n{fill:#e6e8ee;font:700 17px var(--mono)}
text.g-g{font:700 34px var(--mono)} text.g-l{fill:#8b8f9b;font:11px var(--mono)}
.chain{display:flex;flex-direction:column;gap:6px;font-family:var(--mono);font-size:12px}
.chain div{padding:6px 10px;background:var(--panel-2);border:1px solid var(--line);
  border-radius:7px;word-break:break-all}
.empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;padding:28px;
  text-align:center;color:var(--tx-dim)}
.empty b{display:block;color:var(--tx);margin-bottom:6px;font-size:15px}
footer{max-width:1180px;margin:0 auto;padding:16px 20px 40px;color:#6f7685;font-size:11.5px;
  border-top:1px solid var(--line);line-height:1.7}
.lvl-ERROR{color:var(--crit)} .lvl-WARN{color:var(--warn)} .lvl-INFO{color:var(--tx-dim)}
@media (max-width:640px){
  .hd{padding:10px 14px} .wrap{padding:14px 14px 50px} nav{margin-left:0;width:100%}
  .card .n{font-size:20px} table{font-size:12.2px} th,td{padding:8px 9px}
  input[type=text]{min-width:150px}
}
"""

BASE_TPL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ page }} - """ + APP_SHORT + """</title><style>""" + CSS + """</style></head><body>
<header class="top"><div class="hd">
 <div class="brand"><b>CSPX</b> CSP Header Checker
  <small>response headers only &middot; one request per URL</small></div>
 <nav>
  <a href="{{ url_for('page_overview') }}" class="{{ 'on' if nav=='overview' }}">Overview</a>
  <a href="{{ url_for('page_policy') }}" class="{{ 'on' if nav=='policy' }}">Policy</a>
  <a href="{{ url_for('page_headers') }}" class="{{ 'on' if nav=='headers' }}">Headers</a>
  <a href="{{ url_for('page_analytics') }}" class="{{ 'on' if nav=='analytics' }}">Analytics</a>
  <a href="{{ url_for('page_logs') }}" class="{{ 'on' if nav=='logs' }}">Logs</a>
 </nav></div></header>
<div class="wrap">
 <div class="banner"><b>Authorised use only.</b> """ + DISCLAIMER_SHORT + """</div>
 {% if error %}<div class="banner bad"><b>That check failed:</b> {{ error }}</div>{% endif %}
 {% block body %}{% endblock %}
</div>
<footer>""" + APP_NAME + """ v""" + VERSION + """ &middot; built by """ + AUTHOR + """ &middot;
 <a href=\"""" + GITHUB + """\" rel="noopener">GitHub</a> &middot;
 <a href=\"""" + LINKEDIN + """\" rel="noopener">LinkedIn</a><br>
 No API keys, no third-party services: results come only from the site you name. Loopback and
 private addresses are refused unless explicitly allowed.<br>
 Findings are heuristics from the CSP specification and public guidance - verify them before
 acting. Provided "as is" without warranty.</footer>
</body></html>"""

CHECKFORM_TPL = """
<div class="bar"><form method="post" action="{{ url_for('do_check') }}"
  style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
 <input type="text" name="url" placeholder="https://example.com" value="{{ last_url or '' }}"
  required>
 <label class="chk"><input type="checkbox" name="allow_private" value="1"> allow private
  addresses</label>
 <button class="btn primary" type="submit">Check headers</button>
</form>
{% if scan %}
<a class="btn" href="{{ url_for('export', fmt='html') }}?scan={{ scan.id }}">Export HTML</a>
<a class="btn" href="{{ url_for('export', fmt='json') }}?scan={{ scan.id }}">JSON</a>
<a class="btn" href="{{ url_for('export', fmt='csv') }}?scan={{ scan.id }}">CSV</a>
{% endif %}
</div>"""

EMPTY_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
""" + CHECKFORM_TPL + """
<div class="empty"><b>No checks run yet</b>
 Enter a URL above to fetch its response headers, or lint a policy string offline from the
 Policy page. Nothing is shown until a real response has been received - a site that could not
 be reached is not graded.
 <div class="mono" style="margin-top:12px;color:var(--tx-dim)">
  from the terminal: python3 csp_header_checker.py check --url https://example.com<br>
  offline: python3 csp_header_checker.py lint --policy "default-src 'self'"</div>
</div>{% endblock %}"""

OVERVIEW_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
<div class="sub">{{ scan.url }}{% if scan.final_url and scan.final_url != scan.url %}
 &rarr; {{ scan.final_url }}{% endif %}</div>
""" + CHECKFORM_TPL + """
{% if not scan.ok %}
<div class="banner bad"><b>This check did not complete:</b> {{ scan.error }}<br>
 No grade is shown, because a site that could not be reached has not been assessed.</div>
{% else %}
<div class="hero">
 {{ gauge|safe }}
 <div class="meta"><dl class="kv">
  <dt>Status</dt><dd>HTTP {{ scan.status_code }} &middot; {{ scan.duration_ms }} ms
   &middot; {{ scan.redirects }} redirect(s)</dd>
  <dt>Host</dt><dd>{{ scan.host }}{% if scan.ip %} ({{ scan.ip }}){% endif %}</dd>
  <dt>CSP</dt><dd>{% if scan.csp_present %}<span class="tag good">enforced</span>
   {% elif scan.csp_report_only %}<span class="tag bad">report-only, not enforced</span>
   {% elif scan.meta_csp %}<span class="tag bad">meta tag only</span>
   {% else %}<span class="tag bad">absent</span>{% endif %}
   {% if scan.csp_report_only and scan.csp_present %}
    <span class="tag">plus a report-only policy</span>{% endif %}</dd>
  <dt>Checked</dt><dd>{{ ts_pretty(scan.ts) }}</dd>
  <dt>Mode</dt><dd>{{ scan.mode }}{% if scan.private_target %}
   <span class="tag bad">private address, explicitly allowed</span>{% endif %}</dd>
 </dl></div>
</div>
<div class="grid">
{% for s in severities %}
 <div class="card"><div class="l">{{ s }}</div>
  <div class="n" style="color:{{ sev[s] }}">{{ scan[s] }}</div></div>
{% endfor %}
</div>
{% if chain|length > 1 %}
<h2>Redirect chain</h2>
<div class="chain">{% for h in chain %}
 <div>{{ loop.index }}. HTTP {{ h.status }} &middot; {{ h.url }}
  {% if h.location %}&rarr; {{ h.location }}{% endif %}</div>
{% endfor %}</div>
{% endif %}
<h2>Security header checklist</h2>
<table><tr><th>Header</th><th>Present</th><th>Value</th><th>What it does</th></tr>
{% for h in checklist %}
<tr><td class="mono">{{ h.name }}</td>
 <td>{% if h.present %}<span class="tag good">yes</span>
  {% else %}<span class="tag bad">no</span>{% endif %}</td>
 <td class="mono" style="max-width:340px;word-break:break-all">{{ h.value[:160] or '-' }}
  {% if h.value|length > 160 %}&hellip;{% endif %}</td>
 <td style="font-size:12px;color:var(--tx-mid)">{{ h.what }}</td></tr>
{% endfor %}</table>
<h2>Findings</h2>
{% if findings %}
<table><tr><th>Severity</th><th>Header</th><th>Detail</th></tr>
{% for f in findings %}
<tr><td><span class="pill" style="background:{{ sev[f.severity] }}">
 {{ f.severity|upper }}</span></td>
 <td class="mono">{{ f.header }}</td>
 <td><b>{{ f.title }}</b><div class="desc">{{ f.description }}</div>
  {% if f.evidence %}<details><summary>Evidence</summary><pre>{{ f.evidence }}</pre></details>
  {% endif %}
  <div class="rec">Fix: {{ f.recommendation }}</div>
  {% if f.reference %}<div class="ref">{{ f.reference }}</div>{% endif %}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty">No findings were raised.</div>{% endif %}
{% endif %}
{% endblock %}"""

POLICY_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Policy</h1>
<div class="sub">Directive by directive, with the spec's fallback rules applied.
 {% if scan %}From scan #{{ scan.id }} of {{ scan.url }}.{% endif %}</div>
<div class="bar"><form method="post" action="{{ url_for('do_lint') }}" style="width:100%">
 <textarea name="policy" placeholder="Paste a policy to lint offline, e.g.
default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'"
>{{ last_policy or '' }}</textarea>
 <div style="margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
  <label class="chk"><input type="checkbox" name="report_only" value="1"> treat as
   report-only</label>
  <button class="btn primary" type="submit">Lint this policy</button>
  <span class="mono" style="color:var(--tx-dim);font-size:11.5px">no network request is
   made</span>
 </div>
</form></div>
{% if not scan %}
<div class="empty"><b>No policy to show</b> Check a URL, or paste a policy above to lint it
 offline.</div>
{% else %}
{% if scan.csp_raw or scan.csp_report_only_raw or scan.meta_csp %}
<h2>Raw policy</h2>
<pre>{{ scan.csp_raw or scan.csp_report_only_raw or scan.meta_csp }}</pre>
{% if scan.csp_report_only_raw and scan.csp_raw %}
<div class="sub" style="margin-top:10px">Report-only policy also present:</div>
<pre>{{ scan.csp_report_only_raw }}</pre>{% endif %}
<h2>Directives</h2>
<table><tr><th>Directive</th><th>Sources</th><th>Kinds</th><th>Origin</th></tr>
{% for d in directives %}
<tr><td class="mono">{{ d.name }}</td>
 <td class="mono" style="word-break:break-all">{{ d.sources or "(empty)" }}</td>
 <td>{% for k in (d.kinds or '').split(',') %}{% if k %}
  <span class="tag {{ k }}">{{ k }}</span>{% endif %}{% endfor %}</td>
 <td>{% if d.present %}<span class="tag good">declared</span>
  {% else %}<span class="tag">inherits {{ d.inherited_from }}</span>{% endif %}</td></tr>
{% endfor %}</table>
<h2>Directives with no protection</h2>
{% if gaps %}
<table><tr><th>Directive</th><th>Why it matters</th></tr>
{% for g in gaps %}<tr><td class="mono">{{ g.name }}</td>
 <td style="font-size:12.5px;color:var(--tx-mid)">{{ g.why }}</td></tr>{% endfor %}</table>
{% else %}<div class="chart-empty">Every directive this tool checks is either declared or
 inherits from default-src.</div>{% endif %}
<h2>CSP findings</h2>
{% if findings %}
<table><tr><th>Severity</th><th>Detail</th></tr>
{% for f in findings %}<tr>
 <td><span class="pill" style="background:{{ sev[f.severity] }}">{{ f.severity|upper }}</span></td>
 <td><b>{{ f.title }}</b><div class="desc">{{ f.description }}</div>
  {% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}
  <div class="rec">Fix: {{ f.recommendation }}</div></td></tr>{% endfor %}</table>
{% else %}<div class="chart-empty">No CSP findings.</div>{% endif %}
{% else %}
<div class="empty"><b>This response carried no CSP</b>
 There is nothing to break down. The Overview page explains what that means.</div>
{% endif %}
{% endif %}
{% endblock %}"""

HEADERS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Headers</h1>
<div class="sub">Every response header returned{% if scan %} by {{ scan.final_url or scan.url }}
 {% endif %}, exactly as received.</div>
{% if not scan or not scan.ok %}
<div class="empty"><b>No successful response to show</b> Run a check from the Overview page.</div>
{% else %}
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <input type="hidden" name="scan" value="{{ scan.id }}">
 <input type="text" name="qq" value="{{ f_q }}" placeholder="filter header name or value">
 <label class="chk"><input type="checkbox" name="security" value="1"
  {{ 'checked' if only_security }}> security headers only</label>
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_headers') }}?scan={{ scan.id }}">Reset</a>
</form></div>
<div class="grid">
 <div class="card"><div class="l">Headers</div><div class="n">{{ total }}</div></div>
 <div class="card"><div class="l">Security headers</div>
  <div class="n">{{ n_sec }}/{{ n_sec_possible }}</div>
  <div class="s">of the ones checked</div></div>
 <div class="card"><div class="l">Cookies set</div><div class="n">{{ n_cookies }}</div></div>
 <div class="card"><div class="l">Status</div><div class="n">{{ scan.status_code }}</div></div>
</div>
{% if rows %}
<table><tr><th>Header</th><th>Value</th><th>Role</th></tr>
{% for h in rows %}
<tr><td class="mono">{{ h.name }}
 {% if h.security %}<span class="tag key">security</span>{% endif %}</td>
 <td class="mono" style="word-break:break-all">{{ h.value }}</td>
 <td style="font-size:12px;color:var(--tx-mid)">{{ h.what }}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty"><b>Nothing matches that filter</b></div>{% endif %}
{% if cookies %}
<h2>Set-Cookie</h2>
<table><tr><th>Cookie</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Raw</th></tr>
{% for c in cookies %}
<tr><td class="mono">{{ c.name }}</td>
 <td>{% if c.secure %}<span class="tag good">yes</span>{% else %}
  <span class="tag bad">no</span>{% endif %}</td>
 <td>{% if c.httponly %}<span class="tag good">yes</span>{% else %}
  <span class="tag bad">no</span>{% endif %}</td>
 <td>{% if c.samesite %}<span class="tag good">{{ c.samesite }}</span>{% else %}
  <span class="tag bad">unset</span>{% endif %}</td>
 <td class="mono" style="word-break:break-all;font-size:11px">{{ c.raw[:160] }}</td></tr>
{% endfor %}</table>
{% endif %}
{% endif %}
{% endblock %}"""

ANALYTICS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Analytics</h1>
<div class="sub">Charts are plain SVG rendered from the SQLite database - no external chart
 library, no network calls.</div>
<div class="bar">
 <a class="btn" href="{{ url_for('export', fmt='html') }}">Export HTML</a>
 <a class="btn" href="{{ url_for('export', fmt='json') }}">JSON</a>
 <a class="btn" href="{{ url_for('export', fmt='csv') }}">CSV</a>
</div>
{% if scan %}
<h2>Scan #{{ scan.id }}</h2>
<div class="charts">{{ pie|safe }}{{ bar_cat|safe }}</div>
<div class="charts" style="margin-top:16px">{{ bar_hdr|safe }}{{ bar_kinds|safe }}</div>
{% endif %}
<h2>Across every site checked</h2>
<div class="charts">{{ matrix|safe }}</div>
<div class="charts" style="margin-top:16px">{{ col_scores|safe }}{{ pie_grades|safe }}</div>
<h2>Check history</h2>
{% if scans %}
<table><tr><th>#</th><th>When</th><th>URL</th><th>Status</th><th>Grade</th><th>Score</th>
 <th>C</th><th>H</th><th>M</th><th>L</th><th>Time</th></tr>
{% for s in scans %}<tr>
 <td class="mono"><a href="{{ url_for('page_overview') }}?scan={{ s.id }}">#{{ s.id }}</a></td>
 <td class="mono">{{ s.ts[:19].replace('T',' ') }}</td>
 <td class="mono" style="max-width:280px;word-break:break-all">{{ s.url }}</td>
 <td class="mono">{{ s.status_code or 'failed' }}</td>
 <td class="mono"><b style="color:{{ s.colour }}">{{ s.grade or '-' }}</b></td>
 <td class="num">{{ s.score if s.score is not none else '-' }}</td>
 <td class="num" style="color:{{ sev.critical }}">{{ s.critical }}</td>
 <td class="num" style="color:{{ sev.high }}">{{ s.high }}</td>
 <td class="num" style="color:{{ sev.medium }}">{{ s.medium }}</td>
 <td class="num">{{ s.low }}</td>
 <td class="num">{{ s.duration_ms }} ms</td></tr>{% endfor %}</table>
{% else %}<div class="empty">No checks yet.</div>{% endif %}
{% endblock %}"""

LOGS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Logs</h1><div class="sub">Every check, lint, export and refused request, stored locally in
 {{ dbfile }}.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <select name="level"><option value="">All levels</option>
  {% for l in ['INFO','WARN','ERROR'] %}<option value="{{ l }}" {{ 'selected' if l==f_level }}>
   {{ l }}</option>{% endfor %}</select>
 <select name="limit">{% for n in [50,100,250,500,1000] %}
  <option value="{{ n }}" {{ 'selected' if n==limit }}>last {{ n }}</option>{% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="search message">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_logs') }}">Reset</a>
</form></div>
<div class="grid">
 <div class="card"><div class="l">Events</div><div class="n">{{ counts.total }}</div></div>
 <div class="card"><div class="l">Errors</div>
  <div class="n" style="color:var(--crit)">{{ counts.ERROR }}</div></div>
 <div class="card"><div class="l">Warnings</div>
  <div class="n" style="color:var(--warn)">{{ counts.WARN }}</div></div>
 <div class="card"><div class="l">Info</div><div class="n">{{ counts.INFO }}</div></div>
</div>
{% if rows %}
<table><tr><th>Time (UTC)</th><th>Level</th><th>Source</th><th>Message</th><th>Scan</th></tr>
{% for e in rows %}<tr><td class="mono">{{ e.ts[:19].replace('T',' ') }}</td>
 <td class="mono lvl-{{ e.level }}"><b>{{ e.level }}</b></td>
 <td class="mono">{{ e.source }}</td><td>{{ e.message }}</td>
 <td class="mono">{{ ('#' ~ e.scan_id) if e.scan_id else '-' }}</td></tr>{% endfor %}</table>
{% else %}<div class="empty"><b>No log entries match</b></div>{% endif %}
{% endblock %}"""

TEMPLATES = {"base.html": BASE_TPL, "empty.html": EMPTY_TPL, "overview.html": OVERVIEW_TPL,
             "policy.html": POLICY_TPL, "headers.html": HEADERS_TPL,
             "analytics.html": ANALYTICS_TPL, "logs.html": LOGS_TPL}

GAP_REASONS = {
    "base-uri": "An injected <base> tag can repoint every relative script URL, which defeats "
                "a nonce-based policy. Does not inherit from default-src.",
    "form-action": "An injected form can post credentials to an attacker. Does not inherit "
                   "from default-src.",
    "frame-ancestors": "Clickjacking protection. Does not inherit from default-src.",
    "object-src": "Plugin content is a classic route to script execution; 'none' costs "
                  "nothing.",
    "script-src": "Nothing restricts where scripts come from.",
}

try:
    from flask import (Flask, Response, jsonify, redirect, render_template, request, url_for)
    from jinja2 import ChoiceLoader, DictLoader
    HAVE_FLASK = True
except Exception:  # pragma: no cover
    HAVE_FLASK = False


def build_app():
    if not HAVE_FLASK:
        raise SystemExit("Flask is not installed. Install it with:  pip install flask\n"
                         "(The CLI works without Flask; only the web app needs it.)")
    app = Flask(__name__)
    app.jinja_loader = ChoiceLoader([DictLoader(TEMPLATES), app.jinja_loader])

    def ctx(nav, conn, **kw):
        base = {"nav": nav, "page": nav.capitalize(), "sev": SEV_COLOR,
                "severities": SEVERITIES, "ts_pretty": ts_pretty,
                "error": request.args.get("error"), "last_url": None, "last_policy": None}
        row = q1("SELECT url FROM scans WHERE mode='live' ORDER BY id DESC LIMIT 1", (), conn)
        if row:
            base["last_url"] = row["url"]
        base.update(kw)
        return base

    def pick_scan(conn):
        try:
            sid = int(request.args.get("scan", "") or 0)
        except ValueError:
            sid = 0
        if sid and scan_summary(sid, conn):
            return scan_summary(sid, conn)
        sid = latest_scan_id(conn)
        return scan_summary(sid, conn) if sid else None

    @app.route("/")
    def page_overview():
        conn = connect()
        try:
            scan = pick_scan(conn)
            if not scan:
                return render_template("empty.html", **ctx("overview", conn))
            headers = json.loads(scan["headers_json"] or "{}")
            checklist = [{"name": name, "present": bool(headers.get(name)),
                          "value": headers.get(name, ""), "what": what}
                         for name, _cat, what in SECURITY_HEADERS]
            return render_template("overview.html", **ctx(
                "overview", conn, scan=scan, checklist=checklist,
                chain=json.loads(scan["redirect_chain"] or "[]"),
                gauge=svg_gauge(scan["score"] or 0, scan["grade"] or "-"),
                findings=q("SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
                           "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                           "WHEN 'low' THEN 3 ELSE 4 END, id", (scan["id"],), conn)))
        finally:
            conn.close()

    @app.route("/policy")
    def page_policy():
        conn = connect()
        try:
            scan = pick_scan(conn)
            if not scan:
                return render_template("policy.html", **ctx("policy", conn, scan=None))
            raw = scan["csp_raw"] or scan["csp_report_only_raw"] or scan["meta_csp"]
            gaps = []
            if raw:
                pol = Policy(raw, report_only=not scan["csp_raw"])
                for name, why in GAP_REASONS.items():
                    srcs, _ = pol.effective(name)
                    if srcs is None:
                        gaps.append({"name": name, "why": why})
            return render_template("policy.html", **ctx(
                "policy", conn, scan=scan, gaps=gaps,
                directives=q("SELECT * FROM directives WHERE scan_id=? ORDER BY present DESC, "
                             "name", (scan["id"],), conn),
                findings=q("SELECT * FROM findings WHERE scan_id=? AND category='CSP' "
                           "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                           "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
                           (scan["id"],), conn)))
        finally:
            conn.close()

    @app.route("/headers")
    def page_headers():
        conn = connect()
        try:
            scan = pick_scan(conn)
            if not scan or not scan["ok"]:
                return render_template("headers.html", **ctx("headers", conn, scan=scan))
            headers = json.loads(scan["headers_json"] or "{}")
            cookies_raw = json.loads(scan["cookies_json"] or "[]")
            term = request.args.get("qq", "").strip().lower()
            only_sec = request.args.get("security") == "1"
            sec_map = {n: w for n, _c, w in SECURITY_HEADERS}
            rows = []
            for k, v in sorted(headers.items()):
                is_sec = k in sec_map
                if only_sec and not is_sec:
                    continue
                if term and term not in k.lower() and term not in str(v).lower():
                    continue
                rows.append({"name": k, "value": v, "security": is_sec,
                             "what": sec_map.get(k, "")})
            cookies = []
            for raw in cookies_raw:
                attrs = _parse_kv(raw)
                cookies.append({"name": raw.split("=", 1)[0].strip(), "raw": raw,
                                "secure": "secure" in attrs, "httponly": "httponly" in attrs,
                                "samesite": attrs.get("samesite") or ""})
            return render_template("headers.html", **ctx(
                "headers", conn, scan=scan, rows=rows, cookies=cookies, f_q=term,
                only_security=only_sec, total=len(headers), n_cookies=len(cookies_raw),
                n_sec=sum(1 for n in sec_map if headers.get(n)),
                n_sec_possible=len(sec_map)))
        finally:
            conn.close()

    @app.route("/analytics")
    def page_analytics():
        conn = connect()
        try:
            scan = pick_scan(conn)
            kw = {"scan": scan}
            if scan:
                sid = scan["id"]
                cats = q("SELECT category, COUNT(*) c FROM findings WHERE scan_id=? "
                         "GROUP BY category ORDER BY c DESC", (sid,), conn)
                hdrs = q("SELECT header, COUNT(*) c FROM findings WHERE scan_id=? "
                         "GROUP BY header ORDER BY c DESC LIMIT 10", (sid,), conn)
                kinds = {}
                for d in q("SELECT kinds FROM directives WHERE scan_id=? AND present=1",
                           (sid,), conn):
                    for k in (d["kinds"] or "").split(","):
                        if k:
                            kinds[k] = kinds.get(k, 0) + 1
                kw.update(
                    pie=svg_pie([(s, scan[s] or 0, SEV_COLOR[s]) for s in SEVERITIES]),
                    bar_cat=svg_bar([(r["category"], r["c"]) for r in cats],
                                    title="Findings by area"),
                    bar_hdr=svg_bar([(r["header"], r["c"]) for r in hdrs],
                                    title="Findings by header", color="#22b8cf"),
                    bar_kinds=svg_bar(sorted(kinds.items(), key=lambda x: -x[1]),
                                      title="CSP source expression kinds", color="#30a46c"))
            ok_scans = q("SELECT * FROM scans WHERE ok=1 AND mode='live'", (), conn)
            total = len(ok_scans)
            adoption = []
            if total:
                for name, _c, _w in SECURITY_HEADERS:
                    present = 0
                    for s in ok_scans:
                        if json.loads(s["headers_json"] or "{}").get(name):
                            present += 1
                    adoption.append((name, present, total))
            hist = q("SELECT id, score, grade FROM scans WHERE ok=1 AND score IS NOT NULL "
                     "ORDER BY id DESC LIMIT 12", (), conn)
            hist = list(reversed([dict(h) for h in hist]))
            grades = {}
            for s in q("SELECT grade FROM scans WHERE ok=1 AND grade IS NOT NULL", (), conn):
                grades[s["grade"]] = grades.get(s["grade"], 0) + 1
            scans = []
            for s in q("SELECT * FROM scans ORDER BY id DESC LIMIT 25", (), conn):
                d = dict(s)
                d["colour"] = grade_for(d["score"] or 0)[1]
                scans.append(d)
            kw.update(
                matrix=svg_matrix(adoption),
                col_scores=svg_columns([(f"#{h['id']}", h["score"] or 0,
                                         grade_for(h["score"] or 0)[1]) for h in hist],
                                       title="Score by check"),
                pie_grades=svg_pie([(g, n, grade_for({"A": 95, "B": 85, "C": 75, "D": 60,
                                                      "E": 45, "F": 10}.get(g, 0))[1])
                                    for g, n in sorted(grades.items())],
                                   title="Grades awarded"),
                scans=scans)
            return render_template("analytics.html", **ctx("analytics", conn, **kw))
        finally:
            conn.close()

    @app.route("/logs")
    def page_logs():
        conn = connect()
        try:
            level = request.args.get("level", "").strip().upper()
            term = request.args.get("qq", "").strip()
            try:
                limit = clamp(int(request.args.get("limit", 100)), 10, 1000)
            except ValueError:
                limit = 100
            sql, args = "SELECT * FROM events WHERE 1=1", []
            if level in ("INFO", "WARN", "ERROR"):
                sql += " AND level=?"
                args.append(level)
            if term:
                sql += " AND (message LIKE ? OR source LIKE ?)"
                args += [f"%{term}%"] * 2
            sql += " ORDER BY id DESC LIMIT ?"
            args.append(limit)
            counts = {"total": q1("SELECT COUNT(*) c FROM events", (), conn)["c"]}
            for lv in ("INFO", "WARN", "ERROR"):
                counts[lv] = q1("SELECT COUNT(*) c FROM events WHERE level=?", (lv,), conn)["c"]
            return render_template("logs.html", **ctx(
                "logs", conn, rows=q(sql, tuple(args), conn), counts=counts, limit=limit,
                f_level=level, f_q=term, dbfile=os.path.abspath(db_path())))
        finally:
            conn.close()

    @app.post("/check")
    def do_check():
        url = (request.form.get("url") or "").strip()
        allow_private = request.form.get("allow_private") == "1"
        if not url:
            return redirect(url_for("page_overview") + "?error="
                            + urllib.parse.quote("no URL given"))
        res = fetch(url, allow_private=allow_private)
        analysis = None
        if res["ok"]:
            analysis = analyse_all(res["headers"], res["cookies"], res["final_url"],
                                   res["meta_csp"])
        sid = save_scan(res, analysis, mode="live", note="from the web UI")
        if not res["ok"]:
            return redirect(url_for("page_overview") + f"?scan={sid}&error="
                            + urllib.parse.quote(res["error"]))
        return redirect(url_for("page_overview") + f"?scan={sid}")

    @app.post("/lint")
    def do_lint():
        policy = (request.form.get("policy") or "").strip()
        ro = request.form.get("report_only") == "1"
        if not policy:
            return redirect(url_for("page_policy") + "?error="
                            + urllib.parse.quote("no policy text given"))
        analysis = analyse_policy_only(policy, report_only=ro)
        fake = {"ok": True, "url": "policy-lint", "final_url": "policy-lint", "host": "",
                "ip": "", "status": 0, "headers": {"content-security-policy-report-only"
                                                   if ro else "content-security-policy": policy},
                "cookies": [], "meta_csp": None, "chain": [], "duration": 0.0, "error": None}
        sid = save_scan(fake, analysis, mode="lint", note="offline policy lint")
        log_event("INFO", "lint", f"Linted a pasted policy: grade {analysis['grade']} "
                  f"({analysis['score']}/100), {len(analysis['findings'])} findings", sid)
        return redirect(url_for("page_policy") + f"?scan={sid}")

    @app.route("/export/<fmt>")
    def export(fmt):
        try:
            sid = int(request.args.get("scan", "") or 0) or None
        except ValueError:
            sid = None
        fmt = fmt.lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body, mime = export_json(sid), "application/json"
        elif fmt == "csv":
            body, mime = export_csv(sid), "text/csv"
        elif fmt == "html":
            body, mime = export_html(sid), "text/html"
        else:
            return Response("Unsupported format. Use json, csv or html.", 400,
                            mimetype="text/plain")
        log_event("INFO", "export", f"Exported the report as {fmt.upper()}", sid)
        return Response(body, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="cspx-report-{stamp}.{fmt}"'})

    @app.route("/api/summary")
    def api_summary():
        sid = latest_scan_id()
        if not sid:
            return jsonify({"error": "no checks yet"}), 404
        return jsonify({"tool": APP_NAME, "version": VERSION,
                        "disclaimer": DISCLAIMER_SHORT, "scan": scan_summary(sid)})

    @app.errorhandler(404)
    def nf(_e):
        return Response("404 - page not found. Valid pages: / /policy /headers /analytics "
                        "/logs", 404, mimetype="text/plain")

    return app


def serve(host: str, port: int, debug: bool = False):
    app = build_app()
    init_db()
    log_event("INFO", "web", f"Web app started on http://{host}:{port} (db={db_path()})")
    print(f"\n  {APP_NAME} v{VERSION} - by {AUTHOR}")
    print(f"  {'-' * 66}")
    print(f"  Web app : http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}")
    print(f"  Database: {os.path.abspath(db_path())}")
    print(f"  Pages   : /  /policy  /headers  /analytics  /logs")
    if host == "0.0.0.0":
        print("  WARNING : bound to 0.0.0.0 - this UI has no authentication and will fetch\n"
              "            any URL submitted to it. Use 127.0.0.1 unless you have a very\n"
              "            good reason and a firewall in front of it.")
    print(f"  {textwrap.fill(DISCLAIMER_SHORT, 66, subsequent_indent='  ')}")
    print(f"  {'-' * 66}\n  Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


# =============================================================================
# SECTION 10 - Command line interface
# =============================================================================

def line(char="-", n=78):
    print(char * n)


def banner():
    print(f"\n{APP_NAME} v{VERSION}  |  {AUTHOR}")
    line()
    print(textwrap.fill(DISCLAIMER_SHORT, 78))
    line()


def _print_findings(findings, limit=None, indent="  "):
    shown = findings[:limit] if limit else findings
    for f in shown:
        print(f"\n{indent}[{f['severity'].upper():^8}] {f['title']}")
        print(f"{indent}           {f['header']}")
        for l in textwrap.wrap(f["description"], 70):
            print(f"{indent}    {l}")
        if f["evidence"]:
            ev = " ".join(str(f["evidence"]).split())
            print(f"{indent}    evidence: {ev[:200]}{'...' if len(ev) > 200 else ''}")
        if f["recommendation"]:
            for l in textwrap.wrap("fix: " + f["recommendation"], 70):
                print(f"{indent}    {l}")
    if limit and len(findings) > limit:
        print(f"\n{indent}... {len(findings) - limit} more")


def _grade_block(analysis, prefix="  "):
    bars = int(round((analysis["score"]) / 5))
    print(f"{prefix}[{'#' * bars}{'.' * (20 - bars)}]  {analysis['score']}/100   "
          f"grade {analysis['grade']}")
    c = analysis["counts"]
    print(f"{prefix}critical {c['critical']}   high {c['high']}   medium {c['medium']}   "
          f"low {c['low']}   info {c['info']}")


def cmd_check(a):
    banner()
    url = normalise_url(a.url)
    print(f"Checking {url}")
    if a.allow_private:
        print("  --allow-private is set: internal addresses will be fetched and this is "
              "recorded in the log.")
    if a.insecure:
        print("  WARNING: --insecure disables TLS certificate verification for this request.")
    res = fetch(url, timeout=a.timeout, max_redirects=a.redirects,
                allow_private=a.allow_private, insecure=a.insecure)
    analysis = None
    if res["ok"]:
        analysis = analyse_all(res["headers"], res["cookies"], res["final_url"],
                               res["meta_csp"])
    sid = save_scan(res, analysis, mode="live", note=a.note or "")
    if not res["ok"]:
        print(f"\n  FAILED: {res['error']}")
        print("\n  No grade is shown: a site that could not be reached has not been assessed.")
        line()
        return 2
    chain = res["chain"]
    print(f"  HTTP {res['status']} in {res['duration'] * 1000:.0f} ms"
          + (f", {len(chain) - 1} redirect(s)" if len(chain) > 1 else ""))
    if len(chain) > 1:
        for i, hop in enumerate(chain, 1):
            print(f"    {i}. {hop['status']}  {hop['url']}")
    print(f"  final URL: {res['final_url']}")
    line()
    _grade_block(analysis)
    line()
    headers = res["headers"]
    print("  SECURITY HEADERS")
    for name, _cat, _what in SECURITY_HEADERS:
        v = headers.get(name)
        mark = "[ok]" if v else "[--]"
        val = (" " + v[:70] + ("..." if len(v) > 70 else "")) if v else " absent"
        print(f"   {mark} {name}{val}")
    line()
    if a.json:
        print(json.dumps({"url": url, "final_url": res["final_url"],
                          "status": res["status"], "grade": analysis["grade"],
                          "score": analysis["score"], "counts": analysis["counts"],
                          "findings": analysis["findings"]}, indent=2))
    else:
        print(f"  FINDINGS ({len(analysis['findings'])})")
        _print_findings(analysis["findings"], a.show)
        line()
        print(f"  Full detail:  python3 {os.path.basename(__file__)} findings --scan {sid}")
        print(f"  Web app    :  python3 {os.path.basename(__file__)} serve")
        line()
    return _exit_code(a, analysis)


def _exit_code(a, analysis) -> int:
    """Non-zero exit for CI use, if the caller asked for a threshold."""
    if getattr(a, "fail_on", None):
        want = a.fail_on.lower()
        if want in SEVERITIES:
            idx = SEVERITIES.index(want)
            for s in SEVERITIES[:idx + 1]:
                if analysis["counts"].get(s):
                    print(f"  exit 1: at least one '{s}' finding "
                          f"(--fail-on {want})")
                    return 1
        elif want in "abcdef" and len(want) == 1:
            if "abcdef".index(analysis["grade"].lower()) > "abcdef".index(want):
                print(f"  exit 1: grade {analysis['grade']} is worse than {want.upper()} "
                      f"(--fail-on {want})")
                return 1
    return 0


def cmd_lint(a):
    banner()
    policy = a.policy
    if a.policy_file:
        with open(a.policy_file) as fh:
            policy = fh.read()
    elif a.stdin or not policy:
        if not policy:
            print("Reading the policy from standard input...\n")
            policy = sys.stdin.read()
    policy = (policy or "").strip()
    if not policy:
        print("No policy given. Use --policy, --policy-file or pipe it in.")
        return 1
    print("Linting offline - no network request is made.\n")
    analysis = analyse_policy_only(policy, report_only=a.report_only)
    pol = analysis["policy"]
    print(f"  {len(pol.directives)} directive(s) parsed"
          + (" (report-only)" if a.report_only else ""))
    line()
    _grade_block(analysis)
    line()
    print("  DIRECTIVES")
    for name in pol.order:
        srcs = pol.directives[name]
        kinds = ",".join(sorted({s.kind for s in srcs})) or "empty"
        print(f"   {name:<28} {kinds:<22} {' '.join(s.raw for s in srcs)[:60]}")
    inherited = []
    for name in sorted(FALLBACK_CHAIN):
        if name in pol.directives:
            continue
        srcs, origin = pol.effective(name)
        if srcs is not None:
            inherited.append(f"{name} <- {origin}")
    if inherited:
        print("\n  INHERITED THROUGH FALLBACK")
        for i in inherited:
            print(f"   {i}")
    gaps = [n for n in GAP_REASONS if pol.effective(n)[0] is None]
    if gaps:
        print("\n  NO PROTECTION AT ALL")
        for g in gaps:
            print(f"   {g}")
            for l in textwrap.wrap(GAP_REASONS[g], 68):
                print(f"      {l}")
    line()
    print(f"  FINDINGS ({len(analysis['findings'])})")
    _print_findings(analysis["findings"], a.show)
    line()
    if a.save:
        fake = {"ok": True, "url": "policy-lint", "final_url": "policy-lint", "host": "",
                "ip": "", "status": 0,
                "headers": {"content-security-policy-report-only" if a.report_only
                            else "content-security-policy": policy},
                "cookies": [], "meta_csp": None, "chain": [], "duration": 0.0, "error": None}
        sid = save_scan(fake, analysis, mode="lint", note="offline policy lint")
        print(f"  Saved as scan #{sid}.")
        line()
    return _exit_code(a, analysis)


def cmd_bulk(a):
    banner()
    try:
        with open(a.file) as fh:
            urls = [l.strip() for l in fh if l.strip() and not l.strip().startswith("#")]
    except OSError as e:
        print(f"Could not read {a.file}: {e}")
        return 1
    print(f"{len(urls)} URL(s) from {a.file}, {a.delay}s between requests "
          f"(one request per URL, plus redirects).\n")
    print(f"{'GRADE':<6} {'SCORE':>6}  {'STATUS':>6}  URL")
    line()
    worst = 0
    for i, u in enumerate(urls):
        res = fetch(u, timeout=a.timeout, allow_private=a.allow_private)
        analysis = analyse_all(res["headers"], res["cookies"], res["final_url"],
                               res["meta_csp"]) if res["ok"] else None
        save_scan(res, analysis, mode="live", note=f"bulk from {os.path.basename(a.file)}")
        if res["ok"]:
            print(f"{analysis['grade']:<6} {analysis['score']:>6}  {res['status']:>6}  {u}")
            worst = max(worst, "abcdef".index(analysis["grade"].lower()))
        else:
            print(f"{'-':<6} {'-':>6}  {'FAIL':>6}  {u}  ({res['error'][:60]})")
        if i < len(urls) - 1:
            time.sleep(a.delay)
    line()
    print(f"Done. Reports:  python3 {os.path.basename(__file__)} scans")
    return 0


def cmd_show(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No checks yet. Run:  check --url https://example.com")
        return
    s = scan_summary(sid)
    if not s:
        print(f"Scan #{sid} not found.")
        return
    line("=")
    print(f"  SCAN #{s['id']}  {s['url']}")
    if s["final_url"] and s["final_url"] != s["url"]:
        print(f"  final: {s['final_url']}")
    print(f"  {ts_pretty(s['ts'])}  |  {s['duration_ms']} ms  |  mode {s['mode']}")
    line("=")
    if not s["ok"]:
        print(f"  FAILED: {s['error']}")
        line()
        return
    print(f"  HTTP {s['status_code']}   grade {s['grade']}   score {s['score']}/100")
    print(f"  critical {s['critical']}   high {s['high']}   medium {s['medium']}   "
          f"low {s['low']}   info {s['info']}")
    csp = ("enforced" if s["csp_present"] else
           "report-only only" if s["csp_report_only"] else
           "meta tag only" if s["meta_csp"] else "absent")
    print(f"  CSP: {csp}")
    line()
    rows = q("SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
             "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
             "WHEN 'low' THEN 3 ELSE 4 END, id LIMIT ?", (sid, a.limit))
    print(f"  FINDINGS (showing {len(rows)} of {s['total_findings']})")
    _print_findings([dict(r) for r in rows])
    line()


def cmd_findings(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No checks yet.")
        return
    sql, args = "SELECT * FROM findings WHERE scan_id=?", [sid]
    if a.severity:
        sql += " AND severity=?"
        args.append(a.severity)
    if a.category:
        sql += " AND category=?"
        args.append(a.category)
    sql += (" ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id")
    rows = [dict(r) for r in q(sql, tuple(args))]
    if not rows:
        print("No findings match that filter.")
        return
    print(f"Scan #{sid} - {len(rows)} finding(s)")
    _print_findings(rows, indent="")


def cmd_headers(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No checks yet.")
        return
    s = scan_summary(sid)
    if not s or not s["ok"]:
        print("That scan has no successful response to show.")
        return
    headers = json.loads(s["headers_json"] or "{}")
    sec = {n for n, _c, _w in SECURITY_HEADERS}
    print(f"Response headers from {s['final_url'] or s['url']} (HTTP {s['status_code']})\n")
    for k, v in sorted(headers.items()):
        mark = "*" if k in sec else " "
        print(f" {mark} {k}: {v[:150]}{'...' if len(v) > 150 else ''}")
    cookies = json.loads(s["cookies_json"] or "[]")
    if cookies:
        print(f"\n {len(cookies)} Set-Cookie header(s):")
        for c in cookies:
            attrs = _parse_kv(c)
            flags = [f for f in ("secure", "httponly") if f in attrs]
            ss = attrs.get("samesite") or "unset"
            print(f"   {c.split('=', 1)[0]:<28} flags: {','.join(flags) or 'none'}  "
                  f"SameSite={ss}")
    print("\n * marks a header this tool grades.")


def cmd_directives(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No checks yet.")
        return
    rows = q("SELECT * FROM directives WHERE scan_id=? ORDER BY present DESC, name", (sid,))
    if not rows:
        print("That scan carried no CSP.")
        return
    print(f"{'DIRECTIVE':<26} {'ORIGIN':<18} {'KINDS':<24} SOURCES")
    line()
    for r in rows:
        origin = "declared" if r["present"] else f"<- {r['inherited_from']}"
        print(f"{r['name']:<26} {origin:<18} {(r['kinds'] or ''):<24} "
              f"{(r['sources'] or '')[:60]}")


def cmd_compare(a):
    sa, sb = scan_summary(a.a), scan_summary(a.b)
    if not sa or not sb:
        print("Both scan ids must exist. Use 'scans' to list them.")
        return 1
    fa = {(r["header"], r["title"]) for r in q("SELECT header,title FROM findings "
                                              "WHERE scan_id=?", (a.a,))}
    fb = {(r["header"], r["title"]) for r in q("SELECT header,title FROM findings "
                                              "WHERE scan_id=?", (a.b,))}
    line("=")
    print(f"  #{sa['id']} {sa['url']}  ->  #{sb['id']} {sb['url']}")
    print(f"  grade {sa['grade']} ({sa['score']})  ->  {sb['grade']} ({sb['score']})   "
          f"delta {(sb['score'] or 0) - (sa['score'] or 0):+.1f}")
    line("=")
    fixed, added = sorted(fa - fb), sorted(fb - fa)
    print(f"  RESOLVED ({len(fixed)})")
    for h, t in fixed:
        print(f"    - {t}  [{h}]")
    print(f"\n  NEW ({len(added)})")
    for h, t in added:
        print(f"    + {t}  [{h}]")
    print(f"\n  UNCHANGED: {len(fa & fb)}")
    line()
    return 0


def cmd_scans(a):
    rows = q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (a.limit,))
    if not rows:
        print("No checks yet.")
        return
    print(f"{'ID':>4}  {'WHEN (UTC)':<20} {'GR':>3} {'SCORE':>6} {'ST':>5} {'MODE':<6}  URL")
    line()
    for s in rows:
        print(f"{s['id']:>4}  {s['ts'][:19].replace('T', ' '):<20} "
              f"{(s['grade'] or '-'):>3} {(s['score'] if s['score'] is not None else '-'):>6} "
              f"{(s['status_code'] or 'ERR'):>5} {s['mode']:<6}  {s['url'][:44]}")


def cmd_explain(_a):
    banner()
    print(textwrap.dedent("""\
        WHAT CSP IS
          A Content-Security-Policy header tells the browser which sources it may load
          and execute. It is the only mechanism that can stop an injected <script> from
          running even when your output encoding has already failed. It is a second
          line of defence, not a substitute for fixing the injection.

        THE MODERN SHAPE OF A GOOD POLICY
          Content-Security-Policy:
            default-src 'self';
            script-src 'nonce-{random}' 'strict-dynamic' https: 'unsafe-inline';
            object-src 'none';
            base-uri 'none';
            frame-ancestors 'none';
            form-action 'self';
            require-trusted-types-for 'script'
          The nonce changes on every response. 'strict-dynamic' lets a trusted script
          load more scripts, so you do not need a host allowlist. The trailing
          https: and 'unsafe-inline' are ignored by modern browsers - they exist only
          so older ones fall back to something sane.

        THE FOUR MISTAKES THIS TOOL SEES MOST
          1. 'unsafe-inline' in script-src with no nonce or hash. The policy then stops
             almost nothing, because injected inline script is exactly what it permits.
          2. No base-uri. An injected <base> tag repoints every relative script URL,
             which defeats a nonce policy completely. base-uri does NOT inherit from
             default-src, so leaving it out is a real gap rather than a style choice.
          3. Host allowlists containing a CDN that serves arbitrary user content or a
             JSONP endpoint. One such origin is usually enough to bypass the policy.
          4. Leaving the policy in Report-Only forever. It reports and blocks nothing.

        WHAT FALLS BACK, AND WHAT DOES NOT
          Fetch directives (script-src, style-src, img-src, connect-src, font-src,
          media-src, object-src, frame-src, worker-src...) inherit from default-src.
          These do NOT inherit and must be written out:
            base-uri   form-action   frame-ancestors   sandbox   report-to
          That distinction is the single most useful thing to know about CSP.

        HOW TO ROLL ONE OUT WITHOUT BREAKING THE SITE
          1. Ship it as Content-Security-Policy-Report-Only with a reporting endpoint.
          2. Watch the reports for a week or two of real traffic.
          3. Fix what the reports show, or widen the policy where you must.
          4. Move the same policy into the enforcing header.
          5. Keep the report-only header for the next, stricter version.
        """))
    line()


def cmd_export(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No checks to export yet.")
        return 1
    fmt = a.format.lower()
    body = {"json": export_json, "csv": export_csv, "html": export_html}[fmt](sid)
    out = a.out or f"cspx-report-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{fmt}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)
    log_event("INFO", "export", f"Exported scan #{sid} as {fmt.upper()} to {out}", sid)
    print(f"Wrote {out} ({len(body):,} bytes)")
    return 0


def cmd_logs(a):
    sql, args = "SELECT * FROM events WHERE 1=1", []
    if a.level:
        sql += " AND level=?"
        args.append(a.level.upper())
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No log entries.")
        return
    for e in reversed(rows):
        print(f"{e['ts'][:19].replace('T', ' ')}  {e['level']:<5} {e['source']:<12} "
              f"{e['message']}")


def cmd_purge(a):
    conn = connect()
    try:
        if a.all:
            for t in ("findings", "directives", "scans", "events"):
                conn.execute(f"DELETE FROM {t}")
            conn.commit()
            print("All checks, findings and logs deleted.")
            return
        rows = q("SELECT id FROM scans ORDER BY id DESC", (), conn)
        drop = [r["id"] for r in rows[a.keep:]]
        for sid in drop:
            conn.execute("DELETE FROM findings WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM directives WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))
        conn.commit()
        log_event("INFO", "purge", f"Purged {len(drop)} scan(s), kept the newest {a.keep}",
                  None, conn)
        print(f"Purged {len(drop)} scan(s); kept the newest {a.keep}.")
    finally:
        conn.close()


def cmd_serve(a):
    serve(a.host, a.port, a.debug)


def cmd_version(_a):
    banner()
    print(f"  Python     : {platform.python_version()} ({sys.platform})")
    print(f"  Flask      : {'yes' if HAVE_FLASK else 'NOT INSTALLED - web app unavailable'}")
    print(f"  Directives : {len(KNOWN_DIRECTIVES)} known, {len(FALLBACK_CHAIN)} with fallbacks")
    print(f"  Headers    : {len(SECURITY_HEADERS)} graded")
    print(f"  User-Agent : {USER_AGENT}")
    print(f"  Database   : {os.path.abspath(db_path())}")
    print(f"  GitHub     : {GITHUB}")
    print(f"  LinkedIn   : {LINKEDIN}")
    line()
    print(DISCLAIMER_LONG)
    line()


# =============================================================================
# SECTION 11 - Self test
#   Policy analysis is tested offline against crafted policies, and the HTTP
#   path is tested against a throwaway local server serving known headers, so
#   the whole tool is verified without depending on any external site.
# =============================================================================

def _test_server():
    """A local server that returns deliberately good and bad header sets."""
    import http.server
    import threading

    CASES = {
        "/good": [
            ("Content-Security-Policy",
             "default-src 'none'; script-src 'nonce-abc123def456' 'strict-dynamic'; "
             "style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; "
             "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; "
             "require-trusted-types-for 'script'; upgrade-insecure-requests; "
             "report-to csp-endpoint"),
            ("Reporting-Endpoints", 'csp-endpoint="https://example.test/csp"'),
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("X-Frame-Options", "DENY"),
            ("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/"),
        ],
        "/bad": [
            ("Content-Security-Policy",
             "default-src *; script-src 'unsafe-inline' 'unsafe-eval' * data: "
             "ajax.googleapis.com"),
            ("X-Frame-Options", "ALLOW-FROM https://example.test"),
            ("X-XSS-Protection", "1; mode=block"),
            ("Referrer-Policy", "unsafe-url"),
            ("Server", "nginx/1.18.0"),
            ("X-Powered-By", "PHP/7.4.3"),
            ("Set-Cookie", "sid=abc; Path=/"),
        ],
        "/none": [("Content-Type", "text/html")],
        "/reportonly": [
            ("Content-Security-Policy-Report-Only", "default-src 'self'; object-src 'none'"),
        ],
        "/meta": [("Content-Type", "text/html")],
        "/hsts-short": [("Strict-Transport-Security", "max-age=300")],
    }

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_a):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/good")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/loop":
                self.send_response(302)
                self.send_header("Location", "/loop")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"<html><head></head><body>ok</body></html>"
            if path == "/meta":
                body = (b"<html><head><meta http-equiv=\"Content-Security-Policy\" "
                        b"content=\"default-src 'self'; object-src 'none'\">"
                        b"</head><body>ok</body></html>")
            self.send_response(200)
            for k, v in CASES.get(path, CASES["/none"]):
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def cmd_selftest(_a=None) -> int:
    import tempfile
    passed, failed = [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              f"{'  <- ' + str(detail) if detail and not cond else ''}")

    def titles(findings):
        return " | ".join(f["title"] for f in findings)

    banner()
    print("SELF TEST - policy analysis offline, HTTP path against a local test server.\n")
    original = db_path()
    tmp = tempfile.mkdtemp(prefix="cspx-selftest-")
    set_db_path(os.path.join(tmp, "selftest.db"))
    srv = None
    try:
        print(" Unit checks")
        check("URLs without a scheme default to https",
              normalise_url("example.com") == "https://example.com")
        check("html escaping blocks tag injection",
              "<script>" not in html_escape("<script>alert(1)</script>"))
        check("grade bands map scores to letters",
              grade_for(95)[0] == "A" and grade_for(72)[0] == "C" and grade_for(0)[0] == "F")
        check("max-age is rendered in human units", fmt_maxage(31536000) == "1.0 years")

        print("\n Address classification (the SSRF guard)")
        for ip, want in (("127.0.0.1", "loopback"), ("10.1.2.3", "private"),
                         ("192.168.1.1", "private"), ("172.16.0.1", "private"),
                         ("169.254.169.254", "metadata"), ("::1", "loopback"),
                         ("fe80::1", "link-local")):
            check(f"{ip} is refused as {want}", (classify_ip(ip) or "").find(want) >= 0,
                  classify_ip(ip))
        check("public addresses are allowed", classify_ip("93.184.216.34") is None)
        check("the metadata address is named specifically",
              classify_ip("169.254.169.254") == BLOCKED_REASONS["metadata"])

        print("\n CSP source classification")
        for tok, kind in (("'self'", "keyword"), ("'unsafe-inline'", "keyword"),
                          ("'nonce-abc123def456'", "nonce"), ("'sha256-abc'", "hash"),
                          ("https:", "scheme"), ("data:", "scheme"), ("*", "wildcard"),
                          ("example.com", "host"), ("*.example.com", "host"),
                          ("'bogus'", "invalid")):
            check(f"{tok} classified as {kind}", Source(tok).kind == kind, Source(tok).kind)
        check("a short nonce is called out", "short" in Source("'nonce-abc'").note)
        check("host part strips scheme, port and path",
              Source("https://cdn.example.com:443/a").host_part() == "cdn.example.com")

        print("\n Policy parsing and the fallback rules")
        p = Policy("default-src 'self'; script-src 'none'; IMG-SRC data:")
        check("directive names are case-insensitive", p.has("img-src"))
        check("script-src resolves to itself", p.effective("script-src")[1] == "script-src")
        check("style-src falls back to default-src",
              p.effective("style-src")[1] == "default-src")
        check("worker-src falls back to script-src before default-src, per the spec",
              p.effective("worker-src")[1] == "script-src", p.effective("worker-src")[1])
        check("worker-src reaches default-src when nothing closer is declared",
              Policy("default-src 'self'").effective("worker-src")[1] == "default-src")
        check("frame-src falls back through child-src",
              Policy("default-src 'self'; child-src 'none'")
              .effective("frame-src")[1] == "child-src")
        check("base-uri never falls back", p.effective("base-uri")[0] is None)
        check("frame-ancestors never falls back", p.effective("frame-ancestors")[0] is None)
        check("'none' is detected", p.is_none("script-src"))
        dup = Policy("script-src 'self'; script-src 'unsafe-inline'")
        check("a duplicated directive is reported and the first wins",
              len(dup.parse_notes) == 1 and dup.keywords("script-src") == {"'self'"})
        check("an empty policy parses to nothing", len(Policy("").directives) == 0)

        print("\n CSP analysis (crafted policies, offline)")
        f = analyse_csp(Policy("script-src 'unsafe-inline'"), {}, "https://x.test")
        check("'unsafe-inline' alone is critical",
              any(x["severity"] == "critical" and "unsafe-inline" in x["title"] for x in f))
        f = analyse_csp(Policy("script-src 'nonce-abc123def456' 'unsafe-inline'"), {},
                        "https://x.test")
        hit = [x for x in f if "unsafe-inline" in x["title"]]
        check("'unsafe-inline' beside a nonce is only informational",
              hit and hit[0]["severity"] == "info", titles(hit))
        f = analyse_csp(Policy("script-src 'self' 'unsafe-eval'"), {}, "https://x.test")
        check("'unsafe-eval' is high", any(x["severity"] == "high" and "eval" in x["title"]
                                           for x in f))
        f = analyse_csp(Policy("script-src *"), {}, "https://x.test")
        check("a wildcard script-src is critical",
              any(x["severity"] == "critical" and "any host" in x["title"] for x in f))
        f = analyse_csp(Policy("script-src data:"), {}, "https://x.test")
        check("data: in script-src is critical",
              any(x["severity"] == "critical" and "data:" in x["title"] for x in f))
        f = analyse_csp(Policy("default-src 'self'"), {}, "https://x.test")
        check("a missing base-uri is reported",
              any("base-uri" in x["title"] for x in f))
        check("a missing frame-ancestors is reported",
              any("frame-ancestors" in x["title"] for x in f))
        check("object-src not being 'none' is reported",
              any("object-src" in x["title"] for x in f))
        f = analyse_csp(Policy("default-src 'self'"),
                        {"x-frame-options": "DENY"}, "https://x.test")
        fa = [x for x in f if "frame-ancestors" in x["title"]]
        check("a present X-Frame-Options lowers the frame-ancestors severity",
              fa and fa[0]["severity"] == "low", titles(fa))
        f = analyse_csp(Policy("script-src 'nonce-abc123def456' ajax.googleapis.com"), {},
                        "https://x.test")
        check("a known-bypassable allowlist host is flagged",
              any("bypassable" in x["title"] for x in f))
        f = analyse_csp(Policy("script-src 'nonce-abc123def456' 'strict-dynamic'"), {},
                        "https://x.test")
        check("'strict-dynamic' is recognised as good practice",
              any(x["severity"] == "info" and "strict-dynamic" in x["title"] for x in f))
        check("no allowlist warning is raised when strict-dynamic is used",
              not any("bypassable" in x["title"] for x in f))
        f = analyse_csp(Policy("default-src 'self'", report_only=True), {}, "https://x.test")
        check("report-only is called out as unenforced",
              any(x["severity"] == "high" and "not enforced" in x["title"] for x in f))
        f = analyse_csp(Policy("scirpt-src 'self'"), {}, "https://x.test")
        check("a misspelt directive is reported",
              any("Unrecognised" in x["title"] for x in f))
        f = analyse_csp(Policy("script-src 'self'; block-all-mixed-content"), {},
                        "https://x.test")
        check("a deprecated directive is reported",
              any("Deprecated" in x["title"] for x in f))

        print("\n Other header analysis")
        f = analyse_headers({"content-security-policy": "default-src 'self'"}, [],
                            "https://x.test")
        check("missing HSTS on HTTPS is high",
              any(x["severity"] == "high" and "HSTS" in x["title"] for x in f))
        f = analyse_headers({"strict-transport-security": "max-age=300"}, [], "https://x.test")
        check("a short HSTS max-age is reported",
              any("max-age is short" in x["title"] for x in f))
        f = analyse_headers({"strict-transport-security": "max-age=0"}, [], "https://x.test")
        check("max-age=0 is reported", any("max-age is 0" in x["title"] for x in f))
        f = analyse_headers({"x-frame-options": "ALLOW-FROM https://a.test"}, [],
                            "https://x.test")
        check("ALLOW-FROM is reported as unsupported",
              any("ALLOW-FROM" in x["title"] for x in f))
        f = analyse_headers({}, [], "http://x.test")
        check("a plain HTTP target is reported as high",
              any(x["severity"] == "high" and "plain HTTP" in x["title"] for x in f))
        f = analyse_headers({}, [], "https://x.test")
        check("no CSP at all is critical",
              any(x["severity"] == "critical" and "No Content-Security-Policy" in x["title"]
                  for x in f))
        f = analyse_headers({"x-xss-protection": "1; mode=block"}, [], "https://x.test")
        check("the legacy XSS filter is reported",
              any("Legacy XSS filter" in x["title"] for x in f))
        f = analyse_cookies(["sid=1; Path=/"], True)
        check("a cookie missing every flag is reported",
              f and "Secure" in f[0]["title"] and "HttpOnly" in f[0]["title"])
        f = analyse_cookies(["sid=1; Secure; HttpOnly; SameSite=Lax"], True)
        check("a fully flagged cookie raises nothing", not f)
        f = analyse_cookies(["sid=1; SameSite=None; HttpOnly"], True)
        check("SameSite=None without Secure is high",
              any(x["severity"] == "high" for x in f))

        print("\n Scoring")
        check("a clean result scores 100", score_findings([])[0] == 100.0)
        check("one critical costs 22 points",
              score_findings([{"severity": "critical"}])[0] == 78.0)
        check("info findings never reduce the score",
              score_findings([{"severity": "info"}] * 20)[0] == 100.0)
        check("the score floors at 0",
              score_findings([{"severity": "critical"}] * 20)[0] == 0.0)

        print("\n Charts")
        check("pie renders slices",
              svg_pie([("a", 2, "#fff"), ("b", 1, "#000")]).count("<path") == 2)
        check("pie with no data says so", "nothing to show" in svg_pie([]))
        check("bar renders rows", svg_bar([("x", 2), ("y", 1)]).count("<rect") == 4)
        check("columns render", svg_columns([("#1", 80, "#0f0")]).count("<rect") == 1)
        check("gauge renders a grade", ">A<" in svg_gauge(95, "A"))
        check("adoption matrix renders", svg_matrix([("csp", 1, 2)]).count("<rect") == 2)
        check("adoption matrix with no scans says so", "no successful" in svg_matrix([]))

        print("\n HTTP path (local test server)")
        srv, base = _test_server()
        res = fetch(base + "/good", allow_private=True)
        check("a local response is fetched", res["ok"] and res["status"] == 200, res.get("error"))
        a_good = analyse_all(res["headers"], res["cookies"], res["final_url"], res["meta_csp"])
        check(f"a well-configured response grades well (got {a_good['grade']} "
              f"{a_good['score']})", a_good["counts"]["critical"] == 0
              and a_good["counts"]["high"] <= 1,
              titles([x for x in a_good["findings"] if x["severity"] in ("critical", "high")]))
        check("its cookie raises nothing",
              not any(x["category"] == "Cookies" for x in a_good["findings"]))
        res_bad = fetch(base + "/bad", allow_private=True)
        a_bad = analyse_all(res_bad["headers"], res_bad["cookies"], res_bad["final_url"])
        check(f"a badly configured response grades badly (got {a_bad['grade']} "
              f"{a_bad['score']})", a_bad["counts"]["critical"] >= 2 and a_bad["score"] < 40)
        check("the bad response scores worse than the good one",
              a_bad["score"] < a_good["score"])
        check("server version disclosure is picked up",
              any("version disclosed" in x["title"] for x in a_bad["findings"]))
        res_none = fetch(base + "/none", allow_private=True)
        a_none = analyse_all(res_none["headers"], res_none["cookies"], res_none["final_url"])
        # E and F are both bottom-of-scale; F is reserved for policies that are
        # actively misleading (a wildcard CSP scores worse than no CSP at all)
        check("a response with no security headers lands at the bottom of the scale",
              a_none["grade"] in ("E", "F") and a_none["score"] < 55,
              f"{a_none['grade']} {a_none['score']}")
        check("a wildcard policy scores worse than having no policy at all",
              a_bad["score"] < a_none["score"], f"{a_bad['score']} vs {a_none['score']}")
        res_meta = fetch(base + "/meta", allow_private=True)
        check("a <meta http-equiv> policy is found in the body",
              res_meta["meta_csp"] and "default-src" in res_meta["meta_csp"],
              res_meta.get("meta_csp"))
        a_meta = analyse_all(res_meta["headers"], res_meta["cookies"], res_meta["final_url"],
                             res_meta["meta_csp"])
        check("a meta-only policy is reported as weaker than a header",
              any("meta" in x["title"].lower() for x in a_meta["findings"]))
        res_ro = fetch(base + "/reportonly", allow_private=True)
        a_ro = analyse_all(res_ro["headers"], res_ro["cookies"], res_ro["final_url"])
        check("a report-only policy is analysed and flagged as unenforced",
              any("not enforced" in x["title"] for x in a_ro["findings"]))
        res_r = fetch(base + "/redirect", allow_private=True)
        check("redirects are followed and the chain recorded",
              res_r["ok"] and len(res_r["chain"]) == 2
              and res_r["final_url"].endswith("/good"), res_r.get("chain"))
        res_loop = fetch(base + "/loop", allow_private=True, max_redirects=3)
        check("a redirect loop is stopped and reported",
              not res_loop["ok"] and "redirects" in res_loop["error"])
        blocked = fetch(base + "/good")
        check("loopback is refused without --allow-private",
              not blocked["ok"] and "loopback" in blocked["error"])
        check("the refusal explains why and how to override",
              "server-side request forgery" in blocked["error"]
              and "--allow-private" in blocked["error"])
        bad_scheme = fetch("ftp://example.test/x")
        check("a non-HTTP scheme is refused",
              not bad_scheme["ok"] and "scheme" in bad_scheme["error"])
        nodns = fetch("https://this-host-does-not-exist.invalid/")
        check("a DNS failure is reported honestly and not graded",
              not nodns["ok"] and "DNS" in nodns["error"])

        print("\n Database")
        init_db()
        sid = save_scan(res, a_good, mode="live", note="selftest")
        s = scan_summary(sid)
        check("scan row written with a grade", s and s["grade"] == a_good["grade"])
        check("findings persisted",
              q1("SELECT COUNT(*) c FROM findings WHERE scan_id=?", (sid,))["c"]
              == len(a_good["findings"]))
        check("severity counters match the stored rows",
              all(s[sv] == q1("SELECT COUNT(*) c FROM findings WHERE scan_id=? AND severity=?",
                              (sid, sv))["c"] for sv in SEVERITIES))
        check("declared directives were recorded",
              q1("SELECT COUNT(*) c FROM directives WHERE scan_id=? AND present=1",
                 (sid,))["c"] >= 8)
        check("inherited directives were recorded separately",
              q1("SELECT COUNT(*) c FROM directives WHERE scan_id=? AND present=0",
                 (sid,))["c"] >= 1)
        fail_id = save_scan(nodns, None, mode="live")
        fs = scan_summary(fail_id)
        check("a failed check is stored without a grade",
              fs["ok"] == 0 and fs["grade"] is None and fs["error"])
        check("a failed check is logged as an error",
              q1("SELECT COUNT(*) c FROM events WHERE level='ERROR'", ())["c"] >= 1)
        lint = analyse_policy_only("script-src 'unsafe-inline'")
        lint_id = save_scan({"ok": True, "url": "policy-lint", "final_url": "policy-lint",
                             "host": "", "ip": "", "status": 0,
                             "headers": {"content-security-policy": "script-src 'unsafe-inline'"},
                             "cookies": [], "meta_csp": None, "chain": [], "duration": 0.0,
                             "error": None}, lint, mode="lint")
        check("an offline lint is stored and marked as such",
              scan_summary(lint_id)["mode"] == "lint")
        check("a lint raises no transport findings",
              not any(x["category"] == "Transport" for x in lint["findings"]))

        print("\n Exports")
        j = json.loads(export_json(sid))
        check("JSON export is valid and carries the disclaimer",
              "AUTHORISED" in j["disclaimer"].upper() and j["scan"]["id"] == sid)
        check("JSON export includes findings, directives and raw headers",
              len(j["findings"]) == len(a_good["findings"]) and j["directives"]
              and j["headers"])
        c = export_csv(sid)
        rows = [r for r in csv.reader(io.StringIO(c)) if r and not r[0].startswith("#")]
        check("CSV export has a header plus one row per finding",
              rows[0][0] == "severity" and len(rows) == len(a_good["findings"]) + 1)
        h = export_html(sid)
        check("HTML export is a complete document",
              h.startswith("<!doctype html") and h.rstrip().endswith("</html>"))
        check("HTML export contains charts, disclaimer and author",
              "<svg" in h and "AUTHORISED USE ONLY" in h and AUTHOR in h)

        print("\n Web application")
        if not HAVE_FLASK:
            check("Flask installed", False, "pip install flask")
        else:
            app = build_app()
            app.config["TESTING"] = True
            cl = app.test_client()
            for path, must in (("/", "Overview"), ("/policy", "Policy"),
                               ("/headers", "Headers"), ("/analytics", "Analytics"),
                               ("/logs", "Logs")):
                r = cl.get(path)
                body = r.get_data(as_text=True)
                check(f"page {path} returns 200 and renders",
                      r.status_code == 200 and must in body, f"status={r.status_code}")
                check(f"page {path} shows the disclaimer", "Authorised use only" in body)
            check("the policy page breaks the directives out",
                  "script-src" in cl.get(f"/policy?scan={sid}").get_data(as_text=True))
            check("the headers page lists raw headers",
                  "strict-transport-security" in
                  cl.get(f"/headers?scan={sid}").get_data(as_text=True))
            check("header filters apply",
                  cl.get(f"/headers?scan={sid}&security=1&qq=csp").status_code == 200)
            check("analytics renders SVG charts",
                  cl.get("/analytics").get_data(as_text=True).count("<svg") >= 4)
            check("logs filters apply",
                  cl.get("/logs?level=INFO&limit=50&qq=check").status_code == 200)
            check("a failed scan renders without a grade",
                  "did not complete" in cl.get(f"/?scan={fail_id}").get_data(as_text=True))
            for fmt, ctype in (("json", "application/json"), ("csv", "text/csv"),
                               ("html", "text/html")):
                r = cl.get(f"/export/{fmt}?scan={sid}")
                check(f"export /{fmt} downloads",
                      r.status_code == 200 and ctype in r.headers["Content-Type"]
                      and "attachment" in r.headers.get("Content-Disposition", ""))
            check("bad export format is rejected", cl.get("/export/exe").status_code == 400)
            check("unknown route returns a helpful 404", cl.get("/nope").status_code == 404)
            check("api summary returns JSON", cl.get("/api/summary").status_code == 200)
            r = cl.post("/lint", data={"policy": "script-src 'unsafe-inline'"})
            check("web lint runs offline and redirects", r.status_code == 302)
            r = cl.post("/lint", data={"policy": ""})
            check("web lint rejects an empty policy",
                  r.status_code == 302 and "error=" in r.headers["Location"])
            r = cl.post("/check", data={"url": base + "/good"})
            check("the web check refuses loopback without the opt-in",
                  r.status_code == 302 and "error=" in r.headers["Location"])
            r = cl.post("/check", data={"url": base + "/good", "allow_private": "1"})
            check("the web check runs when private access is opted in",
                  r.status_code == 302 and "error=" not in r.headers["Location"])
            check("using --allow-private is recorded as a warning in the log",
                  q1("SELECT COUNT(*) c FROM events WHERE source='ssrf-guard'", ())["c"] >= 1)
            check("empty-state page renders with no checks",
                  "No checks run yet" in _empty_state_probe())

        print("\n Retention")
        n = q1("SELECT COUNT(*) c FROM scans", ())["c"]
        cmd_purge(argparse.Namespace(all=False, keep=1))
        check("purge keeps exactly the newest check",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 1, n)
        check("purge removes orphaned findings",
              q1("SELECT COUNT(*) c FROM findings WHERE scan_id NOT IN "
                 "(SELECT id FROM scans)", ())["c"] == 0)
        cmd_purge(argparse.Namespace(all=True, keep=1))
        check("purge --all clears the database",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 0)
    finally:
        if srv:
            srv.shutdown()
            srv.server_close()
        set_db_path(original)
        shutil.rmtree(tmp, ignore_errors=True)

    line("=")
    print(f"  {len(passed)} passed, {len(failed)} failed")
    if failed:
        print("  Failed: " + ", ".join(failed))
    else:
        print("  All checks passed. The temporary database has been removed and no external\n"
              "  site was contacted: the HTTP path was tested against a local server.")
    line("=")
    return 0 if not failed else 1


def _empty_state_probe() -> str:
    import tempfile
    original = db_path()
    d = tempfile.mkdtemp(prefix="cspx-empty-")
    try:
        set_db_path(os.path.join(d, "empty.db"))
        init_db()
        app = build_app()
        app.config["TESTING"] = True
        return app.test_client().get("/").get_data(as_text=True)
    finally:
        set_db_path(original)
        shutil.rmtree(d, ignore_errors=True)


# =============================================================================
# SECTION 12 - Entry point
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{APP_NAME} v{VERSION} - Content-Security-Policy and security header "
                    f"analysis, by {AUTHOR}",
        epilog=textwrap.dedent(f"""\
            examples
              %(prog)s explain                       what CSP is and how to roll one out
              %(prog)s check --url https://example.com
              %(prog)s lint --policy "default-src 'self'; script-src 'unsafe-inline'"
              %(prog)s bulk --file urls.txt --delay 2
              %(prog)s check --url https://example.com --fail-on high   # for CI
              %(prog)s serve                         web app on http://127.0.0.1:5000
              %(prog)s selftest                      verify every component end to end

            {DISCLAIMER_LONG}
            """))
    p.add_argument("--db", default=DEFAULT_DB,
                   help=f"SQLite database file (default: {DEFAULT_DB}, env CSPX_DB)")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION} by {AUTHOR}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("check", help="fetch a URL and grade its headers")
    s.add_argument("--url", required=True)
    s.add_argument("--timeout", type=float, default=15.0)
    s.add_argument("--redirects", type=int, default=5, help="maximum redirect hops")
    s.add_argument("--allow-private", action="store_true",
                   help="permit loopback and private addresses (recorded in the log)")
    s.add_argument("--insecure", action="store_true",
                   help="disable TLS certificate verification (use only on hosts you own)")
    s.add_argument("--show", type=int, default=12, help="findings to print")
    s.add_argument("--json", action="store_true", help="print the full result as JSON")
    s.add_argument("--fail-on", metavar="LEVEL",
                   help="exit 1 if a finding at LEVEL or worse exists (critical/high/medium/"
                        "low), or if the grade is worse than a letter (a/b/c/d/e)")
    s.add_argument("--note")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("lint", help="analyse a policy string offline, with no network access")
    s.add_argument("--policy", help="the policy text")
    s.add_argument("--policy-file", help="read the policy from a file")
    s.add_argument("--stdin", action="store_true", help="read the policy from standard input")
    s.add_argument("--report-only", action="store_true", help="treat it as report-only")
    s.add_argument("--show", type=int, default=20)
    s.add_argument("--save", action="store_true", help="store the result in the database")
    s.add_argument("--fail-on", metavar="LEVEL")
    s.set_defaults(func=cmd_lint)

    s = sub.add_parser("bulk", help="check many URLs from a file")
    s.add_argument("--file", required=True, help="one URL per line, # comments allowed")
    s.add_argument("--delay", type=float, default=2.0, help="seconds between requests")
    s.add_argument("--timeout", type=float, default=15.0)
    s.add_argument("--allow-private", action="store_true")
    s.set_defaults(func=cmd_bulk)

    s = sub.add_parser("show", help="summary of one check")
    s.add_argument("scan", nargs="?", type=int)
    s.add_argument("--limit", type=int, default=12)
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("findings", help="list findings with filters")
    s.add_argument("--scan", type=int)
    s.add_argument("--severity", choices=SEVERITIES)
    s.add_argument("--category")
    s.set_defaults(func=cmd_findings)

    s = sub.add_parser("headers", help="raw response headers from a check")
    s.add_argument("--scan", type=int)
    s.set_defaults(func=cmd_headers)

    s = sub.add_parser("directives", help="CSP directive breakdown from a check")
    s.add_argument("--scan", type=int)
    s.set_defaults(func=cmd_directives)

    s = sub.add_parser("compare", help="diff the findings of two checks")
    s.add_argument("--a", type=int, required=True)
    s.add_argument("--b", type=int, required=True)
    s.set_defaults(func=cmd_compare)

    s = sub.add_parser("scans", help="list previous checks")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_scans)

    s = sub.add_parser("explain", help="what CSP is, and the mistakes this tool sees most")
    s.set_defaults(func=cmd_explain)

    s = sub.add_parser("serve", help="start the web app (5 pages)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("export", help="write a report to a file")
    s.add_argument("--scan", type=int)
    s.add_argument("--format", choices=["json", "csv", "html"], default="html")
    s.add_argument("--out")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("logs", help="local event log")
    s.add_argument("--level", choices=["INFO", "WARN", "ERROR", "info", "warn", "error"])
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("purge", help="delete stored checks")
    s.add_argument("--keep", type=int, default=20)
    s.add_argument("--all", action="store_true")
    s.set_defaults(func=cmd_purge)

    s = sub.add_parser("selftest", help="verify every component (temporary database)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("version", help="versions, dependencies and the disclaimer")
    s.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_db_path(args.db)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if args.cmd != "selftest":
        init_db()
    try:
        rc = args.func(args)
        return rc if isinstance(rc, int) else 0
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except PermissionError as e:
        print(f"Permission denied: {e}")
        return 1
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}\nIs another copy running against {db_path()}?")
        return 1


if __name__ == "__main__":
    sys.exit(main())
