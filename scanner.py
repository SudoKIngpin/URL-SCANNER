"""
URL Security Scanner — Core Analysis Engine
SudoCorps | Digital Forensics & Automation

All scanning logic lives here. Each function analyzes one aspect of the URL.
The `full_scan()` function orchestrates everything and returns a unified report.
"""

import re
import ssl
import socket
import hashlib
import logging
import datetime
from urllib.parse import urlparse, urlunparse

import httpx
import whois

logger = logging.getLogger("scanner")

# ─────────────────────────── Constants ───────────────────────────

KNOWN_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz",
    ".club", ".work", ".click", ".link", ".win", ".loan", ".racing",
}

SIMULATED_BLACKLIST = {
    "malware-test.example.com",
    "phishing-demo.example.com",
    "evil-site.test.local",
}

SAFE_REGISTRARS = {
    "godaddy", "namecheap", "google", "cloudflare", "amazon",
    "gandi", "name.com", "hover", "porkbun", "dynadot",
}


# ─────────────────────── URL Validation ──────────────────────────

def normalize_url(raw_url: str) -> str:
    """Add scheme if missing and normalize the URL."""
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("URL cannot be empty.")
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: cannot extract domain from '{raw_url}'")
    return urlunparse(parsed)


def extract_domain(url: str) -> str:
    """Extract the bare domain from a URL."""
    return urlparse(url).netloc.split(":")[0]


# ─────────────────────── DNS Resolution ──────────────────────────

def resolve_dns(domain: str) -> dict:
    """Resolve domain to IP address(es)."""
    try:
        ips = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        unique_ips = list({addr[4][0] for addr in ips})
        return {"resolved": True, "ip_addresses": unique_ips}
    except socket.gaierror as e:
        return {"resolved": False, "ip_addresses": [], "error": str(e)}


# ─────────────────────── WHOIS Lookup ────────────────────────────

def whois_lookup(domain: str) -> dict:
    """Perform WHOIS lookup for domain registration info."""
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]

        age_days = None
        if creation:
            age_days = (datetime.datetime.now() - creation).days

        registrar = w.registrar or "Unknown"

        return {
            "available": False,
            "registrar": registrar,
            "creation_date": creation.strftime("%Y-%m-%d") if creation else None,
            "expiration_date": expiration.strftime("%Y-%m-%d") if expiration else None,
            "age_days": age_days,
            "org": w.org or None,
            "country": w.country or None,
        }
    except Exception as e:
        return {
            "available": True,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "age_days": None,
            "org": None,
            "country": None,
            "error": str(e),
        }


# ─────────────────────── SSL Certificate ─────────────────────────

def check_ssl(domain: str) -> dict:
    """Check SSL/TLS certificate validity and details."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.datetime.utcnow()).days

        issuer_parts = {k: v for field in cert.get("issuer", ()) for k, v in field}
        subject_parts = {k: v for field in cert.get("subject", ()) for k, v in field}

        return {
            "valid": True,
            "issuer": issuer_parts.get("organizationName", "Unknown"),
            "subject": subject_parts.get("commonName", domain),
            "issued_on": not_before.strftime("%Y-%m-%d"),
            "expires_on": not_after.strftime("%Y-%m-%d"),
            "days_remaining": days_left,
            "expired": days_left < 0,
            "version": cert.get("version"),
            "serial": cert.get("serialNumber"),
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Certificate verification failed: {e}"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ─────────────────────── HTTP Response ───────────────────────────

def check_http(url: str) -> dict:
    """Perform an HTTP(S) request and inspect response headers."""
    try:
        with httpx.Client(timeout=8, follow_redirects=True, verify=False) as client:
            resp = client.get(url)

        security_headers = {
            "Strict-Transport-Security": resp.headers.get("strict-transport-security"),
            "Content-Security-Policy": resp.headers.get("content-security-policy"),
            "X-Content-Type-Options": resp.headers.get("x-content-type-options"),
            "X-Frame-Options": resp.headers.get("x-frame-options"),
            "X-XSS-Protection": resp.headers.get("x-xss-protection"),
            "Referrer-Policy": resp.headers.get("referrer-policy"),
        }
        present = sum(1 for v in security_headers.values() if v)

        return {
            "reachable": True,
            "status_code": resp.status_code,
            "server": resp.headers.get("server", "Not disclosed"),
            "content_type": resp.headers.get("content-type", "Unknown"),
            "redirect_chain": [str(r.url) for r in resp.history] if resp.history else [],
            "final_url": str(resp.url),
            "security_headers": security_headers,
            "security_headers_present": present,
            "security_headers_total": len(security_headers),
        }
    except httpx.ConnectError:
        return {"reachable": False, "error": "Connection refused or DNS failure."}
    except httpx.TimeoutException:
        return {"reachable": False, "error": "Request timed out (8s)."}
    except Exception as e:
        return {"reachable": False, "error": str(e)}


# ────────────────── Suspicious Pattern Detection ─────────────────

def detect_suspicious_patterns(url: str, domain: str) -> list:
    """Detect heuristic-based risk signals in the URL."""
    flags = []

    # IP-based URL
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        flags.append({
            "flag": "IP-based URL",
            "severity": "high",
            "detail": "Domain is a raw IP address — common in phishing.",
        })

    # Excessively long URL
    if len(url) > 200:
        flags.append({
            "flag": "Excessively long URL",
            "severity": "medium",
            "detail": f"URL length is {len(url)} characters — may hide malicious paths.",
        })

    # @ symbol in URL
    if "@" in url:
        flags.append({
            "flag": "@ symbol in URL",
            "severity": "high",
            "detail": "The @ symbol can be used to mislead users about the real destination.",
        })

    # Excessive hyphens in domain
    if domain.count("-") >= 3:
        flags.append({
            "flag": "Excessive hyphens",
            "severity": "medium",
            "detail": f"Domain has {domain.count('-')} hyphens — often seen in phishing domains.",
        })

    # Suspicious TLD
    for tld in KNOWN_SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append({
                "flag": "Suspicious TLD",
                "severity": "medium",
                "detail": f"Domain uses '{tld}' — a TLD frequently abused for malicious sites.",
            })
            break

    # Many subdomains
    subdomain_count = domain.count(".") - 1
    if subdomain_count >= 3:
        flags.append({
            "flag": "Excessive subdomains",
            "severity": "medium",
            "detail": f"Domain has {subdomain_count} subdomains — may mimic legitimate sites.",
        })

    # Blacklist match (simulated)
    if domain.lower() in SIMULATED_BLACKLIST:
        flags.append({
            "flag": "Blacklisted domain",
            "severity": "critical",
            "detail": "This domain appears in known threat intelligence feeds.",
        })

    # Punycode (internationalized domain — homograph attack)
    if "xn--" in domain:
        flags.append({
            "flag": "Punycode / IDN domain",
            "severity": "high",
            "detail": "Uses internationalized characters — potential homograph attack.",
        })

    # Port in URL
    parsed = urlparse(url)
    if parsed.port and parsed.port not in (80, 443):
        flags.append({
            "flag": "Non-standard port",
            "severity": "low",
            "detail": f"URL specifies port {parsed.port} — unusual for public websites.",
        })

    return flags


# ──────────────────── Credibility Scoring ────────────────────────

def calculate_score(dns: dict, whois_info: dict, ssl_info: dict,
                    http_info: dict, flags: list) -> dict:
    """
    Generate a credibility score (0–100) based on weighted heuristics.
    Returns score + risk_level (Safe / Suspicious / Risky).
    """
    score = 100
    reasons = []

    # DNS
    if not dns.get("resolved"):
        score -= 30
        reasons.append("Domain does not resolve (DNS failure)")

    # WHOIS
    if whois_info.get("available"):
        score -= 15
        reasons.append("WHOIS lookup failed or domain unregistered")
    else:
        age = whois_info.get("age_days")
        if age is not None:
            if age < 30:
                score -= 25
                reasons.append(f"Domain is very new ({age} days old)")
            elif age < 180:
                score -= 10
                reasons.append(f"Domain is relatively new ({age} days old)")

        registrar = (whois_info.get("registrar") or "").lower()
        if registrar and not any(safe in registrar for safe in SAFE_REGISTRARS):
            score -= 5
            reasons.append(f"Uncommon registrar: {whois_info.get('registrar')}")

    # SSL
    if not ssl_info.get("valid"):
        score -= 25
        reasons.append("SSL certificate is invalid or missing")
    else:
        days = ssl_info.get("days_remaining", 0)
        if days < 0:
            score -= 25
            reasons.append("SSL certificate has expired")
        elif days < 14:
            score -= 10
            reasons.append(f"SSL certificate expires in {days} days")

    # HTTP
    if not http_info.get("reachable"):
        score -= 15
        reasons.append("Site is unreachable")
    else:
        status = http_info.get("status_code", 0)
        if status >= 400:
            score -= 10
            reasons.append(f"HTTP returned error status {status}")

        headers_present = http_info.get("security_headers_present", 0)
        if headers_present == 0:
            score -= 15
            reasons.append("No security headers present")
        elif headers_present <= 2:
            score -= 8
            reasons.append(f"Only {headers_present}/6 security headers present")

    # Risk flags
    for flag in flags:
        severity = flag.get("severity", "low")
        if severity == "critical":
            score -= 30
        elif severity == "high":
            score -= 15
        elif severity == "medium":
            score -= 8
        elif severity == "low":
            score -= 3
        reasons.append(flag["flag"])

    # Clamp
    score = max(0, min(100, score))

    # Level
    if score >= 70:
        risk_level = "Safe"
    elif score >= 40:
        risk_level = "Suspicious"
    else:
        risk_level = "Risky"

    return {
        "score": score,
        "risk_level": risk_level,
        "deductions": reasons,
    }


# ──────────────────── Main Orchestrator ──────────────────────────

def full_scan(raw_url: str) -> dict:
    """
    Run a complete security analysis on the given URL.
    Returns a structured report dictionary.
    """
    logger.info(f"Starting scan for: {raw_url}")

    # 1. Validate & normalize
    url = normalize_url(raw_url)
    domain = extract_domain(url)
    url_hash = hashlib.sha256(url.encode()).hexdigest()

    # 2. Run all checks
    dns = resolve_dns(domain)
    whois_info = whois_lookup(domain)
    ssl_info = check_ssl(domain)
    http_info = check_http(url)
    flags = detect_suspicious_patterns(url, domain)

    # 3. Score
    credibility = calculate_score(dns, whois_info, ssl_info, http_info, flags)

    # 4. Assemble report
    report = {
        "scan_id": url_hash[:12],
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "url": url,
        "domain": domain,
        "credibility": credibility,
        "dns": dns,
        "whois": whois_info,
        "ssl": ssl_info,
        "http": http_info,
        "risk_flags": flags,
    }

    logger.info(f"Scan complete: {domain} → score {credibility['score']}")
    return report
