"""Extract and inspect URLs without contacting them."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse, unquote

from scamsentry.models import (
    Category,
    EvidenceSource,
    Finding,
    FindingSource,
    ObservationKind,
    Severity,
)


HTTP_SCHEMES = frozenset({"http", "https"})
RISKY_SCHEMES = frozenset({"javascript", "data", "file", "vbscript", "blob"})
STANDARD_PORTS = frozenset({80, 443})
MULTI_PART_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "co.in",
        "com.br",
        "co.za",
        "com.mx",
        "co.kr",
        "com.sg",
        "com.hk",
        "com.tw",
        "co.nz",
        "com.tr",
        "com.ar",
    }
)

# Conservative brand tokens: flag only when used as a *subdomain* of an
# unrelated registrable domain (paypal.unrelated.example), not brand mention
# in a path or the brand's own registrable domain.
BRAND_REGISTRABLE = {
    "paypal": frozenset({"paypal.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "google": frozenset({"google.com", "google.co.uk"}),
    "microsoft": frozenset({"microsoft.com", "live.com", "outlook.com"}),
    "amazon": frozenset({"amazon.com", "amazon.co.uk"}),
    "facebook": frozenset({"facebook.com", "meta.com"}),
    "instagram": frozenset({"instagram.com"}),
    "whatsapp": frozenset({"whatsapp.com"}),
    "netflix": frozenset({"netflix.com"}),
    "dhl": frozenset({"dhl.com"}),
    "fedex": frozenset({"fedex.com"}),
    "ups": frozenset({"ups.com"}),
    "irs": frozenset({"irs.gov"}),
    "chase": frozenset({"chase.com"}),
    "wellsfargo": frozenset({"wellsfargo.com"}),
}

LEADING_WRAP = "([{<'\"“”‘’"
ALWAYS_TRIM_TRAILING = ".,;:!?…'\"“”‘’"
BRACKET_PAIRS = {
    ")": "(",
    "]": "[",
    "}": "{",
    ">": "<",
}

# Explicit HTTP(S) and recognised defanged schemes. Matches ://, [:], [://], (:), (://).
_SCHEME_URL_RE = re.compile(
    r"(?P<url>(?:https?|hxxps?)(?:\[:\]//|\[://\]|\(:\)//|\(://\)|://)[^\s<>\"']+)",
    re.IGNORECASE,
)

# Host-only defanging such as example[.]com or example(.)com or example[.]com/path
_DEFANGED_HOST_RE = re.compile(
    r"(?P<url>(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[\.\]|\(\.\)|\.))+"
    r"[a-z]{2,24}(?:/[^\s<>\"']*)?)",
    re.IGNORECASE,
)

# Explicit non-HTTP schemes that we may flag when clearly present.
_RISKY_SCHEME_RE = re.compile(
    r"(?P<url>(?:javascript|data|file|vbscript|blob):[^\s<>\"']+)",
    re.IGNORECASE,
)

_EMAIL_RE = re.compile(
    r"^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ExtractedURL:
    original_text: str
    normalised_candidate: str
    start: int
    end: int
    recognised_defanged: bool
    parse_ok: bool
    scheme: str | None
    host: str | None
    port: int | None
    path: str
    query: str
    userinfo: str | None
    host_is_ip: bool
    parse_error: str | None
    notes: tuple[str, ...]


def _trim_span(text: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start] in LEADING_WRAP:
        start += 1
    while end > start:
        char = text[end - 1]
        if char in ALWAYS_TRIM_TRAILING:
            end -= 1
        elif char in BRACKET_PAIRS:
            open_bracket = BRACKET_PAIRS[char]
            candidate_span = text[start:end]
            if candidate_span.count(char) > candidate_span.count(open_bracket):
                end -= 1
            else:
                break
        else:
            break
    return start, end


def refang_recognised(text: str) -> tuple[str, bool]:
    """Apply only recognised defanging patterns. Preserve the original separately."""

    changed = False
    candidate = text
    replacements = (
        ("hxxps", "https"),
        ("hxxp", "http"),
        ("HXXPS", "https"),
        ("HXXP", "http"),
        ("[://]", "://"),
        ("(://)", "://"),
        ("[:]", ":"),
        ("(:)", ":"),
        ("[.]", "."),
        ("(.)", "."),
    )
    lower = candidate.lower()
    # Scheme-level hxxp at the start (case-insensitive).
    for fang, live in (("hxxps", "https"), ("hxxp", "http")):
        if lower.startswith(fang):
            candidate = live + candidate[len(fang) :]
            lower = candidate.lower()
            changed = True
            break
    for fang, live in replacements[4:]:
        if fang in candidate:
            candidate = candidate.replace(fang, live)
            changed = True
    return candidate, changed


def _looks_like_email(text: str) -> bool:
    return bool(_EMAIL_RE.match(text.strip().rstrip(".,;:!?)")))


def _collect_spans(text: str) -> list[tuple[int, int, bool]]:
    spans: list[tuple[int, int, bool]] = []
    occupied: list[tuple[int, int]] = []

    def overlaps(start: int, end: int) -> bool:
        for other_start, other_end in occupied:
            if start < other_end and end > other_start:
                return True
        return False

    for match in _SCHEME_URL_RE.finditer(text):
        start, end = _trim_span(text, match.start("url"), match.end("url"))
        if start >= end:
            continue
        occupied.append((start, end))
        original = text[start:end]
        defanged = bool(
            re.search(r"hxxp|\[:\]|\[://\]|\(:\)|\(://\)|\[\.\]|\(\.\)", original, re.I)
        )
        spans.append((start, end, defanged))

    for match in _RISKY_SCHEME_RE.finditer(text):
        start, end = _trim_span(text, match.start("url"), match.end("url"))
        if start >= end or overlaps(start, end):
            continue
        occupied.append((start, end))
        spans.append((start, end, False))

    for match in _DEFANGED_HOST_RE.finditer(text):
        start, end = _trim_span(text, match.start("url"), match.end("url"))
        if start >= end or overlaps(start, end):
            continue
        original = text[start:end]
        if "[.]" not in original and "(.)" not in original:
            continue
        if _looks_like_email(original):
            continue
        occupied.append((start, end))
        spans.append((start, end, True))

    spans.sort(key=lambda item: (item[0], item[1]))
    return spans


def registrable_domain(hostname: str) -> str | None:
    host = hostname.lower().rstrip(".")
    if not host or _ip_from_host(host) is not None:
        return None
    labels = [part for part in host.split(".") if part]
    if len(labels) < 2:
        return host
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:]) if len(labels) >= 3 else last_two
    if last_two in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return last_three
    return last_two


def _ip_from_host(host: str) -> str | None:
    candidate = host
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    candidate = unquote(candidate)
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return None


def _hostname_structure_notes(hostname: str) -> tuple[str, ...]:
    notes: list[str] = []
    labels = [part for part in hostname.lower().split(".") if part]
    if len(labels) >= 4:
        notes.append("hostname has many labels; review subdomain structure")
    if hostname.startswith("xn--") or ".xn--" in hostname:
        notes.append("punycode / IDNA label present; review visually similar names")
    if len(hostname) >= 50:
        notes.append("unusually long hostname")
    return tuple(notes)


def misleading_brand_subdomain(hostname: str) -> str | None:
    """Return a brand token if it appears as a subdomain of an unrelated domain."""

    host = hostname.lower().rstrip(".")
    if _ip_from_host(host) is not None:
        return None
    labels = [part for part in host.split(".") if part]
    registrable = registrable_domain(host)
    if registrable is None or len(labels) < 3:
        return None
    registrable_labels = registrable.split(".")
    subdomain_labels = labels[: max(0, len(labels) - len(registrable_labels))]
    for label in subdomain_labels:
        allowed = BRAND_REGISTRABLE.get(label)
        if allowed and registrable not in allowed:
            return label
    return None


def parse_url_candidate(original_text: str, recognised_defanged: bool) -> ExtractedURL:
    notes: list[str] = []
    candidate, defanged_applied = refang_recognised(original_text)
    recognised_defanged = recognised_defanged or defanged_applied

    if _looks_like_email(original_text):
        return ExtractedURL(
            original_text=original_text,
            normalised_candidate=original_text,
            start=0,
            end=0,
            recognised_defanged=False,
            parse_ok=False,
            scheme=None,
            host=None,
            port=None,
            path="",
            query="",
            userinfo=None,
            host_is_ip=False,
            parse_error="looks_like_email",
            notes=("ordinary email address; not treated as a URL",),
        )

    to_parse = candidate
    if "://" not in to_parse and recognised_defanged:
        to_parse = "http://" + to_parse
        notes.append("scheme inferred as http for defanged host-only candidate")

    try:
        parsed = urlparse(to_parse)
    except ValueError as exc:
        is_bracket = "[" in to_parse or "]" in to_parse or "IPv4 or IPv6" in str(exc)
        err_type = "malformed_bracketed_host" if is_bracket else "malformed_url"
        return ExtractedURL(
            original_text=original_text,
            normalised_candidate=candidate,
            start=0,
            end=0,
            recognised_defanged=recognised_defanged,
            parse_ok=False,
            scheme=None,
            host=None,
            port=None,
            path="",
            query="",
            userinfo=None,
            host_is_ip=False,
            parse_error=err_type,
            notes=(f"URL could not be parsed safely: {exc}",),
        )
    except Exception as exc:  # pragma: no cover - urllib.parse is generally safe
        return ExtractedURL(
            original_text=original_text,
            normalised_candidate=candidate,
            start=0,
            end=0,
            recognised_defanged=recognised_defanged,
            parse_ok=False,
            scheme=None,
            host=None,
            port=None,
            path="",
            query="",
            userinfo=None,
            host_is_ip=False,
            parse_error=type(exc).__name__,
            notes=("URL could not be parsed safely",),
        )

    scheme = (parsed.scheme or "").lower() or None
    host = parsed.hostname
    port: int | None = None
    malformed_port = False
    try:
        port = parsed.port
    except ValueError as exc:
        malformed_port = True
        notes.append(f"port value is not a valid integer: {exc}")

    userinfo = None
    if parsed.username is not None:
        userinfo = parsed.username if parsed.password is None else f"{parsed.username}:***"

    host_is_ip = False
    if host:
        ip_value = _ip_from_host(host)
        host_is_ip = ip_value is not None
        if not host_is_ip:
            notes.extend(_hostname_structure_notes(host))
            brand = misleading_brand_subdomain(host)
            if brand:
                notes.append(f"brand-like subdomain {brand!r} on unrelated registrable domain")

    parse_ok = bool(scheme and (host or scheme in RISKY_SCHEMES or parsed.path))
    if malformed_port:
        parse_ok = False
        parse_error = "malformed_port"
    elif not host and scheme in HTTP_SCHEMES:
        parse_ok = False
        parse_error = "missing_host"
        notes.append("HTTP(S) URL missing host")
    else:
        parse_error = None if parse_ok else "incomplete_parse"

    return ExtractedURL(
        original_text=original_text,
        normalised_candidate=candidate,
        start=0,
        end=0,
        recognised_defanged=recognised_defanged,
        parse_ok=parse_ok,
        scheme=scheme,
        host=host,
        port=port,
        path=parsed.path or "",
        query=parsed.query or "",
        userinfo=userinfo,
        host_is_ip=host_is_ip,
        parse_error=parse_error,
        notes=tuple(notes),
    )


def extract_urls(text: str) -> tuple[ExtractedURL, ...]:
    extracted: list[ExtractedURL] = []
    for start, end, defanged in _collect_spans(text):
        original = text[start:end]
        parsed = parse_url_candidate(original, defanged)
        extracted.append(
            ExtractedURL(
                original_text=parsed.original_text,
                normalised_candidate=parsed.normalised_candidate,
                start=start,
                end=end,
                recognised_defanged=parsed.recognised_defanged,
                parse_ok=parsed.parse_ok,
                scheme=parsed.scheme,
                host=parsed.host,
                port=parsed.port,
                path=parsed.path,
                query=parsed.query,
                userinfo=parsed.userinfo,
                host_is_ip=parsed.host_is_ip,
                parse_error=parsed.parse_error,
                notes=parsed.notes,
            )
        )
    return tuple(extracted)


def _url_finding(
    *,
    rule_id: str,
    severity: Severity,
    title: str,
    extracted: ExtractedURL,
    explanation: str,
    kind: ObservationKind,
) -> Finding:
    return Finding(
        id="",
        rule_id=rule_id,
        category=Category.URL,
        severity=severity,
        title=title,
        evidence_text=extracted.original_text,
        evidence_source=EvidenceSource.ORIGINAL,
        explanation=explanation,
        observation_kind=kind,
        source=FindingSource.DETERMINISTIC,
        start_offset=extracted.start,
        end_offset=extracted.end,
    )


def findings_for_url(extracted: ExtractedURL) -> list[Finding]:
    findings: list[Finding] = []
    if extracted.parse_error == "looks_like_email":
        return findings

    if extracted.recognised_defanged:
        findings.append(
            _url_finding(
                rule_id="E_DEFANGED",
                severity=Severity.MEDIUM,
                title="Recognised defanged URL pattern",
                extracted=extracted,
                explanation=(
                    "A recognised defanging pattern (hxxp/hxxps, [.], [:]) was observed. "
                    "Defanging is common in security discussion and in concealment; "
                    "this is not proof the destination is malicious. Offline parsing "
                    "cannot establish whether a remote site is currently malicious."
                ),
                kind=ObservationKind.DIRECT,
            )
        )

    if extracted.scheme and extracted.scheme in RISKY_SCHEMES:
        findings.append(
            _url_finding(
                rule_id="E_RISKY_SCHEME",
                severity=Severity.HIGH,
                title="Unsupported or risky URL scheme",
                extracted=extracted,
                explanation=(
                    f"Explicit scheme {extracted.scheme!r} is not ordinary HTTP(S). "
                    "The analyser does not execute or fetch the target."
                ),
                kind=ObservationKind.DIRECT,
            )
        )

    if extracted.parse_error in {"malformed_port", "malformed_bracketed_host"}:
        err_desc = extracted.parse_error.replace("_", " ")
        findings.append(
            _url_finding(
                rule_id="E_MALFORMED_URL",
                severity=Severity.MEDIUM,
                title="Malformed URL component",
                extracted=extracted,
                explanation=(
                    f"The candidate URL contains a syntactically invalid component ({err_desc}). "
                    "Partially parsed candidates are distinguished from valid links and not fetched."
                ),
                kind=ObservationKind.DIRECT,
            )
        )

    if not extracted.parse_ok:
        return findings

    if extracted.host_is_ip:
        findings.append(
            _url_finding(
                rule_id="E_IP_HOST",
                severity=Severity.HIGH,
                title="URL host is an IP address",
                extracted=extracted,
                explanation=(
                    "The URL uses a raw IP address as its host. This is unusual for "
                    "consumer services and is worth review. It is not conclusive."
                ),
                kind=ObservationKind.DIRECT,
            )
        )

    if extracted.userinfo is not None:
        findings.append(
            _url_finding(
                rule_id="E_USERINFO",
                severity=Severity.HIGH,
                title="URL contains userinfo",
                extracted=extracted,
                explanation=(
                    "A username (and possibly password) appears before the host "
                    "(@-userinfo). This can impersonate a trusted site in the "
                    "visible text. Credentials in URLs should not be followed."
                ),
                kind=ObservationKind.DIRECT,
            )
        )

    if extracted.port is not None and extracted.port not in STANDARD_PORTS:
        findings.append(
            _url_finding(
                rule_id="E_UNUSUAL_PORT",
                severity=Severity.MEDIUM,
                title="URL uses a non-standard port",
                extracted=extracted,
                explanation=(
                    f"Port {extracted.port} is outside the common HTTP/HTTPS ports "
                    "(80, 443). Unusual ports are not automatically malicious."
                ),
                kind=ObservationKind.HEURISTIC,
            )
        )

    if extracted.host:
        brand = misleading_brand_subdomain(extracted.host)
        if brand:
            findings.append(
                _url_finding(
                    rule_id="E_MISLEADING_HOST",
                    severity=Severity.HIGH,
                    title="Brand-like token used as an unrelated subdomain",
                    extracted=extracted,
                    explanation=(
                        f"The hostname uses {brand!r} as a subdomain of "
                        f"{registrable_domain(extracted.host)!r}, which is not a "
                        "known registrable domain for that brand. This is a "
                        "conservative heuristic, not proof of impersonation."
                    ),
                    kind=ObservationKind.HEURISTIC,
                )
            )
        structure = [note for note in extracted.notes if "hostname" in note or "punycode" in note or "long hostname" in note]
        if structure:
            findings.append(
                _url_finding(
                    rule_id="E_HOST_STRUCTURE",
                    severity=Severity.LOW,
                    title="Hostname structure worth review",
                    extracted=extracted,
                    explanation=" ".join(structure)
                    + " Appearance alone is not treated as malicious.",
                    kind=ObservationKind.HEURISTIC,
                )
            )

    return findings
