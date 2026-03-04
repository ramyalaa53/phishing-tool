import re
from urllib.parse import urlparse
LENGTH_THRESHOLD = 75
DOTS_THRESHOLD = 3

suspicious_words = ["verify", "update", "secure", "account", "bank", "confirm", "login",
                    "payment", "signin", "security", "reset", "urgent"]

#  استبدال الأرقام بالحروف
_subs = str.maketrans({
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '@': 'a',
    '$': 's'
})

# كلمات أو علامات شهيرة للكشف عن التقليد
BRAND_KEYWORDS = ["facebook", "google", "paypal", "amazon", "microsoft", "bank", "apple", "instagram", "twitter"]

def _normalize_pattern(p):
    return p.strip().lower() if p else ''

def _match_pattern_to_domain(pattern, domain, full_url):
    """مطابقة الدومين أو URL مع pattern في القائمة"""
    if not pattern:
        return False
    p = _normalize_pattern(pattern)
    domain = (domain or '').lower()
    full = (full_url or '').lower()

    if p.startswith("*."):
        return domain.endswith(p[2:])
    if p == domain or domain.endswith("." + p):
        return True
    if p in full:
        return True
    return False

def _is_brand_lookalike(domain, full_url):
    """كشف تقليد العلامات الشهيرة (typo/lookalike)"""
    dom = domain.split(':')[0].lower()
    parts = dom.split('.')
    for part in parts:
        clean = part.translate(_subs)
        for brand in BRAND_KEYWORDS:
            if brand in clean or clean in brand:
                return brand
    full_clean = full_url.lower().translate(_subs)
    for brand in BRAND_KEYWORDS:
        if brand in full_clean:
            return brand
    return None

def evaluate_url(url, blacklist_patterns=None, whitelist_patterns=None):
    reasons = []
    score = 0
    u = (url or '').strip()

    if not re.match(r'^https?://', u):
        reasons.append("Missing schema (http/https)")
        score += 1

    try:
        parsed = urlparse(u if re.match(r'^https?://', u) else 'http://' + u)
        domain = parsed.netloc.lower()
        path = parsed.path + ('?' + parsed.query if parsed.query else '')
    except Exception:
        parsed = None
        domain = ''
        path = ''

    matched = {"blacklist": [], "whitelist": []}

    #  فحص القوائم
    if blacklist_patterns:
        for p in blacklist_patterns:
            if _match_pattern_to_domain(p, domain, u):
                matched["blacklist"].append(_normalize_pattern(p))
    if whitelist_patterns:
        for p in whitelist_patterns:
            if _match_pattern_to_domain(p, domain, u):
                matched["whitelist"].append(_normalize_pattern(p))

    #  أولوية الـ blacklist
    if matched["blacklist"] and not matched["whitelist"]:
        return {"score": 10, "result": "SUSPICIOUS (blacklisted)",
                "reasons": ["Matched blacklist pattern: " + ", ".join(matched["blacklist"])],
                "matched": matched, "domain": domain}

    #  Lookalike / brand spoof check
    brand = _is_brand_lookalike(domain, u)
    if brand:
        reasons.append(f"Possible brand lookalike / typo-squat for: {brand}")
        return {"score": 8, "result": "SUSPICIOUS (brand lookalike)",
                "reasons": reasons, "matched": matched, "domain": domain}

    #  أولوية الـ whitelist
    if matched["whitelist"] and not matched["blacklist"]:
        return {"score": 0, "result": "SAFE (whitelisted)",
                "reasons": ["Matched whitelist pattern: " + ", ".join(matched["whitelist"])],
                "matched": matched, "domain": domain}

    # باقي القواعد العامة
    if len(u) > LENGTH_THRESHOLD:
        score += 1
        reasons.append("URL length is long")
    if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
        score += 2
        reasons.append("URL uses an IP address instead of domain")
    if not u.startswith("https://"):
        score += 1
        reasons.append("No HTTPS (not secure)")
    if '@' in u:
        score += 2
        reasons.append("Contains '@' which may redirect to another URL")
    if domain.count('.') > DOTS_THRESHOLD:
        score += 1
        reasons.append("Domain has many subdomains/dots (possible lookalike)")
    low = u.lower()
    if any(w in low for w in suspicious_words):
        score += 1
        reasons.append("Contains suspicious keywords (e.g., verify, secure, login)")
    if "xn--" in domain:
        score += 2
        reasons.append("Contains punycode (possible IDN homograph)")
    if '//' in path and path.count('/') > 3:
        score += 1
        reasons.append("Complex path with many segments or redirects")

    if score >= 4:
        result = "SUSPICIOUS"
    elif score >= 2:
        result = "POTENTIALLY RISKY"
    else:
        result = "SAFE"

    return {"score": score, "result": result, "reasons": reasons, "matched": matched, "domain": domain}