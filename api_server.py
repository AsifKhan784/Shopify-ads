import os
import asyncio
import concurrent.futures
import functools
import logging
import random
import time
import uuid
from typing import Optional, Tuple

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from checkout_engine import (
    run_checkout_for_card,
    normalize_proxy,
    parse_card_entry,
)

# ── Logging ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cardcheckout.api")

# ── Configuration ──────────────────────────────────────────────────────
THREAD_WORKERS = int(os.environ.get("CHECKER_THREADS", "200"))
MAX_RETRIES    = int(os.environ.get("CHECKER_RETRIES", "1"))
CHECK_TIMEOUT  = float(os.environ.get("CHECK_TIMEOUT", "75"))

import threading as _threading

_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=THREAD_WORKERS,
    thread_name_prefix="chk",
)

_active_checks      = 0
_active_checks_lock = _threading.Lock()

def _inc_active():
    global _active_checks
    with _active_checks_lock:
        _active_checks += 1

def _dec_active():
    global _active_checks
    with _active_checks_lock:
        _active_checks -= 1


# ── FastAPI app ────────────────────────────────────────────────────────
app = FastAPI(
    title="CardCheckout API",
    version="2.2.0",
    description="Shopify card-check API.",
    docs_url=None,
    redoc_url=None,
)


# ── Custom /docs UI ────────────────────────────────────────────────────
_DOCS_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>CardCheckout API</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet"/>
<script src="https://unpkg.com/@phosphor-icons/web@2.1.1/src/index.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#03030a;--glass:rgba(255,255,255,0.03);--glass2:rgba(255,255,255,0.06);
  --border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.13);
  --p:#8b5cf6;--p2:#a78bfa;--p3:#c4b5fd;
  --cyan:#06b6d4;--green:#10b981;--red:#f43f5e;--amber:#f59e0b;
  --text:#f1f5f9;--text2:#94a3b8;--text3:#475569;--mono:'JetBrains Mono',monospace;
}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;min-height:100vh;line-height:1.6}
.mesh{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.orb{position:absolute;border-radius:50%;filter:blur(120px);opacity:.15;animation:drift 22s infinite ease-in-out}
.orb1{width:700px;height:700px;background:radial-gradient(circle,#7c3aed,transparent 70%);top:-250px;left:-200px}
.orb2{width:550px;height:550px;background:radial-gradient(circle,#0e7490,transparent 70%);top:40%;right:-180px}
.orb3{width:450px;height:450px;background:radial-gradient(circle,#5b21b6,transparent 70%);bottom:-120px;left:35%}
@keyframes drift{0%,100%{transform:translate(0,0)}33%{transform:translate(40px,-30px)}66%{transform:translate(-20px,20px)}}
.wrap{position:relative;z-index:1;max-width:880px;margin:0 auto;padding:0 24px 80px}
nav{position:sticky;top:0;z-index:100;padding:0 24px;backdrop-filter:blur(28px);background:rgba(3,3,10,.75);border-bottom:1px solid var(--border)}
.nav-i{max-width:880px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;height:62px}
.logo{display:flex;align-items:center;gap:10px;text-decoration:none}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,#7c3aed,#06b6d4);border-radius:11px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 28px rgba(124,58,237,.55)}
.logo-name{font-size:16px;font-weight:800;color:var(--text)}
.logo-name em{background:linear-gradient(135deg,var(--p2),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-style:normal}
.logo-ver{font-size:10px;font-weight:600;letter-spacing:1.2px;color:var(--p2);background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.28);padding:2px 9px;border-radius:20px}
.live-pill{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--green);font-weight:600;background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.2);padding:4px 12px;border-radius:20px}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:blink 2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
.hero{padding:56px 0 48px;text-align:center}
.hero h1{font-size:clamp(30px,5vw,50px);font-weight:800;letter-spacing:-1.8px;line-height:1.12;margin-bottom:18px}
.hero h1 .g{background:linear-gradient(135deg,#a78bfa 0%,#38bdf8 50%,#34d399 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero p{font-size:15px;color:var(--text2);max-width:500px;margin:0 auto 38px}
.stats{display:flex;gap:10px;justify-content:center;flex-wrap:wrap}
.stat{background:var(--glass);border:1px solid var(--border);border-radius:30px;padding:7px 16px;font-size:12px;color:var(--text2)}
.stat strong{color:var(--text);font-weight:600}
.sh{display:flex;align-items:center;gap:10px;margin:44px 0 14px}
.sh-title{font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--text3)}
.sh-line{flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}
.ep{background:var(--glass);border:1px solid var(--border);border-radius:14px;margin-bottom:10px;overflow:hidden}
.ep-h{display:flex;align-items:center;gap:14px;padding:15px 20px;cursor:pointer}
.mtag{font-family:var(--mono);font-size:11px;font-weight:700;padding:4px 12px;border-radius:7px;min-width:55px;text-align:center}
.GET{background:rgba(16,185,129,.1);color:#34d399;border:1px solid rgba(16,185,129,.22)}
.POST{background:rgba(139,92,246,.1);color:#a78bfa;border:1px solid rgba(139,92,246,.22)}
.ep-path{font-family:var(--mono);font-size:14px;font-weight:500}
.ep-desc{font-size:12px;color:var(--text2);margin-left:auto}
.ep-b{display:none;border-top:1px solid var(--border);background:rgba(0,0,0,.18)}
.ep.open .ep-b{display:block}
.panel{padding:20px}
.form{display:flex;flex-direction:column;gap:13px}
.fl{font-size:12px;font-weight:500;color:var(--text2);margin-bottom:5px}
.rs{color:var(--red)}
input[type=text]{width:100%;background:rgba(0,0,0,.35);border:1px solid var(--border2);border-radius:10px;padding:10px 14px;color:var(--text);font-family:var(--mono);font-size:13px;outline:none}
input[type=text]:focus{border-color:var(--p);box-shadow:0 0 0 3px rgba(139,92,246,.14)}
.cb{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text2);cursor:pointer}
.cb input{accent-color:var(--p)}
.sbtn{background:linear-gradient(135deg,#7c3aed,#4f46e5);border:none;border-radius:10px;padding:12px 26px;color:#fff;font-weight:700;font-size:13px;cursor:pointer}
.sbtn:hover{transform:translateY(-2px);box-shadow:0 10px 28px rgba(124,58,237,.45)}
.rbox{margin-top:16px;border-radius:10px;border:1px solid var(--border);overflow:hidden;display:none}
.rbox.show{display:block}
.rhead{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--border);background:rgba(0,0,0,.4)}
.rstat{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text2)}
.rbadge{padding:3px 11px;border-radius:20px;font-size:11px;font-weight:700}
.S-CHARGED{background:rgba(16,185,129,.14);color:#34d399;border:1px solid rgba(16,185,129,.28)}
.S-APPROVED{background:rgba(6,182,212,.14);color:#22d3ee;border:1px solid rgba(6,182,212,.28)}
.S-DECLINED{background:rgba(244,63,94,.14);color:#fb7185;border:1px solid rgba(244,63,94,.28)}
.S-ERROR{background:rgba(245,158,11,.14);color:#fbbf24;border:1px solid rgba(245,158,11,.28)}
.rbody{padding:16px;background:rgba(0,0,0,.5);font-family:var(--mono);font-size:12.5px;line-height:1.85;overflow-x:auto;white-space:pre;max-height:340px;overflow-y:auto;color:#e2e8f0}
.lgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:10px}
.lc{background:var(--glass);border:1px solid var(--border);border-radius:10px;padding:15px;display:flex;gap:12px}
.li{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.lt{font-weight:700;font-size:13px;margin-bottom:3px}
.ld{font-size:12px;color:var(--text2)}
.lc-ch .li{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.18)}
.lc-ap .li{background:rgba(6,182,212,.1);border:1px solid rgba(6,182,212,.18)}
.lc-dc .li{background:rgba(244,63,94,.1);border:1px solid rgba(244,63,94,.18)}
.lc-er .li{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.18)}
.lt-ch{color:#34d399}.lt-ap{color:#22d3ee}.lt-dc{color:#fb7185}.lt-er{color:#fbbf24}
</style>
</head>
<body>
<div class="mesh"><div class="orb orb1"></div><div class="orb orb2"></div><div class="orb orb3"></div></div>
<nav><div class="nav-i">
  <a class="logo" href="#"><div class="logo-icon"><i class="ph-bold ph-lightning" style="color:#fff;font-size:19px"></i></div>
  <span class="logo-name">Card<em>Checkout</em></span><span class="logo-ver">v2.2</span></a>
  <div class="live-pill"><div class="live-dot"></div>Live</div>
</div></nav>
<div class="wrap">
<div class="hero">
  <h1>Card verification<br><span class="g">at production scale</span></h1>
  <p>Supply a card, Shopify store URL and proxy — the engine finds the cheapest product, runs a full checkout, and returns a precise result.</p>
  <div class="stats">
    <div class="stat"><strong>200</strong> threads</div>
    <div class="stat"><strong>Auto-retry</strong> on errors</div>
    <div class="stat"><strong>TLS</strong> fingerprint spoof</div>
    <div class="stat"><strong>$0.50 – $5.00</strong> price band</div>
  </div>
</div>
<div class="sh"><span class="sh-title">Endpoints</span><div class="sh-line"></div></div>
<div class="ep" id="e-health"><div class="ep-h" onclick="tog('e-health')">
  <span class="mtag GET">GET</span><span class="ep-path">/health</span><span class="ep-desc">Liveness check</span>
</div><div class="ep-b"><div class="panel">
  <button class="sbtn" onclick="req('health',event)">Send</button>
  <div class="rbox" id="rb-health"><div class="rhead"><div class="rstat">Response<span class="rbadge" id="bd-health"></span></div></div><div class="rbody" id="by-health"></div></div>
</div></div></div>
<div class="ep" id="e-get"><div class="ep-h" onclick="tog('e-get')">
  <span class="mtag GET">GET</span><span class="ep-path">/check</span><span class="ep-desc">Check via query params</span>
</div><div class="ep-b"><div class="panel">
  <div class="form">
    <div><div class="fl">Card <span class="rs">*</span></div><input type="text" id="gc" placeholder="4111111111111111|12|2026|123"/></div>
    <div><div class="fl">Shop URL <span class="rs">*</span></div><input type="text" id="gu" placeholder="https://store.myshopify.com"/></div>
    <div><div class="fl">Proxy <span class="rs">*</span></div><input type="text" id="gp" placeholder="http://user:pass@host:port"/></div>
    <label class="cb"><input type="checkbox" id="gl" checked/> Low mode</label>
    <button class="sbtn" onclick="req('get',event)">Send</button>
  </div>
  <div class="rbox" id="rb-get"><div class="rhead"><div class="rstat">Response<span class="rbadge" id="bd-get"></span></div></div><div class="rbody" id="by-get"></div></div>
</div></div></div>
<div class="ep" id="e-post"><div class="ep-h" onclick="tog('e-post')">
  <span class="mtag POST">POST</span><span class="ep-path">/check</span><span class="ep-desc">Check via JSON body</span>
</div><div class="ep-b"><div class="panel">
  <div class="form">
    <div><div class="fl">Card <span class="rs">*</span></div><input type="text" id="pc" placeholder="4111111111111111|12|2026|123"/></div>
    <div><div class="fl">Shop URL <span class="rs">*</span></div><input type="text" id="pu" placeholder="https://store.myshopify.com"/></div>
    <div><div class="fl">Proxy <span class="rs">*</span></div><input type="text" id="pp" placeholder="http://user:pass@host:port"/></div>
    <label class="cb"><input type="checkbox" id="pl" checked/> Low mode</label>
    <button class="sbtn" onclick="req('post',event)">Send</button>
  </div>
  <div class="rbox" id="rb-post"><div class="rhead"><div class="rstat">Response<span class="rbadge" id="bd-post"></span></div></div><div class="rbody" id="by-post"></div></div>
</div></div></div>
<div class="sh"><span class="sh-title">Response Statuses</span><div class="sh-line"></div></div>
<div class="lgrid">
  <div class="lc lc-ch"><div class="li"><i class="ph-bold ph-check-circle" style="color:#34d399;font-size:18px"></i></div><div><div class="lt lt-ch">CHARGED</div><div class="ld">Order placed</div></div></div>
  <div class="lc lc-ap"><div class="li"><i class="ph-bold ph-seal-check" style="color:#22d3ee;font-size:18px"></i></div><div><div class="lt lt-ap">APPROVED</div><div class="ld">3DS or insufficient funds</div></div></div>
  <div class="lc lc-dc"><div class="li"><i class="ph-bold ph-x-circle" style="color:#fb7185;font-size:18px"></i></div><div><div class="lt lt-dc">DECLINED</div><div class="ld">Rejected by issuer/risk</div></div></div>
  <div class="lc lc-er"><div class="li"><i class="ph-bold ph-warning" style="color:#fbbf24;font-size:18px"></i></div><div><div class="lt lt-er">ERROR</div><div class="ld">Store/proxy issue — retryable</div></div></div>
</div>
</div>
<script>
function tog(id){document.getElementById(id).classList.toggle('open')}
async function req(t,ev){
  ev.target.disabled=true;
  const rb=document.getElementById('rb-'+t),bd=document.getElementById('bd-'+t),by=document.getElementById('by-'+t);
  try{
    let r;
    if(t==='health'){r=await fetch('/health');}
    else if(t==='get'){const p=new URLSearchParams({card:gc.value,url:gu.value,proxy:gp.value,low:gl.checked?'true':'false'});r=await fetch('/check?'+p);}
    else{r=await fetch('/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({card:pc.value,shop_url:pu.value,proxy:pp.value,low:pl.checked})});}
    const d=await r.json();
    const s=d.Response||d.status||'ERROR';
    bd.textContent=s;bd.className='rbadge S-'+s;by.textContent=JSON.stringify(d,null,2);rb.classList.add('show');
  }catch(e){bd.textContent='ERROR';bd.className='rbadge S-ERROR';by.textContent='Request failed: '+e.message;rb.classList.add('show');}
  ev.target.disabled=false;
}
const [gc,gu,gp,gl,pc,pu,pp,pl]=['gc','gu','gp','gl','pc','pu','pp','pl'].map(id=>document.getElementById(id));
</script>
</body>
</html>
"""


# ── Request / Response models ──────────────────────────────────────────
class CheckRequest(BaseModel):
    card:     Optional[str]  = None
    shop_url: Optional[str]  = None
    proxy:    Optional[str]  = None
    low:      bool           = True


class CheckResponse(BaseModel):
    Response:    str  = "ERROR"
    CC:          str  = ""
    Price:       str  = ""
    Gate:        str  = "Shopify"
    Site:        str  = ""
    Charged:     str  = "False"
    status_code: str  = ""
    error:       str  = ""
    retryable:   bool = False
    receipt_url: str  = ""


# ── Helpers ────────────────────────────────────────────────────────────
def _validate_proxy(raw: str) -> Tuple[Optional[str], Optional[CheckResponse]]:
    if not raw or not raw.strip():
        return None, CheckResponse(
            Response="ERROR", status_code="PROXY_REQUIRED",
            error="proxy is required — e.g. http://user:pass@1.2.3.4:8080",
            retryable=False,
        )
    try:
        return normalize_proxy(raw), None
    except Exception as exc:
        return None, CheckResponse(
            Response="ERROR", status_code="PROXY_INVALID",
            error=f"Invalid proxy format: {exc}",
            retryable=False,
        )


def _validate_card(raw: str) -> Tuple[Optional[str], Optional[CheckResponse]]:
    import datetime as _dt
    if not raw or not raw.strip():
        return None, CheckResponse(
            Response="ERROR", status_code="CARD_REQUIRED",
            error="card is required — format: number|mm|yyyy|cvv",
            retryable=False,
        )
    try:
        _num, _month, _year, _cvv = parse_card_entry(raw)
    except Exception as exc:
        return None, CheckResponse(
            Response="ERROR", status_code="CARD_INVALID",
            error=f"invalid card format: {exc}",
            retryable=False,
        )
    now = _dt.datetime.utcnow()
    if _year < now.year or (_year == now.year and _month < now.month):
        return None, CheckResponse(
            Response="ERROR", status_code="CARD_EXPIRED",
            error=f"card expired: {_month:02d}/{_year}",
            retryable=False,
        )
    return raw.strip(), None


def _validate_url(raw: str) -> Tuple[Optional[str], Optional[CheckResponse]]:
    import urllib.parse as _up
    if not raw or not raw.strip():
        return None, CheckResponse(
            Response="ERROR", status_code="URL_REQUIRED",
            error="shop url is required",
            retryable=False,
        )
    url = raw.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        parsed = _up.urlparse(url)
        hostname = parsed.hostname or ""
        if not hostname or "." not in hostname or " " in hostname:
            raise ValueError(hostname)
    except Exception:
        return None, CheckResponse(
            Response="ERROR", status_code="URL_INVALID",
            error=f"invalid shop url: {raw!r}",
            retryable=False,
        )
    return url, None


def _build_response(res, shop_url: str = "") -> CheckResponse:
    status_name = res.status.name
    return CheckResponse(
        Response    = status_name,
        CC          = res.card or "",
        Price       = res.amount or "",
        Gate        = "Shopify",
        Site        = shop_url or res.shop_url or "",
        Charged     = "True" if status_name == "CHARGED" else "False",
        status_code = res.status_code or "",
        error       = str(res.error) if res.error else "",
        retryable   = res.retryable,
        receipt_url = res.receipt_url or "",
    )


async def _run_check(shop_url: str, card: str, proxy_url: str, low: bool) -> CheckResponse:
    loop     = asyncio.get_running_loop()
    attempts = 1 + MAX_RETRIES
    last: Optional[CheckResponse] = None

    for attempt in range(1, attempts + 1):
        t0 = time.perf_counter()
        _inc_active()
        try:
            fn  = functools.partial(run_checkout_for_card, shop_url, card, proxy_url, low)
            res = await asyncio.wait_for(
                loop.run_in_executor(_pool, fn),
                timeout=CHECK_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.warning("attempt %d/%d hard-timeout after %.0fs",
                           attempt, attempts, CHECK_TIMEOUT)
            last = CheckResponse(Response="ERROR", status_code="TIMEOUT",
                                 error=f"engine hard-timeout after {CHECK_TIMEOUT}s",
                                 retryable=True)
            continue
        except Exception as exc:
            logger.warning("attempt %d/%d — unhandled exception: %s", attempt, attempts, exc)
            last = CheckResponse(Response="ERROR", error=str(exc), retryable=True)
            continue
        finally:
            _dec_active()

        resp = _build_response(res, shop_url)
        logger.info(
            "attempt %d/%d | status=%-8s code=%-24s elapsed=%.1fs",
            attempt, attempts, resp.Response, resp.status_code or "-",
            time.perf_counter() - t0,
        )
        if resp.Response in ("CHARGED", "APPROVED"):
            logger.info("HIT | status=%s | amount=%s | site=%s",
                        resp.Response, resp.Price, shop_url)

        if not resp.retryable or attempt == attempts:
            return resp

        backoff = min(2.0, 0.4 * (2 ** (attempt - 1))) + (random.random() * 0.3)
        logger.info("retrying in %.2fs (retryable=true)…", backoff)
        await asyncio.sleep(backoff)
        last = resp

    return last  # type: ignore[return-value]


# ── Routes ─────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root():
    return HTMLResponse(_DOCS_HTML)


@app.get("/docs", include_in_schema=False)
async def custom_docs():
    return HTMLResponse(_DOCS_HTML)


@app.get("/health", tags=["meta"])
async def health():
    with _active_checks_lock:
        active = _active_checks
    return {
        "ok":            True,
        "threads":       THREAD_WORKERS,
        "retries":       MAX_RETRIES,
        "timeout":       CHECK_TIMEOUT,
        "active_checks": active,
    }


@app.get("/check", response_model=CheckResponse, tags=["check"])
async def check_get(
    card:  str = Query(..., description="number|mm|yyyy|cvv"),
    url:   str = Query(..., description="Shopify store URL"),
    proxy: str = Query(..., description="http://user:pass@host:port"),
    low:   str = Query(default="true"),
):
    card_val, err = _validate_card(card)
    if err:
        err.CC = card
        return err

    url_val, err = _validate_url(url)
    if err:
        err.CC = card
        err.Site = url
        return err

    proxy_val, err = _validate_proxy(proxy)
    if err:
        err.CC = card
        err.Site = url_val
        return err

    low_mode = low.strip().lower() in ("1", "true", "yes")
    return await _run_check(url_val, card_val, proxy_val, low_mode)


@app.post("/check", response_model=CheckResponse, tags=["check"])
async def check_post(req: CheckRequest):
    raw_card = req.card or ""
    raw_url  = req.shop_url or ""
    card_val, err = _validate_card(raw_card)
    if err:
        err.CC = raw_card
        return err

    url_val, err = _validate_url(raw_url)
    if err:
        err.CC   = raw_card
        err.Site = raw_url
        return err

    proxy_val, err = _validate_proxy(req.proxy or "")
    if err:
        err.CC   = raw_card
        err.Site = url_val
        return err

    return await _run_check(url_val, card_val, proxy_val, req.low)


# ── Lifecycle ─────────────────────────────────────────────────────────
@app.on_event("shutdown")
async def _shutdown():
    logger.info("shutting down thread pool…")
    _pool.shutdown(wait=False, cancel_futures=True)


# ── Standalone ────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    logger.info("CardCheckout API — port=%d threads=%d retries=%d",
                port, THREAD_WORKERS, MAX_RETRIES)
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="warning",
        backlog=2048,
        limit_concurrency=THREAD_WORKERS * 2,
        timeout_keep_alive=60,
    )
