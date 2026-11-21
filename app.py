# app.py — Challan + RC→Mobile Only (Render Ready)
import os
import time
import json
import random
import re
import threading
from collections import defaultdict
from datetime import datetime
from functools import wraps
from base64 import b64decode

import requests
import pyaes
from flask import Flask, request, jsonify
from flask_cors import CORS

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_RETRY = True
except ImportError:
    HAS_RETRY = False

# ═══════════════════════════════════════════════════════════════
#  APP + CACHE
# ═══════════════════════════════════════════════════════════════
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
CORS(app)


class SimpleCache:
    def __init__(self, maxsize=500, default_timeout=3600):
        self._d = {}
        self._lock = threading.Lock()
        self.maxsize = maxsize
        self.default_timeout = default_timeout

    def get(self, key):
        with self._lock:
            item = self._d.get(key)
            if not item:
                return None
            value, expires = item
            if time.time() > expires:
                self._d.pop(key, None)
                return None
            return value

    def set(self, key, value, timeout=None):
        timeout = timeout or self.default_timeout
        with self._lock:
            if len(self._d) >= self.maxsize:
                self._d.pop(next(iter(self._d)), None)
            self._d[key] = (value, time.time() + timeout)

    def clear(self):
        with self._lock:
            self._d.clear()

    def __len__(self):
        with self._lock:
            return len(self._d)


cache = SimpleCache()

# ═══════════════════════════════════════════════════════════════
#  RATE LIMIT
# ═══════════════════════════════════════════════════════════════
ip_requests = defaultdict(list)
blocked_ips = {}
MAX_REQ_MIN = 20
MAX_REQ_5MIN = 30
BLOCK_HOURS = 24
WIN_1MIN = 60
WIN_5MIN = 300


def rate_limit(f):
    @wraps(f)
    def wrapper(*a, **kw):
        ip = request.remote_addr or "unknown"
        if request.headers.get("X-Forwarded-For"):
            ip = request.headers["X-Forwarded-For"].split(",")[0].strip()
        now = time.time()
        if ip in blocked_ips:
            until = blocked_ips[ip]
            if now < until:
                return jsonify({
                    "success": False, "error": "IP blocked",
                    "unblock_at": datetime.fromtimestamp(until).isoformat(),
                }), 429
            del blocked_ips[ip]
            ip_requests.pop(ip, None)
        ip_requests[ip] = [t for t in ip_requests.get(ip, []) if now - t <= WIN_5MIN]
        if len(ip_requests[ip]) >= MAX_REQ_5MIN:
            blocked_ips[ip] = now + BLOCK_HOURS * 3600
            return jsonify({"success": False,
                            "error": f"Max {MAX_REQ_5MIN}/5min. Blocked {BLOCK_HOURS}h."}), 429
        one_min = len([t for t in ip_requests[ip] if now - t <= WIN_1MIN])
        if one_min >= MAX_REQ_MIN:
            blocked_ips[ip] = now + BLOCK_HOURS * 3600
            return jsonify({"success": False,
                            "error": f"Max {MAX_REQ_MIN}/min. Blocked {BLOCK_HOURS}h."}), 429
        ip_requests[ip].append(now)
        return f(*a, **kw)
    return wrapper


# ═══════════════════════════════════════════════════════════════
#  UTILS
# ═══════════════════════════════════════════════════════════════
REGEX_STRIP = re.compile(r"[\s-]+")


def normalize(n):
    return REGEX_STRIP.sub("", n or "").upper()


# ═══════════════════════════════════════════════════════════════
#  E-CHALLAN CONFIG
# ═══════════════════════════════════════════════════════════════
ECHALLAN_AES_KEY = b"eECHALLAN@JSON$#"
ECHALLAN_URL = "https://echallan.parivahan.gov.in/api/get-rc-offence-info"
ECHALLAN_HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 15; 23124RN87I Build/AP3A.240905.015.A2)",
    "Connection": "Keep-Alive",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/json",
    "Auth-Token": "YTAyNzEwNTliNjA4NGUzNzZjNGUxNGY4NTNmZTA2MTg6WDFzdE1RdFRoSVVzbkREZ0hITTFsQT09",
    "Content-Language": "en-US",
}
ECHALLAN_PAYLOAD = {
    "device_user_id": "29592",
    "user_id": "329515",
    "token": "6a9ecf2963a6013eb8a44604ec5465a8",
    "IMEI": "AP3A.240905.015.A2",
    "state_code": "MP",
    "user_type": "CPU_DEPARTMENT",
    "is_traffic": 1,
    "mode": 1,
    "api_mode": "live",
    "is_chassis": 0,
}


def echallan_decrypt(enc_b64):
    aes = pyaes.AESModeOfOperationECB(ECHALLAN_AES_KEY)
    raw = b64decode(enc_b64)
    decrypted = b""
    for i in range(0, len(raw), 16):
        decrypted += aes.decrypt(raw[i:i + 16])
    pad = decrypted[-1]
    if not (1 <= pad <= 16):
        return decrypted.decode("utf-8", errors="ignore")
    return decrypted[:-pad].decode("utf-8")


def echallan_lookup(reg_no, **overrides):
    payload = {**ECHALLAN_PAYLOAD, "reg_no": reg_no, **overrides}
    try:
        resp = requests.post(ECHALLAN_URL, data=json.dumps(payload),
                             headers=ECHALLAN_HEADERS, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as e:
        return {"success": False, "vehicle_details": None,
                "challan_details": None, "error": f"HTTP error: {e}"}
    except json.JSONDecodeError as e:
        return {"success": False, "vehicle_details": None,
                "challan_details": None, "error": f"JSON error: {e}"}

    if data.get("status") != 200:
        return {"success": False, "vehicle_details": None,
                "challan_details": None,
                "error": data.get("message", "Unknown API error")}

    result = data.get("result", {})
    vehicle_details = None
    if enc := result.get("vehicle_details"):
        try:
            vehicle_details = json.loads(echallan_decrypt(enc))
        except Exception as e:
            vehicle_details = {"__error__": str(e)}

    challan_details = None
    if enc := result.get("challan_details"):
        try:
            challan_details = json.loads(echallan_decrypt(enc))
        except Exception as e:
            challan_details = {"__error__": str(e)}

    return {"success": True, "vehicle_details": vehicle_details,
            "challan_details": challan_details, "error": None}


# ═══════════════════════════════════════════════════════════════
#  CHASSIS (RenewBuy → SMC)
# ═══════════════════════════════════════════════════════════════
RENEWBUY_URL = "https://apex.renewbuyinsurance.com/api/v1/vaahan/registration_number/"
SMC_API_URL = "https://www.smcinsurance.com/central/centralcall/CallReqWithHeader"
SMC_HEADERS = {
    "content-type": "application/json;charset=UTF-8",
    "accept": "application/json, text/plain, */*",
    "origin": "https://www.smcinsurance.com",
    "referer": "https://www.smcinsurance.com/rto/vehicle-owner-details",
    "x-requested-with": "XMLHttpRequest",
    "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
}

_session = requests.Session()


def renewbuy_chassis(number):
    params = {"regn_no": number, "partner_code": "",
              "mobile_no": "7451010349", "source": "apex", "originData": "false"}
    try:
        r = _session.get(RENEWBUY_URL, params=params, timeout=60)
        if r.status_code != 200:
            return None
        data = r.json()
        if isinstance(data, dict):
            if "code" in data and data.get("code") not in [200, 0, None]:
                return None
            ch = data.get("chassis_number", "")
            if not ch:
                md = data.get("meta_data", {})
                if isinstance(md, dict):
                    sr = md.get("signzy_response", {})
                    if isinstance(sr, dict):
                        rr = sr.get("result", {})
                        if isinstance(rr, dict):
                            ch = rr.get("chassis", "")
            if not ch:
                vd = data.get("vehicle_details", {})
                if isinstance(vd, dict):
                    ch = vd.get("chassis_no", "")
            return ch.replace("*", "") if ch else None
    except Exception:
        pass
    return None


def smc_chassis(number):
    payload = {"URL": "GetVaahanDetailsByVehicleNo", "Props": [number], "Token": ""}
    try:
        r = _session.post(SMC_API_URL, headers=SMC_HEADERS, json=payload,
                          timeout=60)
        if r.status_code != 200:
            return None
        data = r.json()
        if isinstance(data, dict):
            rd = data.get("response", {})
            if isinstance(rd, dict):
                ch = rd.get("chassis", "")
                if ch:
                    return ch.replace("*", "")
    except Exception:
        pass
    return None


def get_chassis(number):
    return renewbuy_chassis(number) or smc_chassis(number)


# ═══════════════════════════════════════════════════════════════
#  PARIVAHAN MOBILE SCRAPE
# ═══════════════════════════════════════════════════════════════
HOMEPAGE_URL = ("https://vahan.parivahan.gov.in/vahanservice/vahan/ui/"
                "statevalidation/homepage.xhtml?statecd="
                "Mzc2MzM2MzAzNjY0MzIzODM3NjIzNjY0MzY2MjM3NDQ0Yw==")
HOMEPAGE_BASE = ("https://vahan.parivahan.gov.in/vahanservice/vahan/ui/"
                 "statevalidation/homepage.xhtml")
LOGIN_URL = "https://vahan.parivahan.gov.in/vahanservice/vahan/ui/usermgmt/login.xhtml"
FORM_URL = ("https://vahan.parivahan.gov.in/vahanservice/vahan/ui/"
            "balanceservice/form_reschedule_fitness.xhtml")


def create_session():
    s = requests.Session()
    if HAS_RETRY:
        retry = Retry(total=1, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/143.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    return s


def extract_viewstate(html):
    if not HAS_BS4:
        return None
    soup = BeautifulSoup(html, "html.parser")
    vs = soup.find("input", {"name": "javax.faces.ViewState"})
    return vs.get("value") if vs else None


def extract_viewstate_ajax(text):
    m = re.search(
        r'<update id="j_id1:javax\.faces\.ViewState:0"><!\[CDATA\[(.*?)\]\]></update>',
        text)
    return m.group(1) if m else None


def find_checkbox_id(html):
    m = re.search(r'<div[^>]*id="(j_idt\d+)"[^>]*class="[^"]*ui-chkbox', html)
    if not m:
        m = re.search(r'PrimeFaces.cw\("SelectBooleanCheckbox"[^}]*id:"(j_idt\d+)"', html)
    return m.group(1) if m else "j_idt193"


def fetch_mobile_parivahan(vehicle_number, chassis_last_5, fallback_mobile=""):
    if not HAS_BS4:
        return {"success": False, "error": "bs4 not installed"}

    session = create_session()
    ajax_headers = {
        "Accept": "application/xml, text/xml, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Faces-Request": "partial/ajax",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "https://vahan.parivahan.gov.in",
    }

    for attempt in range(2):
        try:
            r1 = session.get(HOMEPAGE_URL, timeout=20)
            if r1.status_code != 200:
                continue
            vs = extract_viewstate(r1.text)
            if not vs:
                continue
            cb = find_checkbox_id(r1.text)

            ajax_headers["Referer"] = HOMEPAGE_URL
            r2 = session.post(HOMEPAGE_BASE, data={
                "javax.faces.partial.ajax": "true",
                "javax.faces.source": "fit_c_office_to",
                "javax.faces.partial.execute": "fit_c_office_to",
                "javax.faces.behavior.event": "change",
                "javax.faces.partial.event": "change",
                "homepageformid": "homepageformid",
                "fit_c_office_to_input": "1",
                "javax.faces.ViewState": vs,
            }, headers=ajax_headers, timeout=20)
            vs = extract_viewstate_ajax(r2.text) or vs

            r3 = session.post(HOMEPAGE_BASE, data={
                "javax.faces.partial.ajax": "true",
                "javax.faces.source": cb,
                "javax.faces.partial.execute": cb,
                "javax.faces.partial.render": "proccedHomeButtonId",
                "javax.faces.behavior.event": "change",
                "homepageformid": "homepageformid",
                f"{cb}_input": "on",
                "javax.faces.ViewState": vs,
            }, headers=ajax_headers, timeout=20)
            vs = extract_viewstate_ajax(r3.text) or vs

            r4 = session.post(HOMEPAGE_BASE, data={
                "javax.faces.partial.ajax": "true",
                "javax.faces.source": "proccedHomeButtonId",
                "javax.faces.partial.execute": "@all",
                "proccedHomeButtonId": "proccedHomeButtonId",
                "homepageformid": "homepageformid",
                f"{cb}_input": "on",
                "javax.faces.ViewState": vs,
            }, headers=ajax_headers, timeout=20)
            vs = extract_viewstate_ajax(r4.text) or vs

            dm = re.search(r'id="(j_idt\d+)"[^>]*class="[^"]*ui-button', r4.text)
            dbtn = dm.group(1) if dm else "j_idt536"
            r5 = session.post(HOMEPAGE_BASE, data={
                "javax.faces.partial.ajax": "true",
                "javax.faces.source": dbtn,
                "javax.faces.partial.execute": "@all",
                f"{dbtn}": dbtn,
                "homepageformid": "homepageformid",
                f"{cb}_input": "on",
                "javax.faces.ViewState": vs,
            }, headers=ajax_headers, timeout=20)
            vs = extract_viewstate_ajax(r5.text) or vs

            r6 = session.get(LOGIN_URL + "?faces-redirect=true", timeout=20,
                             allow_redirects=True)
            vs = extract_viewstate(r6.text)
            if not vs:
                continue

            fm = re.search(r'id="(j_idt\d+)"[^>]*name="\1"[^>]*type="submit"', r6.text)
            fit_btn = fm.group(1) if fm else "j_idt506"
            post_headers = {
                **session.headers,
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://vahan.parivahan.gov.in",
                "Referer": LOGIN_URL + "?faces-redirect=true",
            }
            session.post(LOGIN_URL, data={
                "loginForm": "loginForm",
                f"{fit_btn}": fit_btn,
                "javax.faces.ViewState": vs,
                "fitbalcTest": "fitbalcTest",
                "pur_cd": "86",
            }, headers=post_headers, timeout=20, allow_redirects=True)

            form_headers = {**session.headers,
                            "Referer": LOGIN_URL + "?faces-redirect=true"}
            r8 = session.get(FORM_URL, headers=form_headers, timeout=20)
            vs = extract_viewstate(r8.text)
            if not vs:
                continue

            ajax_headers["Referer"] = FORM_URL
            r9 = session.post(FORM_URL, data={
                "javax.faces.partial.ajax": "true",
                "javax.faces.source": "balanceFeesFine:validate_dtls",
                "javax.faces.partial.execute": "@all",
                "javax.faces.partial.render": "balanceFeesFine:auth_panel",
                "balanceFeesFine:validate_dtls": "balanceFeesFine:validate_dtls",
                "balanceFeesFine": "balanceFeesFine",
                "balanceFeesFine:tf_reg_no": vehicle_number,
                "balanceFeesFine:tf_chasis_no": chassis_last_5,
                "javax.faces.ViewState": vs,
            }, headers=ajax_headers, timeout=20)

            txt = r9.text
            for pat in [r'id="balanceFeesFine:tf_mobile"[^>]*value="(\d{10})"',
                        r'value="(\d{10})"[^>]*id="balanceFeesFine:tf_mobile"',
                        r'balanceFeesFine:tf_mobile[^>]*value="(\d{10})"']:
                m = re.search(pat, txt, re.DOTALL)
                if m and m.group(1)[0] in "6789":
                    return {"success": True, "mobile_number": m.group(1)}

            fb = re.findall(r"\b[6-9]\d{9}\b", txt)
            if fb:
                return {"success": True, "mobile_number": fb[0]}
        except Exception:
            pass
        if attempt == 0:
            time.sleep(2)

    if fallback_mobile and len(fallback_mobile) == 10 and fallback_mobile[0] in "6789":
        return {"success": True, "mobile_number": fallback_mobile}
    return {"success": False, "error": "Mobile not found"}


# ═══════════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════════
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "success": True,
        "message": "🚗 Challan + RC→Mobile API",
        "endpoints": {
            "/challan?number=MH29SY6188": "E-Challan Parivahan",
            "/rc4?number=MH12AB1234": "RC → Mobile (Parivahan scrape)",
            "/health": "Health check",
        },
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "cache_size": len(cache),
        "deps": {"bs4": HAS_BS4, "retry": HAS_RETRY},
        "rate_limits": {
            "max_per_min": MAX_REQ_MIN,
            "max_per_5min": MAX_REQ_5MIN,
            "block_hours": BLOCK_HOURS,
        },
    })


@app.route("/challan", methods=["GET"])
@rate_limit
def challan_route():
    reg = normalize(request.args.get("number", ""))
    if not reg:
        return jsonify({"success": False, "error": "number required",
                        "example": "/challan?number=MH29SY6188"}), 400

    key = f"challan|{reg}"
    hit = cache.get(key)
    if hit:
        hit["cached"] = True
        return jsonify(hit)

    t0 = time.perf_counter()
    r = echallan_lookup(reg)
    rt = round(time.perf_counter() - t0, 2)

    r["reg_no"] = reg
    r["response_time"] = rt
    r["cached"] = False

    if r["success"]:
        cache.set(key, r, timeout=1800)

    return jsonify(r), (200 if r["success"] else 502)


@app.route("/rc4", methods=["GET"])
@rate_limit
def rc4():
    reg = normalize(request.args.get("number", ""))
    if not reg:
        return jsonify({"success": False, "error": "number required",
                        "example": "/rc4?number=MH12AB1234"}), 400

    key = f"rc4|{reg}"
    hit = cache.get(key)
    if hit:
        hit["cached"] = True
        return jsonify(hit)

    t0 = time.perf_counter()
    ch = get_chassis(reg)
    if not ch:
        return jsonify({
            "success": False,
            "vehicle_number": reg,
            "error": "chassis not found (needed for mobile lookup)",
        }), 404

    m = fetch_mobile_parivahan(reg, ch[-5:])
    rt = round(time.perf_counter() - t0, 2)

    out = {
        "success": m.get("success", False),
        "vehicle_number": reg,
        "chassis_last_5": ch[-5:],
        "mobile": m.get("mobile_number"),
        "error": m.get("error"),
        "response_time": rt,
        "cached": False,
    }
    if m.get("success"):
        cache.set(key, out, timeout=3600)
    else:
        cache.set(key, out, timeout=300)
    return jsonify(out), (200 if m.get("success") else 502)


@app.route("/cache/clear", methods=["POST"])
def clear_cache():
    cache.clear()
    return jsonify({"success": True, "message": "cache cleared"})


# ═══════════════════════════════════════════════════════════════
#  MAIN (local + Render)
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print("=" * 60)
    print("  🚗 Challan + RC→Mobile API")
    print(f"  http://0.0.0.0:{port}/")
    print("=" * 60)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
