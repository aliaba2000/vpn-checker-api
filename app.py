from flask import Flask, request, jsonify
import requests
import os
import datetime

app = Flask(__name__)
API_KEY = os.environ.get('API_KEY', '')

# Darmowe źródła do sprawdzania VPN/Proxy/TOR
# ip-api.com: 45 req/min bez klucza, zwraca proxy/vpn/tor/hosting
# proxycheck.io: 100 req/dzień bez klucza
# iphub.info: 1000 req/dzień bez klucza (blok 0=ok, 1=vpn/proxy, 2=residential proxy)

IPAPI_URL = "http://ip-api.com/json/{ip}?fields=status,message,proxy,vpn,tor,hosting,isp,org,as,countryCode,country,city"
PROXYCHECK_URL = "http://proxycheck.io/v2/{ip}?vpn=1&asn=1"
IPHUB_URL = "http://v2.api.iphub.info/ip/{ip}"
IPHUB_KEY = os.environ.get('IPHUB_KEY', '')  # opcjonalny, zwiększa limit


@app.before_request
def check_api_key():
    if request.path == '/':
        return
    key = request.args.get('key') or request.headers.get('X-API-Key')
    if not API_KEY or key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401


def check_ipapi(ip):
    try:
        r = requests.get(IPAPI_URL.format(ip=ip), timeout=5)
        data = r.json()
        if data.get('status') == 'fail':
            return {"error": data.get('message', 'unknown error')}
        return {
            "is_vpn": data.get('vpn', False),
            "is_proxy": data.get('proxy', False),
            "is_tor": data.get('tor', False),
            "is_hosting": data.get('hosting', False),
            "isp": data.get('isp', ''),
            "org": data.get('org', ''),
            "as": data.get('as', ''),
            "country": data.get('country', ''),
            "country_code": data.get('countryCode', ''),
            "city": data.get('city', ''),
        }
    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def check_proxycheck(ip):
    try:
        r = requests.get(PROXYCHECK_URL.format(ip=ip), timeout=5)
        data = r.json()
        status = data.get('status', '')
        if status == 'error':
            return {"error": data.get('message', 'unknown error')}
        ip_data = data.get(ip, {})
        proxy_val = ip_data.get('proxy', 'no')
        vpn_val = ip_data.get('type', '')
        return {
            "is_proxy": proxy_val == 'yes',
            "type": vpn_val,  # np. "VPN", "TOR", "SOCKS5", ""
            "asn": ip_data.get('asn', ''),
            "provider": ip_data.get('provider', ''),
            "country": ip_data.get('country', ''),
            "country_code": ip_data.get('isocode', ''),
        }
    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def check_iphub(ip):
    try:
        headers = {}
        if IPHUB_KEY:
            headers['X-Key'] = IPHUB_KEY
        r = requests.get(IPHUB_URL.format(ip=ip), headers=headers, timeout=5)
        if r.status_code == 429:
            return {"error": "rate limit exceeded"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        data = r.json()
        block = data.get('block', -1)
        # block: 0 = OK (residential/business), 1 = VPN/proxy (niezalecane), 2 = residential proxy
        return {
            "block": block,
            "is_vpn_or_proxy": block == 1,
            "is_residential_proxy": block == 2,
            "isp": data.get('isp', ''),
            "country_code": data.get('countryCode', ''),
        }
    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def aggregate_risk(ipapi, proxycheck, iphub):
    """
    Wylicza risk_score 0-100 i flagę is_suspicious
    na podstawie wyników z trzech źródeł.
    """
    score = 0
    flags = []

    # ip-api.com
    if isinstance(ipapi, dict) and 'error' not in ipapi:
        if ipapi.get('is_vpn'):
            score += 40
            flags.append('vpn')
        if ipapi.get('is_proxy'):
            score += 35
            flags.append('proxy')
        if ipapi.get('is_tor'):
            score += 50
            flags.append('tor')
        if ipapi.get('is_hosting'):
            score += 15
            flags.append('hosting')

    # proxycheck.io
    if isinstance(proxycheck, dict) and 'error' not in proxycheck:
        if proxycheck.get('is_proxy'):
            score += 30
            if 'proxy' not in flags:
                flags.append('proxy')
        ptype = proxycheck.get('type', '').upper()
        if ptype == 'TOR' and 'tor' not in flags:
            score += 40
            flags.append('tor')
        elif ptype in ('VPN',) and 'vpn' not in flags:
            score += 30
            flags.append('vpn')

    # iphub.info
    if isinstance(iphub, dict) and 'error' not in iphub:
        if iphub.get('is_vpn_or_proxy'):
            score += 25
            if 'vpn' not in flags and 'proxy' not in flags:
                flags.append('vpn_or_proxy')
        if iphub.get('is_residential_proxy'):
            score += 20
            if 'residential_proxy' not in flags:
                flags.append('residential_proxy')

    risk_score = min(score, 100)
    return {
        "risk_score": risk_score,
        "is_suspicious": risk_score >= 30,
        "flags": list(set(flags)),
    }


@app.route('/')
def index():
    return jsonify({
        "service": "VPN & Proxy Checker API",
        "endpoints": {
            "/check": "Sprawdź IP pod kątem VPN/Proxy/TOR — /check?ip=1.2.3.4&key=KLUCZ"
        },
        "sources": ["ip-api.com", "proxycheck.io", "iphub.info"]
    })


@app.route('/check')
def check():
    ip = request.args.get('ip', '').strip()

    if not ip:
        return jsonify({"error": "Podaj parametr 'ip'"}), 400

    # prosta walidacja formatu IPv4/IPv6
    parts = ip.split('.')
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        # może IPv6 – przepuść, zewnętrzne API obsłużą błąd
        if ':' not in ip:
            return jsonify({"error": f"Nieprawidłowy adres IP: {ip}"}), 400

    checked_at = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    ipapi_result = check_ipapi(ip)
    proxycheck_result = check_proxycheck(ip)
    iphub_result = check_iphub(ip)

    summary = aggregate_risk(ipapi_result, proxycheck_result, iphub_result)

    return jsonify({
        "ip": ip,
        "checked_at": checked_at,
        "is_vpn": summary["is_suspicious"],
        "is_proxy": 'proxy' in summary["flags"],
        "is_tor": 'tor' in summary["flags"],
        "risk_score": summary["risk_score"],
        "flags": summary["flags"],
        "sources": {
            "ip_api": ipapi_result,
            "proxycheck": proxycheck_result,
            "iphub": iphub_result,
        }
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
