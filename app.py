from flask import Flask, request, jsonify
import requests
import dns.resolver
import dns.exception
import os
import datetime
import threading

app = Flask(__name__)
API_KEY = os.environ.get('API_KEY', '')

# Darmowe źródła do sprawdzania VPN/Proxy/TOR
# ip-api.com:      45 req/min bez klucza
# proxycheck.io:   100 req/dzień bez klucza
# iphub.info:      1000 req/dzień bez klucza (opcjonalny klucz IPHUB_KEY)
# ipinfo.io:       50k req/miesiąc bez klucza
# db-ip.com:       darmowy, bez klucza, typ sieci
# TOR exit nodes:  oficjalna lista torproject.org, bez limitu
# DNSBL:           zen.spamhaus.org, cbl.abuseat.org

IPAPI_URL      = "http://ip-api.com/json/{ip}?fields=status,message,proxy,vpn,tor,hosting,isp,org,as,countryCode,country,city"
PROXYCHECK_URL = "http://proxycheck.io/v2/{ip}?vpn=1&asn=1"
IPHUB_URL      = "http://v2.api.iphub.info/ip/{ip}"
IPINFO_URL     = "https://ipinfo.io/{ip}/json"
DBIP_URL       = "https://api.db-ip.com/v2/free/{ip}"
TOR_EXIT_URL   = "https://check.torproject.org/torbulkexitlist"
IPHUB_KEY      = os.environ.get('IPHUB_KEY', '')

# Cache listy TOR – odświeżany co godzinę
_tor_cache = {"nodes": set(), "updated_at": None}
_tor_lock = threading.Lock()


def get_tor_exit_nodes():
    with _tor_lock:
        now = datetime.datetime.utcnow()
        if _tor_cache["updated_at"] is None or (now - _tor_cache["updated_at"]).seconds > 3600:
            try:
                r = requests.get(TOR_EXIT_URL, timeout=10)
                nodes = set(line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#'))
                _tor_cache["nodes"] = nodes
                _tor_cache["updated_at"] = now
            except Exception:
                pass
        return _tor_cache["nodes"]


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
        if data.get('status') == 'error':
            return {"error": data.get('message', 'unknown error')}
        ip_data = data.get(ip, {})
        return {
            "is_proxy": ip_data.get('proxy', 'no') == 'yes',
            "type": ip_data.get('type', ''),
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
        # block: 0=ok, 1=vpn/proxy, 2=residential proxy
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


def check_ipinfo(ip):
    try:
        r = requests.get(IPINFO_URL.format(ip=ip), timeout=5)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        data = r.json()
        privacy = data.get('privacy', {})
        return {
            "org": data.get('org', ''),
            "hostname": data.get('hostname', ''),
            "city": data.get('city', ''),
            "country": data.get('country', ''),
            "is_vpn": privacy.get('vpn', False),
            "is_proxy": privacy.get('proxy', False),
            "is_tor": privacy.get('tor', False),
            "is_hosting": privacy.get('hosting', False),
        }
    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def check_dbip(ip):
    try:
        r = requests.get(DBIP_URL.format(ip=ip), timeout=5)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        data = r.json()
        conn_type = data.get('connectionType', '')
        # connectionType: consumer, business, hosting, education
        return {
            "connection_type": conn_type,
            "is_hosting": conn_type == 'hosting',
            "isp": data.get('isp', ''),
            "country_code": data.get('countryCode', ''),
            "city": data.get('city', ''),
        }
    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def check_tor_exit(ip):
    try:
        nodes = get_tor_exit_nodes()
        is_tor = ip in nodes
        return {
            "is_tor": is_tor,
            "nodes_in_cache": len(nodes),
            "cache_updated_at": _tor_cache["updated_at"].strftime('%Y-%m-%dT%H:%M:%SZ') if _tor_cache["updated_at"] else None,
        }
    except Exception as e:
        return {"error": str(e)}


def check_dnsbl(ip):
    lists = ['zen.spamhaus.org', 'cbl.abuseat.org']
    parts = ip.strip().split('.')
    if len(parts) != 4:
        return {"error": "IPv6 not supported for DNSBL"}
    reversed_ip = '.'.join(reversed(parts))
    results = {}
    listed_count = 0
    for bl in lists:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = resolver.resolve(f"{reversed_ip}.{bl}", 'A')
            try:
                txt = resolver.resolve(f"{reversed_ip}.{bl}", 'TXT')
                reason = str(txt[0]).strip('"')
            except Exception:
                reason = ""
            results[bl] = {"listed": True, "addresses": [str(r) for r in answers], "reason": reason}
            listed_count += 1
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            results[bl] = {"listed": False}
        except dns.exception.Timeout:
            results[bl] = {"listed": None, "error": "timeout"}
        except Exception as e:
            results[bl] = {"listed": None, "error": str(e)}
    return {"listed_count": listed_count, "checked": results}


def aggregate_risk(ipapi, proxycheck, iphub, ipinfo, dbip, tor_exit, dnsbl):
    score = 0
    flags = []

    def add_flag(flag):
        if flag not in flags:
            flags.append(flag)

    # ip-api.com
    if isinstance(ipapi, dict) and 'error' not in ipapi:
        if ipapi.get('is_vpn'):     score += 40; add_flag('vpn')
        if ipapi.get('is_proxy'):   score += 35; add_flag('proxy')
        if ipapi.get('is_tor'):     score += 50; add_flag('tor')
        if ipapi.get('is_hosting'): score += 15; add_flag('hosting')

    # proxycheck.io
    if isinstance(proxycheck, dict) and 'error' not in proxycheck:
        if proxycheck.get('is_proxy'): score += 30; add_flag('proxy')
        ptype = proxycheck.get('type', '').upper()
        if ptype == 'TOR':   score += 40; add_flag('tor')
        elif ptype == 'VPN': score += 30; add_flag('vpn')

    # iphub.info
    if isinstance(iphub, dict) and 'error' not in iphub:
        if iphub.get('is_vpn_or_proxy'):      score += 25; add_flag('vpn_or_proxy')
        if iphub.get('is_residential_proxy'): score += 20; add_flag('residential_proxy')

    # ipinfo.io
    if isinstance(ipinfo, dict) and 'error' not in ipinfo:
        if ipinfo.get('is_vpn'):     score += 30; add_flag('vpn')
        if ipinfo.get('is_proxy'):   score += 25; add_flag('proxy')
        if ipinfo.get('is_tor'):     score += 45; add_flag('tor')
        if ipinfo.get('is_hosting'): score += 10; add_flag('hosting')

    # db-ip.com
    if isinstance(dbip, dict) and 'error' not in dbip:
        if dbip.get('is_hosting'): score += 10; add_flag('hosting')

    # TOR exit nodes (oficjalna lista torproject.org)
    if isinstance(tor_exit, dict) and 'error' not in tor_exit:
        if tor_exit.get('is_tor'): score += 60; add_flag('tor')

    # DNSBL
    if isinstance(dnsbl, dict) and 'error' not in dnsbl:
        if dnsbl.get('listed_count', 0) > 0: score += 20; add_flag('blacklisted')

    return {
        "risk_score": min(score, 100),
        "is_suspicious": min(score, 100) >= 30,
        "flags": flags,
    }


@app.route('/')
def index():
    return jsonify({
        "service": "VPN & Proxy Checker API",
        "endpoints": {
            "/check": "Sprawdź IP pod kątem VPN/Proxy/TOR — /check?ip=1.2.3.4&key=KLUCZ"
        },
        "sources": [
            "ip-api.com",
            "proxycheck.io",
            "iphub.info",
            "ipinfo.io",
            "db-ip.com",
            "torproject.org (exit nodes)",
            "DNSBL: zen.spamhaus.org, cbl.abuseat.org"
        ]
    })


@app.route('/check')
def check():
    ip = request.args.get('ip', '').strip()

    if not ip:
        return jsonify({"error": "Podaj parametr 'ip'"}), 400

    parts = ip.split('.')
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        if ':' not in ip:
            return jsonify({"error": f"Nieprawidłowy adres IP: {ip}"}), 400

    checked_at = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    # Równoległe zapytania do wszystkich źródeł
    results = {}

    def run(key, fn, *args):
        results[key] = fn(*args)

    threads = [
        threading.Thread(target=run, args=('ipapi',      check_ipapi,      ip)),
        threading.Thread(target=run, args=('proxycheck', check_proxycheck, ip)),
        threading.Thread(target=run, args=('iphub',      check_iphub,      ip)),
        threading.Thread(target=run, args=('ipinfo',     check_ipinfo,     ip)),
        threading.Thread(target=run, args=('dbip',       check_dbip,       ip)),
        threading.Thread(target=run, args=('tor_exit',   check_tor_exit,   ip)),
        threading.Thread(target=run, args=('dnsbl',      check_dnsbl,      ip)),
    ]
    for t in threads: t.start()
    for t in threads: t.join(timeout=10)

    summary = aggregate_risk(
        results.get('ipapi', {}),
        results.get('proxycheck', {}),
        results.get('iphub', {}),
        results.get('ipinfo', {}),
        results.get('dbip', {}),
        results.get('tor_exit', {}),
        results.get('dnsbl', {}),
    )

    return jsonify({
        "ip": ip,
        "checked_at": checked_at,
        "is_vpn": 'vpn' in summary["flags"] or 'vpn_or_proxy' in summary["flags"],
        "is_proxy": 'proxy' in summary["flags"] or 'vpn_or_proxy' in summary["flags"],
        "is_tor": 'tor' in summary["flags"],
        "is_hosting": 'hosting' in summary["flags"],
        "is_blacklisted": 'blacklisted' in summary["flags"],
        "risk_score": summary["risk_score"],
        "flags": summary["flags"],
        "sources": {
            "ip_api":     results.get('ipapi', {}),
            "proxycheck": results.get('proxycheck', {}),
            "iphub":      results.get('iphub', {}),
            "ipinfo":     results.get('ipinfo', {}),
            "dbip":       results.get('dbip', {}),
            "tor_exit":   results.get('tor_exit', {}),
            "dnsbl":      results.get('dnsbl', {}),
        }
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
