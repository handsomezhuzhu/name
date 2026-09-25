#!/usr/bin/env python3
"""
3-letter .com domain scanner using VeriSign RDAP + WHOIS fallback.
Generates domains.json + data.js for the GitHub Pages site.

Classification (based on original data):
  - RDAP 404  -> available (可注册)
  - RDAP 200  -> parse expiration, compute days_left
      days_left in [0, 90]            -> expiring (即将到期)
      days_left < 0 (recently expired)-> grace / redemption / pending_delete
      else                            -> registered (not shown, unless expiring)
"""
import json, os, sys, time, datetime, socket
import itertools, string, urllib.request, urllib.error
import concurrent.futures as cf

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
DOMAINS_JSON = os.path.join(REPO_DIR, "domains.json")
DATA_JS = os.path.join(REPO_DIR, "data.js")
PROGRESS_JSON = os.path.join(REPO_DIR, "scan_progress.json")

CHARS = string.ascii_lowercase + string.digits   # 26 + 10 = 36
LEN = 3
TOTAL = len(CHARS) ** LEN                          # 46656

CONCURRENCY = int(os.environ.get("SCAN_CONCURRENCY", "16"))
UA = "Mozilla/5.0 (X11; Linux x86_64) domain-scan/1.0 (contact: own)"
RDAP_BASE = "https://rdap.verisign.com/com/v1/domain/"

# EPP lifecycle statuses that indicate non-normal state
REDEMPTION_STATUSES = {"redemption period", "pending delete", "pending redemption"}


def rdap_query(domain):
    """Return (status_code, data_dict) or (None, None) on network error."""
    url = RDAP_BASE + domain
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Accept": "application/rdap+json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, None
        except (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError, OSError) as e:
            if attempt == 2:
                return None, None
            time.sleep(0.4 * (attempt + 1))
    return None, None


def classify(domain):
    """Scan one 3-letter domain. Returns (result_dict_or_None, is_network_error_bool).
    result_dict None + is_network_error=False means: registered, not expiring soon -> skip."""
    code, data = rdap_query(domain + ".com")
    if code is None:
        return None, True  # network error, retry later

    # 404 -> not registered -> available
    if code == 404:
        return {"domain": domain + ".com", "status": "available",
                "expiry": None, "days_left": None}, False

    if code != 200:
        return None, False

    # Registered. Get expiration.
    events = {e.get("eventAction"): e.get("eventDate")
              for e in data.get("events", []) if isinstance(e, dict)}
    exp_raw = events.get("expiration")
    if not exp_raw:
        return None, False

    today = datetime.date.today()
    try:
        exp_dt = datetime.datetime.fromisoformat(exp_raw.replace("Z", "+00:00"))
        exp_date = exp_dt.date()
    except (ValueError, TypeError):
        return None, False

    days_left = (exp_date - today).days
    expiry = exp_date.isoformat()

    # Status hints from RDAP
    statuses = {s.lower() for s in data.get("status", [])}

    # Normal registered domain with >90 days -> not interesting.
    if days_left >= 0:
        if days_left <= 90:
            return {"domain": domain + ".com", "status": "expiring",
                    "expiry": expiry, "days_left": days_left}, False
        return None, False  # registered, not expiring soon -> drop

    # Expired (days_left < 0). Classify by how long ago + status hints.
    if days_left >= -2:
        return {"domain": domain + ".com", "status": "grace",
                "expiry": expiry, "days_left": days_left}, False
    if days_left >= -75 or statuses & REDEMPTION_STATUSES:
        return {"domain": domain + ".com", "status": "redemption",
                "expiry": expiry, "days_left": days_left}, False
    return {"domain": domain + ".com", "status": "pending_delete",
            "expiry": expiry, "days_left": days_left}, False


def load_state():
    if os.path.exists(PROGRESS_JSON):
        try:
            return json.load(open(PROGRESS_JSON))
        except Exception:
            pass
    return {"checked": [], "domains": {}}


def save_state(state):
    tmp = PROGRESS_JSON + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, ensure_ascii=False)
    os.replace(tmp, PROGRESS_JSON)


def build_output(domains_map):
    """domains_map: {domain_with_com: [domain,status,expiry,days_left]}
    Only bumps 'updated' timestamp when the actual domain list changes,
    so git sees no diff on pure re-runs."""
    domains = list(domains_map.values())
    stats = {
        "total_checked": TOTAL,
        "total_target": TOTAL,
        "found": len(domains),
        "counts": {
            "expiring": sum(1 for d in domains if d[1] == "expiring"),
            "grace": sum(1 for d in domains if d[1] == "grace"),
            "redemption": sum(1 for d in domains if d[1] == "redemption"),
            "available": sum(1 for d in domains if d[1] == "available"),
            "pending_delete": sum(1 for d in domains if d[1] == "pending_delete"),
        },
        "checked": {"len3": TOTAL, "len4": 0, "len5": 0},
    }
    # Determine 'updated': reuse previous if domain data unchanged
    prev_updated = None
    if os.path.exists(DOMAINS_JSON):
        try:
            with open(DOMAINS_JSON) as f:
                prev = json.load(f)
            prev_domains = prev.get("domains")
            if prev_domains == domains:
                prev_updated = prev.get("updated")
        except Exception:
            pass
    now = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")
    updated = prev_updated if prev_updated else now
    return {
        "stats": stats,
        "counts": stats["counts"],
        "checked": stats["checked"],
        "updated": updated,
        "domains": domains,
    }


def write_datajs(payload):
    with open(DATA_JS, "w") as f:
        f.write("// Auto-generated %s - %d unique domains\n" % (
            datetime.datetime.now().isoformat(), payload["stats"]["found"]))
        f.write("const STATS = %s;\n" % json.dumps(payload["stats"], ensure_ascii=False))
        f.write("const DOMAINS = %s;\n" % json.dumps(payload["domains"], ensure_ascii=False))


def scan_all():
    state = load_state()
    domains_map = state.get("domains", {})
    print(f"已有记录: {len(domains_map)}", flush=True)

    # Generate all candidates
    all_doms = [''.join(p) for p in itertools.product(CHARS, repeat=LEN)]
    limit = int(os.environ.get("SCAN_LIMIT", "0"))
    if limit > 0:
        all_doms = all_doms[:limit]

    # 每日全量重扫: 不再跳过已检查域名, 保证数据每日新鲜
    # (46656个 RDAP 查询约 12 分钟, 每日 06:00 cron 可接受)
    # REFRESH=0 时保留旧的断点续跑行为(仅扫未检查的)
    refresh = os.environ.get("REFRESH", "1") == "1"
    if refresh:
        pending = all_doms
        print("模式: 每日全量刷新", flush=True)
    else:
        checked_set = set(state.get("checked", []))
        pending = [d for d in all_doms if d not in checked_set]
        print(f"模式: 断点续跑, 待扫描: {len(pending)}", flush=True)

    t0 = time.time()
    done = 0
    retry_queue = []

    def worker(d):
        return d, classify(d)

    # 全量刷新模式下 checked_set 就是本次扫描全集; 断点模式用历史记录
    checked_set = set(pending) if refresh else set(state.get("checked", []))

    with cf.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futures = {ex.submit(worker, d): d for d in pending}
        for fut in cf.as_completed(futures):
            d, (res, is_net_err) = fut.result()
            done += 1
            checked_set.add(d)
            if res is not None:
                domains_map[res["domain"]] = [res["domain"], res["status"],
                                              res["expiry"], res["days_left"]]
            elif is_net_err:
                # real network error -> mark for retry
                retry_queue.append(d)

            if done % 500 == 0:
                dt = time.time() - t0
                rate = done / dt if dt > 0 else 0
                eta = (len(pending) - done) / rate / 60 if rate > 0 else 0
                print(f"  进度 {done}/{len(pending)} ({done/len(pending)*100:.1f}%) "
                      f"rate={rate:.0f}/s ETA={eta:.1f}min found={len(domains_map)}", flush=True)
                save_state({"checked": list(checked_set), "domains": domains_map})

    # Retry failed ones once more
    if retry_queue:
        print(f"重试 {len(retry_queue)} 个网络错误...", flush=True)
        time.sleep(2)
        with cf.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
            futures = {ex.submit(worker, d): d for d in retry_queue}
            for fut in cf.as_completed(futures):
                d, (res, _is_net_err) = fut.result()
                if res is not None:
                    domains_map[res["domain"]] = [res["domain"], res["status"],
                                                  res["expiry"], res["days_left"]]
        save_state({"checked": list(checked_set), "domains": domains_map})

    return domains_map, checked_set


def main():
    print("=" * 50)
    print("3-letter .com scanner")
    print(f"Total candidates: {TOTAL}")
    print("=" * 50)

    domains_map, checked_set = scan_all()

    print(f"\n扫描完成: {len(checked_set)}/{TOTAL}")
    print(f"发现: {len(domains_map)} 个")

    payload = build_output(domains_map)
    print("\n状态分布:", json.dumps(payload["stats"]["counts"], ensure_ascii=False))

    # Save domains.json
    with open(DOMAINS_JSON, "w") as f:
        json.dump(payload, f, ensure_ascii=False)
    print(f"已写入 {DOMAINS_JSON}")

    # Save data.js
    write_datajs(payload)
    print(f"已写入 {DATA_JS}")

    # Write progress summary
    save_state({"checked": list(checked_set), "domains": domains_map})

    # Print summary for cron delivery
    c = payload["stats"]["counts"]
    print("\n【三字母 .com 域名扫描完成】")
    print(f"✅ 可注册: {c['available']}")
    print(f"⏰ 即将到期: {c['expiring']}")
    print(f"⏳ 宽限期: {c['grace']}")
    print(f"💰 赎回期: {c['redemption']}")
    print(f"🗑️ 待删除: {c['pending_delete']}")
    print(f"📊 总计: {len(domains_map)}")
    print(f"更新: {payload['updated']}")


if __name__ == "__main__":
    main()
