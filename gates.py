# -*- coding: utf-8 -*-

from __future__ import annotations
import hashlib, json, os, re, redis, time
import numpy as np
import unicodedata as ud
from datasketch import MinHash
from simhash import Simhash
from typing import Optional

from dotenv import load_dotenv
load_dotenv(os.getenv("ENV_FILE", ".env"))

LABEL = os.environ.get("LABEL", "prompt_gates")
PATH_TTL = int(os.getenv("PATH_TTL", "1800"))
EVENT_TTL = int(os.getenv("EVENT_TTL", "3600"))
MAX_EVENTS = int(os.getenv("MAX_EVENTS", "200"))
MAX_PATH_STEPS = int(os.getenv("MAX_PATH_STEPS", "20"))
RULES_FILE = os.getenv("RULES_FILE", "./rules.json")
NUM_PERM = int(os.getenv("NUM_PERM", "128"))
REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

_RULES: dict | None = None
_RULES_MTIME: float | None = None

RE_ZERO_WIDTH = re.compile(r"[\u200B\u200C\u200D\u2060\uFEFF]")

def _serialize_mh(mh: MinHash | None):
    if mh is None:
        return None
    return {
        "num_perm": int(mh.num_perm),
        "hashvalues": [int(x) for x in mh.hashvalues.astype(np.uint64)]
    }

def _deserialize_mh(obj):
    if not obj:
        return None
    hv = np.array(obj["hashvalues"], dtype=np.uint64)
    mh = MinHash(num_perm=int(obj["num_perm"]))
    mh.hashvalues = hv
    return mh

def _stable_hash(token: BytesLike) -> int:
    digest = hashlib.blake2b(token, digest_size=8).digest()
    return int.from_bytes(digest, "big")

def _load_rules_file(path: str) -> tuple[dict, float | None]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"rules file not found: {path}")
    with open(path, "rb") as f:
        rules = json.load(f)
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    return rules, mtime

_RULES, _RULES_MTIME = _load_rules_file(RULES_FILE)

def build_simhash(shingles) -> int:
    return Simhash(shingles, f=64, hashfunc=_stable_hash).value

def get_rules() -> dict:
    global _RULES, _RULES_MTIME
    try:
        mtime = os.path.getmtime(RULES_FILE)
    except OSError:
        mtime = None
    if mtime != _RULES_MTIME:
        _RULES, _RULES_MTIME = _load_rules_file(RULES_FILE)
    return _RULES

def normalize_text(s: str) -> str:
    s = ud.normalize("NFC", s)
    s = RE_ZERO_WIDTH.sub("", s)
    s = s.lower()
    s = re.sub(r"\s+", " ", s).strip()
    return s

def word_ngrams(s: str, n: int = 5):
    words = s.split()
    for i in range(len(words) - n + 1):
        yield " ".join(words[i:i+n])

def build_minhash(shingles) -> MinHash:
    mh = MinHash(num_perm=NUM_PERM, hashfunc=_stable_hash)
    for sh in shingles:
        mh.update(sh.encode("utf-8"))
    return mh

def _emoji_count(s: str) -> int:
    return sum(1 for ch in s if ("\U0001F000" <= ch <= "\U0001FAFF") or ("\u2600" <= ch <= "\u27BF"))

def fingerprint_prompt(s: str) -> dict:
    norm = normalize_text(s)
    sh = list(word_ngrams(norm, n=5))
    sim64 = int(build_simhash(sh))
    mh = build_minhash(sh)

    return {
        "norm": norm,
        "len": len(norm),
        "emoji_count": _emoji_count(norm),
        "simhash64": sim64,
        "minhash": _serialize_mh(mh)
    }

def _hamming(a: int | None, b: int | None) -> Optional[int]:
    if a is None or b is None: return None
    return (int(a) ^ int(b)).bit_count()

def _jaccard_from_mh(a, b) -> Optional[float]:
    if not a or not b:
        return None
    if isinstance(a, dict): a = _deserialize_mh(a)
    if isinstance(b, dict): b = _deserialize_mh(b)
    if a is None or b is None or a.num_perm != b.num_perm:
        return None
    return float((a.hashvalues == b.hashvalues).mean())

def _subkey(sub: str, kind: str) -> str:
    return f"{LABEL}:{kind}:{sub}"

def _digest(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()[:16]

def _now() -> float:
    return time.time()

def record_event(sub: str, action: str, prompt: str, fp: dict, decision: str, gate: str, now: float | None = None):
    now = now or _now()
    key = _subkey(sub, "events")
    evt = {
        "t": now,
        "action": action,
        "decision": decision,
        "gate": gate,
        "len": fp.get("len"),
        "emoji": fp.get("emoji_count"),
        "simhash64": fp.get("simhash64"),
        "minhash_digest": _digest("".join(map(str, fp["minhash"]["hashvalues"])) if (fp.get("minhash") and fp["minhash"].get("hashvalues")) else ""),
        "txt_hash": _digest(fp.get("norm","")),
    }
    pipe = r.pipeline()
    pipe.rpush(key, json.dumps(evt, separators=(",",":")))
    pipe.ltrim(key, -MAX_EVENTS, -1)
    pipe.expire(key, EVENT_TTL)
    pipe.execute()

def record_action_path(sub: str, action: str, now: float | None = None):
    now = now or _now()
    key = _subkey(sub, "path")
    rec = {"t": now, "action": action}
    pipe = r.pipeline()
    pipe.rpush(key, json.dumps(rec, separators=(",",":")))
    pipe.ltrim(key, -MAX_PATH_STEPS, -1)
    pipe.expire(key, PATH_TTL)
    pipe.execute()

def last_fingerprint(sub: str) -> dict | None:
    raw = r.get(_subkey(sub, "lastfp"))
    if not raw:
        return None
    obj = json.loads(raw)
    sh = obj.get("simhash64")
    obj["simhash64"] = int(sh) if sh is not None else None
    return obj

def save_fingerprint(sub: str, fp: dict):
    payload = {
        "norm": fp.get("norm") or "",
        "len": int(fp.get("len") or 0),
        "emoji_count": int(fp.get("emoji_count") or 0),
        "simhash64": int(fp.get("simhash64") or 0),
        "minhash": fp.get("minhash"),
    }
    r.setex(_subkey(sub, "lastfp"), PATH_TTL, json.dumps(payload, separators=(",",":")))

def route_by_similarity(prev: dict | None, fp: dict) -> dict:
    sim = get_rules().get("similarity", {})
    SIMHASH_BLOCK = int(sim.get("simhash_block", 4))
    SIMHASH_REVIEW = int(sim.get("simhash_review", 8))
    MIN_LEN_GATE = int(sim.get("min_len_gate", 40))
    EMOJI_DENSITY_REVIEW = float(sim.get("emoji_density_review", 0.15))
    J_NEAR = float(sim.get("minhash_near", 0.80))
    J_KIND = max(0.0, min(1.0, J_NEAR - 0.10))

    plen = int(fp.get("len") or 0)
    edensity = (fp.get("emoji_count") or 0) / max(1, plen)
    hdist = None
    jacc = None

    if prev:
        sh_cur = fp.get("simhash64")
        sh_prev = prev.get("simhash64")
        mh_cur = fp.get("minhash")
        mh_prev = prev.get("minhash")

        if sh_cur is not None and sh_prev is not None:
            hdist = _hamming(sh_cur, sh_prev)
        if mh_cur is not None and mh_prev is not None:
            jacc = _jaccard_from_mh(mh_cur, mh_prev)

    sim_near_dup = ((hdist is not None and hdist <= SIMHASH_BLOCK) or
                     (jacc is not None and jacc >= J_NEAR))
    sim_kinda_dup = ((hdist is not None and hdist <= SIMHASH_REVIEW) or
                     (jacc is not None and jacc >= J_KIND))

    if sim_near_dup:
        sim_kinda_dup = False

    glyph_tiny = (plen < MIN_LEN_GATE) and (edensity > EMOJI_DENSITY_REVIEW)

    return {
        "glyph_tiny": glyph_tiny,
        "sim_near_dup": sim_near_dup,
        "sim_kinda_dup": sim_kinda_dup,
        "hamming": hdist,
        "jaccard": jacc,
        "len": plen,
        "emoji_density": edensity,
    }

def route_by_path_timing(sub: str, new_action: str, now: float | None = None):
    now = now or _now()
    key = _subkey(sub, "path")
    items = r.lrange(key, -2, -1)
    if len(items) < 2:
        return {"path_timing_bad": False, "delta": None, "rule": None}
    try:
        a_prev = json.loads(items[-2]); a_curr = json.loads(items[-1])
    except Exception:
        return {"path_timing_bad": False, "delta": None, "rule": None}
    if a_curr.get("action") != new_action:
        return {"path_timing_bad": False, "delta": None, "rule": None}

    prev_name = a_prev.get("action"); curr_name = a_curr.get("action")
    if not prev_name or not curr_name:
        return {"path_timing_bad": False, "delta": None, "rule": None}

    delta = float(a_curr.get("t", now) - a_prev.get("t", now))
    rule_key = f"{prev_name}->{curr_name}"
    win = get_rules()["path_timing"].get(rule_key)
    if not win:
        return {"path_timing_bad": False, "delta": delta, "rule": None}

    lo, hi = float(win["min_s"]), float(win["max_s"])
    ok = (lo <= delta <= hi)
    return {"path_timing_bad": (not ok), "delta": delta, "rule": rule_key, "lo": lo, "hi": hi}

def check_rate_limits(sub: str, action: str) -> dict:
    cfg = get_rules().get("rate_limits", {})
    per_gap = cfg.get("per_action_min_gap_s", {})
    min_gap = int(per_gap.get(action, 0))
    now = int(_now())
    k_last = f"{LABEL}:last:{sub}:{action}"
    last = r.get(k_last)
    per_action_gap_bad = False
    if last is not None:
        try:
            last = int(last)
            per_action_gap_bad = (now - last) < min_gap if min_gap > 0 else False
        except Exception:
            per_action_gap_bad = False
    r.setex(k_last, max(min_gap, 300), str(now))

    burst_cfg = cfg.get("burst", {"window_s": 60, "max_actions": 20})
    bwin = int(burst_cfg.get("window_s", 60))
    bmax = int(burst_cfg.get("max_actions", 20))
    k_burst = f"{LABEL}:burst:{sub}"
    bcnt = r.incr(k_burst)
    if bcnt == 1: r.expire(k_burst, bwin)
    burst_bad = bcnt > bmax

    return {
        "per_action_gap_bad": per_action_gap_bad,
        "burst_bad": burst_bad,
        "burst_count": int(bcnt),
    }

def _ip_from_sub(sub: str) -> str:
    parts = sub.split(":")
    return parts[-1] if parts else "0.0.0.0"

def _token_for_sub(sub: str) -> Optional[str]:
    return r.get(f"{LABEL}:tokens:{sub}")

def check_ip_heuristics(sub: str) -> dict:
    rules = get_rules().get("ip_heuristics", {})
    if not rules:
        return {"ip_churn_high": False, "ip_fanout_high": False}

    ip = _ip_from_sub(sub)

    churn_cfg = rules.get("ip_churn_per_token", {"window_s": 3600, "max_ips": 3})
    ch_win = int(churn_cfg.get("window_s", 3600))
    ch_max = int(churn_cfg.get("max_ips", 3))
    tok = _token_for_sub(sub)
    churn_high = False
    if tok:
        tid = hashlib.sha1(tok.encode("utf-8")).hexdigest()[:16]
        k_tok_ips = f"{LABEL}:tokips:{tid}"
        r.sadd(k_tok_ips, ip); r.expire(k_tok_ips, ch_win)
        churn_high = r.scard(k_tok_ips) >= ch_max

    fan_cfg = rules.get("ip_fanout", {"window_s": 3600, "max_subs_per_ip": 10})
    fn_win = int(fan_cfg.get("window_s", 3600))
    fn_max = int(fan_cfg.get("max_subs_per_ip", 10))
    k_ip_subs = f"{LABEL}:ipfans:{ip}"
    r.sadd(k_ip_subs, sub); r.expire(k_ip_subs, fn_win)
    fanout_high = r.scard(k_ip_subs) >= fn_max

    ctry_high = False
    ccfg = rules.get("country_churn", {"window_s": 86400, "max_countries": 2})
    cc_win = int(ccfg.get("window_s", 86400))
    cc_max = int(ccfg.get("max_countries", 2))
    country = r.get(f"geo:{ip}")
    if tok and country:
        tid = hashlib.sha1(tok.encode("utf-8")).hexdigest()[:16]
        k_tok_ctry = f"{LABEL}:tokctry:{tid}"
        r.sadd(k_tok_ctry, country); r.expire(k_tok_ctry, cc_win)
        ctry_high = r.scard(k_tok_ctry) >= cc_max

    return {
        "ip_churn_high": churn_high or ctry_high,
        "ip_fanout_high": fanout_high,
    }

def check_coordination(sub: str, fp: dict) -> dict:
    rules = get_rules().get("coordination", {})
    if not rules:
        return {"coordination_detected": False}

    txt_hash = _digest(fp.get("norm",""))
    shared_cfg = rules.get("shared_txt_hash", {"window_s": 1800, "min_unique_subs": 3, "min_geodiversity": 2})
    sw = int(shared_cfg.get("window_s", 1800))
    smin = int(shared_cfg.get("min_unique_subs", 3))
    sgeo = int(shared_cfg.get("min_geodiversity", 2))
    k_cross = f"{LABEL}:txtsubs:{txt_hash}"
    r.sadd(k_cross, sub); r.expire(k_cross, sw)
    uniq_subs = r.scard(k_cross)
    geodiv = 0

    if uniq_subs > 0 and sgeo > 1:
        subs_list = list(r.smembers(k_cross))[:50]
        countries = set()
        for s in subs_list:
            ip = _ip_from_sub(s)
            c = r.get(f"geo:{ip}")
            if c: countries.add(c)
            if len(countries) >= sgeo: break
        geodiv = len(countries)

    shared_flag = (uniq_subs >= smin) and (geodiv >= min(1, sgeo))
    cl_cfg = rules.get("similarity_cluster", {"window_s": 1800, "min_cluster_size": 4, "max_avg_hamming": 8})
    cw = int(cl_cfg.get("window_s", 1800))
    csize = int(cl_cfg.get("min_cluster_size", 4))
    cmaxh = int(cl_cfg.get("max_avg_hamming", 8))
    simhash_val = fp.get("simhash64") or 0
    cluster_flag = False

    zkey = f"{LABEL}:simhashes:z"
    now = int(_now())
    r.zadd(zkey, {str(simhash_val): now})
    r.zremrangebyscore(zkey, 0, now - cw)
    recent = [int(x) for x in r.zrangebyscore(zkey, now - cw, now)]

    if recent:
        dists = [ (simhash_val ^ v).bit_count() for v in recent if v != simhash_val ]
        near = [d for d in dists if d <= cmaxh]
        cluster_flag = len(near) + 1 >= csize

    return {
        "coordination_detected": shared_flag or cluster_flag,
        "coord_shared_subs": int(uniq_subs),
        "coord_geodiversity": int(geodiv),
    }

def choose_gate(flags: dict) -> str:
    if flags.get("sim_near_dup"):
        return "Echo"
    if flags.get("sim_kinda_dup"):
        return "Mirror"
    if flags.get("glyph_tiny"):
        return "Glyph"
    if flags.get("burst_bad") or flags.get("path_timing_bad"):
        return "Too-Fast"
    if flags.get("per_action_gap_bad"):
        return "Rift"
    if flags.get("ip_fanout_high"):
        return "Hive"
    if flags.get("ip_churn_high") or flags.get("coordination_detected"):
        return "Antechamber"
    return "OK" if flags else "Labyrinth"

def route_and_record(action: str, s: str, sub: str):
    now = _now()
    record_action_path(sub, action, now)
    path_t = route_by_path_timing(sub, action, now)
    rate = check_rate_limits(sub, action)
    flags = {
        "path_timing_bad": path_t.get("path_timing_bad", False),
        "per_action_gap_bad": rate.get("per_action_gap_bad", False),
        "burst_bad": rate.get("burst_bad", False),
    }

    fp = {"norm":"", "len":0, "emoji_count":0, "simhash64":0, "minhash":None}
    sim = {"glyph_tiny": False, "sim_near_dup": False, "sim_kinda_dup": False,
           "hamming": None, "jaccard": None, "len":0, "emoji_density":0.0}
    coord = {"coordination_detected": False}
    iphz = check_ip_heuristics(sub)

    if action == "prompt":
        fp = fingerprint_prompt(s or "")
        prev = last_fingerprint(sub)
        sim = route_by_similarity(prev, fp)
        coord = check_coordination(sub, fp)
        save_fingerprint(sub, fp)

    flags.update({
        "glyph_tiny": sim.get("glyph_tiny", False),
        "sim_near_dup": sim.get("sim_near_dup", False),
        "sim_kinda_dup": sim.get("sim_kinda_dup", False),
        "ip_churn_high": iphz.get("ip_churn_high", False),
        "ip_fanout_high": iphz.get("ip_fanout_high", False),
        "coordination_detected": coord.get("coordination_detected", False),
    })

    message = None
    status = 200
    if flags["sim_near_dup"]:
        gate = "Echo"
        decision = "block"
    elif flags["sim_kinda_dup"]:
        gate = "Mirror"
        decision = "review"
    else:
        gate = choose_gate(flags)
        decision = "allow"

    reasons = []
    if flags["path_timing_bad"] and path_t.get("rule"):
        reasons.append(f"path {path_t['rule']} in {int(path_t['delta'] or 0)}s")
    for name in ("per_action_gap_bad","burst_bad","glyph_tiny","sim_near_dup","sim_kinda_dup",
                 "ip_churn_high","ip_fanout_high","coordination_detected"):
        if flags.get(name):
            reasons.append(name)
    reason = "; ".join(reasons) or "ok" 
    record_event(sub, action, s, fp, decision, gate, now)

    return {
        "status": status,
        "gate": gate,
        "reason": reason,
        "decision": decision,
        "metrics": {
            "timing": path_t,
            "rate": rate,
            "similarity": {
                k: sim.get(k) for k in ("hamming","jaccard","len","emoji_density",
                                        "sim_near_dup","sim_kinda_dup")
            },
            "ip": iphz,
            "coordination": {
                k: coord.get(k) for k in ("coordination_detected","coord_shared_subs","coord_geodiversity")
            }
        },
        "flags": flags
    }
