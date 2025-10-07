import os, time, subprocess, signal, socket, json, hashlib
from pathlib import Path

import pytest
import random
import requests
import redis

PORT = 8081
BASE = f"http://127.0.0.1:{PORT}"
REDIS_URL = "redis://127.0.0.1:6379/15"
ROOT = Path(__file__).resolve().parent.parent
RULES = Path(__file__).resolve().parent / "test_rules.json"
INDEX = ROOT / "index.html"
STATIC = ROOT / "static"
LABEL = "prompt_gates"
NUM_PERM = 128

@pytest.fixture(autouse=True)
def _isolate_redis_each_test():
    r = redis.Redis.from_url(
        os.environ.get("REDIS_URL", REDIS_URL),
        decode_responses=True
    )
    r.flushdb()

def wait(host, port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"server did not open {host}:{port}")

def ua_fingerprint(ua: str) -> str:
    return hashlib.sha256(ua.encode("utf-8")).hexdigest()[:16]

def sub_for(ua: str, ip="127.0.0.1") -> str:
    return f"{ua_fingerprint(ua)}:{ip}"

def get_csrf(session: requests.Session, ua: str):
    resp = session.get(BASE + "/", headers={"User-Agent": ua})
    resp.raise_for_status()
    idx = resp.text.find('name="csrf"')
    assert idx != -1, "csrf field not found"
    vpos = resp.text.find('value="', idx)
    epos = resp.text.find('"', vpos + 7)
    return resp.text[vpos + 7: epos]

def extract_user_token(html: str) -> str | None:
    needle = 'name="user_token"'
    i = html.find(needle)
    if i == -1:
        return None
    vpos = html.find('value="', i)
    if vpos == -1:
        return None
    epos = html.find('"', vpos + 7)
    return html[vpos + 7: epos]

def last_gate_for(r: redis.Redis, sub: str) -> str | None:
    key = f"{LABEL}:events:{sub}"
    raw = r.lrange(key, -1, -1)
    if not raw:
        return None
    evt = json.loads(raw[0])
    return evt.get("gate")

@pytest.fixture(scope="session")
def rconn():
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    r.flushdb()
    yield r
    r.flushdb()

@pytest.fixture(scope="session", autouse=True)
def server(rconn):
    env = os.environ.copy()
    env.update({
        "BIND_URL": f"http://127.0.0.1:{PORT}",
        "REDIS_URL": REDIS_URL,
        "RULES_FILE": str(RULES),
        "INDEX_HTML": str(INDEX),
        "STATIC_DIR": str(STATIC),
        "SECRET": "testsecret",
        "TOKEN_TTL": "300",
        "CSRF_TTL": "120",
        "LABEL": "prompt_gates"
    })

    proc = subprocess.Popen(["python3", "server.py"], cwd=str(ROOT), env=env)
    try:
        wait("127.0.0.1", PORT, timeout=8.0)
        yield proc
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

def register(session: requests.Session, ua: str) -> str:
    csrf = get_csrf(session, ua)
    resp = session.post(BASE + "/register",
                        data={"csrf": csrf},
                        headers={"User-Agent": ua})
    resp.raise_for_status()
    tok = extract_user_token(resp.text)
    assert tok, "user_token not found after /register"
    return tok

def payment(session: requests.Session, ua: str, tok: str):
    csrf = get_csrf(session, ua)
    resp = session.post(BASE + "/payment",
                        data={"csrf": csrf, "user_token": tok},
                        headers={"User-Agent": ua})
    resp.raise_for_status()
    return resp

def cancel_payment(session: requests.Session, ua: str, tok: str):
    csrf = get_csrf(session, ua)
    resp = session.post(BASE + "/cancel_payment",
                        data={"csrf": csrf, "user_token": tok},
                        headers={"User-Agent": ua})
    resp.raise_for_status()
    return resp

def submit_prompt(session: requests.Session, ua: str, tok: str, prompt: str):
    csrf = get_csrf(session, ua)
    resp = session.post(BASE + "/submit",
                        data={"csrf": csrf, "user_token": tok, "prompt": prompt},
                        headers={"User-Agent": ua})
    resp.raise_for_status()
    return resp

def test_ok_flow_register_payment_prompt(rconn):
    ua = "UA/ok-flow"
    sess = requests.Session()
    tok = register(sess, ua)
    time.sleep(1.2)
    payment(sess, ua, tok)
    gate = last_gate_for(rconn, sub_for(ua))
    assert gate == "OK"

def test_too_fast_register_to_payment(rconn):
    ua = "UA/too-fast"
    sess = requests.Session()
    tok = register(sess, ua)
    payment(sess, ua, tok)
    gate = last_gate_for(rconn, sub_for(ua))
    assert gate == "Too-Fast"

def test_near_duplicate_prompts_echo_or_mirror(rconn):
    ua = "UA/dup"
    sess = requests.Session()
    tok = register(sess, ua)
    time.sleep(1.0)
    payment(sess, ua, tok)
    time.sleep(1.0)
    p1 = "🦊 and graph theory."
    p2 = "🦊s & graph theory."
    submit_prompt(sess, ua, tok, p1)
    time.sleep(1.0)
    submit_prompt(sess, ua, tok, p2)
    gate = last_gate_for(rconn, sub_for(ua))

    assert gate in {"Mirror", "Echo"}

def test_ip_fanout_hive_gate(rconn):
    uas = ["UA/fanout/1", "UA/fanout/2", "UA/fanout/3"]
    sessions = [requests.Session() for _ in uas]
    tokens = []
    for sess, ua in zip(sessions, uas):
        tok = register(sess, ua); tokens.append(tok)
        time.sleep(1); payment(sess, ua, tok)
    submit_prompt(sessions[0], uas[0], tokens[0], "fanout test 🌋")
    time.sleep(1.0)
    submit_prompt(sessions[1], uas[1], tokens[1], "fanout test ⛰️")
    time.sleep(1.0)
    submit_prompt(sessions[2], uas[2], tokens[2], "fanout test 💎")
    gate = last_gate_for(rconn, sub_for(uas[2]))
    assert gate == "Hive"

def test_fast_cancel_is_too_fast(rconn):
    ua = "UA/refund"
    sess = requests.Session()
    tok = register(sess, ua)
    time.sleep(1.0); payment(sess, ua, tok)
    cancel_payment(sess, ua, tok)
    gate = last_gate_for(rconn, sub_for(ua))
    assert gate == "Too-Fast"

def test_cancel_then_repay_too_fast(rconn):
    ua = "UA/repay"
    sess = requests.Session()
    tok = register(sess, ua)
    time.sleep(1.0); payment(sess, ua, tok)
    time.sleep(1.0); cancel_payment(sess, ua, tok)
    payment(sess, ua, tok)
    gate = last_gate_for(rconn, sub_for(ua))
    assert gate == "Too-Fast"
