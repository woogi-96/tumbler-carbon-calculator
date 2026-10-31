"""닉네임 계정과 사용 횟수 저장, 연구자용 CSV (Vercel Python, 표준 라이브러리만 사용).

서버가 받는 것은 닉네임, PIN, 사용 기록의 식별자와 날짜뿐이다. 사진을 받는 입력은 없다.
PIN은 해시로만 저장하고 토큰도 해시로만 저장한다. CSV에는 닉네임과 횟수만 나간다.
"""
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

PREFIX = "tumbler:"
USERS_KEY = PREFIX + "users"
NICKNAME_RE = re.compile(r"^[가-힣a-zA-Z0-9_]{2,12}$")
PIN_RE = re.compile(r"^\d{4}$")
EVENT_ID_RE = re.compile(r"^[a-z0-9-]{1,40}$")
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
KST = timezone(timedelta(hours=9))

CONSENT_VERSION = "2026-10-31"
PIN_ITERATIONS = 120_000
MAX_FAILS = 5
LOCK_SECONDS = 15 * 60
MAX_TOKENS = 5
MAX_BODY_BYTES = 64 * 1024
MAX_OPS_PER_REQUEST = 300
MAX_USES_PER_DAY = 20
MAX_BACKFILL_DAYS = 60


class ApiError(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status = status
        self.code = code


class Limiter:
    """인스턴스 메모리 기준의 단순 제한. PIN 잠금은 저장소에 따로 기록한다."""

    def __init__(self):
        self._lock = threading.Lock()
        self._hits = {}

    def check(self, key, limit, window, now=None):
        now = time.time() if now is None else now
        with self._lock:
            recent = [t for t in self._hits.get(key, []) if now - t < window]
            if len(recent) >= limit:
                self._hits[key] = recent
                raise ApiError(429, "too_many")
            recent.append(now)
            self._hits[key] = recent
            if len(self._hits) > 5000:
                self._hits = {k: v for k, v in self._hits.items() if now - v[-1] < window}


LIMITER = Limiter()


def _storage_config():
    url = os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL") or ""
    token = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN") or ""
    if not url or not token:
        raise ApiError(503, "not_configured")
    return url.rstrip("/"), token


def _post(path, payload):
    url, token = _storage_config()
    request = urllib.request.Request(url + path, data=json.dumps(payload).encode("utf-8"), method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError):
        print("storage request failed")
        raise ApiError(503, "storage_error")


def redis(*command):
    data = _post("", list(command))
    if "error" in data:
        print("storage command failed")
        raise ApiError(503, "storage_error")
    return data.get("result")


def pipeline(commands):
    if not commands:
        return []
    rows = _post("/pipeline", [list(c) for c in commands])
    if not isinstance(rows, list) or any("error" in row for row in rows):
        print("storage pipeline failed")
        raise ApiError(503, "storage_error")
    return [row.get("result") for row in rows]


def _pairs(flat):
    flat = flat or []
    return dict(zip(flat[0::2], flat[1::2]))


def normalize_nickname(value):
    if not isinstance(value, str):
        raise ApiError(400, "invalid_nickname")
    nickname = unicodedata.normalize("NFC", value.strip())
    if not NICKNAME_RE.match(nickname):
        raise ApiError(400, "invalid_nickname")
    return nickname


def user_key(nickname):
    return PREFIX + "user:" + nickname.casefold()


def events_key(nickname):
    return PREFIX + "events:" + nickname.casefold()


def token_key(token_hash):
    return PREFIX + "token:" + token_hash


def hash_pin(pin, salt):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), PIN_ITERATIONS).hex()


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def load_events(nickname):
    return _pairs(redis("HGETALL", events_key(nickname)))


def issue_token(user, nickname):
    token = secrets.token_urlsafe(32)
    hashed = hash_token(token)
    tokens = (user.get("tokens") or []) + [hashed]
    old, user["tokens"] = tokens[:-MAX_TOKENS], tokens[-MAX_TOKENS:]
    commands = [("SET", token_key(hashed), nickname)] + [("DEL", token_key(h)) for h in old]
    return token, commands


def op_enter(body, now=None):
    """처음이면 계정을 만들고, 있으면 PIN을 확인한다."""
    now = time.time() if now is None else now
    nickname = normalize_nickname(body.get("nickname"))
    pin = body.get("pin")
    if not isinstance(pin, str) or not PIN_RE.match(pin):
        raise ApiError(400, "invalid_pin")
    key = user_key(nickname)
    raw = redis("GET", key)
    if raw is None:
        if body.get("consent") is not True:
            raise ApiError(400, "consent_required")
        salt = secrets.token_hex(16)
        user = {"nickname": nickname, "salt": salt, "pin": hash_pin(pin, salt), "fails": 0, "lockedUntil": 0,
                "tokens": [], "createdAt": int(now), "consentAt": int(now), "consentVersion": CONSENT_VERSION}
        token, commands = issue_token(user, nickname)
        # 동시에 같은 닉네임을 만들면 먼저 저장한 쪽만 성공한다.
        if redis("SET", key, json.dumps(user), "NX") is None:
            raise ApiError(409, "nickname_race")
        pipeline(commands + [("SADD", USERS_KEY, nickname.casefold())])
        return 200, {"nickname": nickname, "token": token, "events": {}, "created": True}

    user = json.loads(raw)
    if now < user.get("lockedUntil", 0):
        raise ApiError(429, "locked")
    if not hmac.compare_digest(hash_pin(pin, user["salt"]), user["pin"]):
        user["fails"] = user.get("fails", 0) + 1
        if user["fails"] >= MAX_FAILS:
            user["fails"], user["lockedUntil"] = 0, int(now + LOCK_SECONDS)
        redis("SET", key, json.dumps(user))
        raise ApiError(401, "wrong_pin")
    user["fails"], user["lockedUntil"] = 0, 0
    token, commands = issue_token(user, user["nickname"])
    pipeline(commands + [("SET", key, json.dumps(user))])
    return 200, {"nickname": user["nickname"], "token": token, "events": load_events(user["nickname"]), "created": False}


def authenticate(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise ApiError(401, "session_expired")
    token = authorization[7:].strip()
    if not token or len(token) > 200:
        raise ApiError(401, "session_expired")
    hashed = hash_token(token)
    nickname = redis("GET", token_key(hashed))
    if not nickname:
        raise ApiError(401, "session_expired")
    return nickname, hashed


def valid_day(day, today=None):
    if not isinstance(day, str) or not DAY_RE.match(day):
        return False
    try:
        value = date.fromisoformat(day)
    except ValueError:
        return False
    today = today or datetime.now(KST).date()
    # 시간대 차이를 고려해 내일까지 허용하고, 인터넷이 끊겼던 기록과 옮겨 온 기록은 60일까지 받는다.
    return today - timedelta(days=MAX_BACKFILL_DAYS) <= value <= today + timedelta(days=1)


def op_sync(body, authorization, today=None):
    """밀린 추가·삭제를 반영하고 전체 기록을 돌려준다. 같은 요청을 다시 보내도 결과가 같다."""
    nickname, _ = authenticate(authorization)
    add, remove = body.get("add") or [], body.get("remove") or []
    if not isinstance(add, list) or not isinstance(remove, list) or len(add) + len(remove) > MAX_OPS_PER_REQUEST:
        raise ApiError(400, "invalid_request")
    events = load_events(nickname)
    commands, rejected = [], []
    for event_id in remove:
        if isinstance(event_id, str) and EVENT_ID_RE.match(event_id) and event_id in events:
            commands.append(("HDEL", events_key(nickname), event_id))
            del events[event_id]
    counts = {}
    for day in events.values():
        counts[day] = counts.get(day, 0) + 1
    for item in add:
        event_id = item.get("id") if isinstance(item, dict) else None
        day = item.get("day") if isinstance(item, dict) else None
        if not isinstance(event_id, str) or not EVENT_ID_RE.match(event_id) or not valid_day(day, today):
            rejected.append(event_id if isinstance(event_id, str) else "")
            continue
        if event_id in events:
            continue
        if counts.get(day, 0) >= MAX_USES_PER_DAY:
            rejected.append(event_id)
            continue
        counts[day] = counts.get(day, 0) + 1
        events[event_id] = day
        commands.append(("HSET", events_key(nickname), event_id, day))
    pipeline(commands)
    return 200, {"nickname": nickname, "events": events, "rejected": rejected}


def op_logout(authorization):
    nickname, hashed = authenticate(authorization)
    raw = redis("GET", user_key(nickname))
    commands = [("DEL", token_key(hashed))]
    if raw:
        user = json.loads(raw)
        user["tokens"] = [t for t in user.get("tokens", []) if t != hashed]
        commands.append(("SET", user_key(nickname), json.dumps(user)))
    pipeline(commands)
    return 200, {"ok": True}


def op_delete(authorization):
    """참여 철회: 계정과 사용 기록을 서버에서 지운다."""
    nickname, _ = authenticate(authorization)
    raw = redis("GET", user_key(nickname))
    tokens = json.loads(raw).get("tokens", []) if raw else []
    pipeline([("DEL", user_key(nickname)), ("DEL", events_key(nickname)), ("SREM", USERS_KEY, nickname.casefold())]
             + [("DEL", token_key(t)) for t in tokens])
    return 200, {"ok": True}


def safe_cell(value):
    # 스프레드시트가 값을 수식으로 실행하지 못하게 한다.
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def build_csv(view="daily"):
    keys = sorted(redis("SMEMBERS", USERS_KEY) or [])
    rows = pipeline([("GET", PREFIX + "user:" + k) for k in keys] + [("HGETALL", PREFIX + "events:" + k) for k in keys])
    users, events = rows[:len(keys)], rows[len(keys):]
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    if view == "total":
        writer.writerow(["닉네임", "총 사용 횟수", "사용한 날 수", "첫 사용일", "마지막 사용일"])
    else:
        writer.writerow(["닉네임", "날짜", "사용 횟수"])
    for raw, flat in zip(users, events):
        if not raw:
            continue
        nickname = json.loads(raw)["nickname"]
        counts = {}
        for day in _pairs(flat).values():
            counts[day] = counts.get(day, 0) + 1
        days = sorted(counts)
        if view == "total":
            writer.writerow([safe_cell(nickname), sum(counts.values()), len(days), days[0] if days else "", days[-1] if days else ""])
        else:
            for day in days:
                writer.writerow([safe_cell(nickname), day, counts[day]])
    return ("﻿" + out.getvalue()).encode("utf-8")  # 엑셀에서 한글이 깨지지 않게 BOM을 붙인다


def check_admin(authorization, ip):
    expected = os.environ.get("ADMIN_PASSWORD", "")
    if not expected:
        raise ApiError(503, "not_configured")
    LIMITER.check("admin:" + ip, 10, 60)
    if not authorization or not authorization.startswith("Basic "):
        raise ApiError(401, "admin_required")
    try:
        decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise ApiError(401, "admin_required")
    password = decoded.split(":", 1)[-1]
    if not hmac.compare_digest(password.encode(), expected.encode()):
        raise ApiError(401, "admin_required")


def check_origin(origin, host):
    allowed = {h.strip() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()}
    if host:
        allowed.add(host)
    if not origin or urlparse(origin).netloc not in allowed:
        raise ApiError(403, "forbidden_origin")


def handle_post(op, raw, authorization, ip, origin, host):
    check_origin(origin, host)
    _storage_config()
    try:
        body = json.loads(raw or b"{}")
    except (ValueError, UnicodeDecodeError):
        raise ApiError(400, "invalid_request")
    if not isinstance(body, dict):
        raise ApiError(400, "invalid_request")
    if op == "enter":
        LIMITER.check("enter:" + ip, 20, 600)
        return op_enter(body)
    LIMITER.check("sync:" + ip, 120, 60)
    if op == "sync":
        return op_sync(body, authorization)
    if op == "logout":
        return op_logout(authorization)
    if op == "delete":
        return op_delete(authorization)
    raise ApiError(404, "unknown_op")


class handler(BaseHTTPRequestHandler):
    def _send(self, status, payload, extra=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _ip(self):
        forwarded = self.headers.get("X-Forwarded-For", "")
        return forwarded.split(",")[0].strip() or self.client_address[0]

    def _op(self):
        return parse_qs(urlparse(self.path).query).get("op", [""])[0]

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send(411, {"code": "invalid_request"})
        if length < 0 or length > MAX_BODY_BYTES:
            # 사진처럼 큰 내용은 받지 않는다. 연결 오류로 보이지 않게 한도까지 읽고 답한다.
            self.close_connection = True
            remaining = min(max(length, 0), 2 * MAX_BODY_BYTES)
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
            return self._send(413, {"code": "too_large"})
        raw = self.rfile.read(length)
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
        try:
            status, payload = handle_post(self._op(), raw, self.headers.get("Authorization", ""), self._ip(),
                                          self.headers.get("Origin", ""), host)
        except ApiError as error:
            status, payload = error.status, {"code": error.code}
        self._send(status, payload)

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        if query.get("op", [""])[0] != "export":
            return self._send(405, {"code": "method_not_allowed"})
        try:
            check_admin(self.headers.get("Authorization", ""), self._ip())
            view = "total" if query.get("view", [""])[0] == "total" else "daily"
            data = build_csv(view)
        except ApiError as error:
            extra = {"WWW-Authenticate": 'Basic realm="tumbler-export", charset="UTF-8"'} if error.status == 401 else None
            return self._send(error.status, {"code": error.code}, extra)
        filename = f"tumbler_usage_{view}_{datetime.now(KST).strftime('%Y%m%d')}.csv"
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass  # 방문자 IP가 로그에 남지 않게 한다
