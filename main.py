"""CPM2 Vinyl Transfer — Web Version | No Keys / No Coins / No Payments"""
from __future__ import annotations
import asyncio, base64, datetime, hashlib, hmac, json, logging, math, os, re, struct, time, urllib.parse
from contextlib import asynccontextmanager
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path
from typing import Optional
import aiohttp, aiosqlite, uvicorn
from fastapi import FastAPI, HTTPException, Request, Query, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
try:
    import brotli
except ImportError:
    brotli = None
from Crypto.Cipher import AES

# ==========================================================
# CONFIG
# ==========================================================
WEBAPP_URL = os.getenv("WEBAPP_URL", "http://localhost:8080").rstrip("/")
DB_PATH = os.getenv("DB_PATH", "mrx.db").strip() or "mrx.db"
IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
def now_ist(): return datetime.datetime.now(IST)
def ts_ist(): return now_ist().strftime("%Y-%m-%d %H:%M:%S")

# API ENDPOINTS
CPM1_API_KEY = "AIzaSyBW1ZbMiUeDZHYUO2bY8Bfnf5rRgrQGPTM"
CPM2_API_KEY = "AIzaSyCQDz9rgjgmvmFkvVfmvr2-7fT4tfrzRRQ"
CPM1_DATABASE_URL = "https://carparkingmultiplayer-dc1d2.firebaseio.com"
CPM1_API_BASE = "https://us-central1-carparkingmultiplayer-dc1d2.cloudfunctions.net"
CPM2_API_BASE = "https://europe-west1-cpm-2-7cea1.cloudfunctions.net"
CPM1_CARS_FUNCTION = "GetAllCars2"
CPM1_FALLBACK_BASES = ("https://europe-west1-cp-multiplayer.cloudfunctions.net","https://us-central1-cp-multiplayer.cloudfunctions.net")
CPM2_CARS_FUNCTION_CANDIDATES = ("GetAllCars24_1","GetAllCars23_1","GetAllCars22_1","GetAllCars21_1","GetAllCars20_2")
CPM2_SAVE_CAR_FUNCTION = "SaveCar22_1"
CPM2_SAVE_CAR_FUNCTION_CANDIDATES = ("SaveCar24_1","SaveCar23_1","SaveCar22_1","SaveCar21_1","SaveCar20_2")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("mrx")

app = FastAPI(title="CPM2 Vinyl Transfer")

# ==========================================================
# DATABASE
# ==========================================================
class _Rows:
    __slots__ = ("rows",)
    def __init__(self, rows): self.rows = rows
class SQLiteClient:
    def __init__(self, conn): self.conn = conn
    async def execute(self, sql, params=None):
        params = params or []
        cur = await self.conn.execute(sql, params)
        await self.conn.commit()
        if cur.description is not None:
            rows = await cur.fetchall()
            await cur.close()
            return _Rows(rows)
        await cur.close()
        return _Rows([])
    async def close(self):
        try: await self.conn.close()
        except Exception: pass

@asynccontextmanager
async def db_client():
    try:
        conn = await aiosqlite.connect(DB_PATH, timeout=30)
    except Exception as ex:
        log.error(f"db connect: {ex}")
        yield None
        return
    client = SQLiteClient(conn)
    try:
        yield client
    except Exception as ex:
        log.error(f"db_client error: {type(ex).__name__}: {ex}")
        raise
    finally:
        try: await client.close()
        except Exception: pass

async def init_db():
    async with db_client() as c:
        if not c: return False
        try:
            await c.execute("""CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                email TEXT UNIQUE,
                first_name TEXT,
                last_name TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )""")
            await c.execute("""CREATE TABLE IF NOT EXISTS activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                details TEXT,
                created_at_ist TEXT
            )""")
            log.info("✅ Database ready")
            return True
        except Exception as ex:
            log.error(f"❌ Database init: {ex}")
            return False

# ==========================================================
# VINYL CORE ENGINE
# ==========================================================
_balance_http_session = ContextVar("balance_http_session", default=None)

@lru_cache(maxsize=1)
def _load_car_names():
    for p in (Path(__file__).with_name("cpm2_car_names.json"), Path(__file__).parent / "cpm2_car_names.json"):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(d, dict):
                return {str(k): " ".join(str(v).split()) for k, v in d.items()}
        except: continue
    return {}

async def firebase_verify_password(email, password, *, api_key, session=None):
    if not api_key: return {"error": {"message": "NO_KEY"}}
    url = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key={api_key}"
    async def do(s):
        try:
            async with s.post(url, json={"email": email, "password": password, "returnSecureToken": True}, timeout=aiohttp.ClientTimeout(total=15)) as r:
                try: d = await r.json(content_type=None)
                except: return {"error": {"message": "SERVICE_UNAVAILABLE"}}
                return d
        except Exception as e: return {"error": {"message": f"CONNECTION_ERROR: {e}"}}
    if session: return await do(session)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as own:
        return await do(own)

def _derive_key_iv(local_id):
    if not local_id: return None, None
    raw = (local_id[:8] + "12345678").encode()[:16]
    return raw, raw

def _encrypt_value(value, local_id):
    k, iv = _derive_key_iv(local_id)
    if not k: return None
    raw = value.encode(); pad = 16 - len(raw) % 16; raw += bytes([pad]) * pad
    return base64.b64encode(AES.new(k, AES.MODE_CBC, iv).encrypt(raw)).decode()

def _int_value(v, d=0):
    try: return int(v)
    except: return d

def _float_value(v):
    try: n = float(v)
    except: return 0.0
    return n if math.isfinite(n) else 0.0

def _uint32_value(v): return _int_value(v) & 0xFFFFFFFF

def _int64_value(v):
    n = _int_value(v)
    if n > 0x7FFFFFFFFFFFFFFF: n -= 0x10000000000000000
    if n < -0x8000000000000000: n = -0x8000000000000000
    return n

def _memorypack_string(v):
    e = v.encode()
    if not e: return struct.pack("<i", 0)
    return struct.pack("<ii", ~len(e), len(v)) + e

def _vector3(v):
    if not isinstance(v, dict): return 0.0, 0.0, 0.0
    return (_float_value(v.get("x", v.get("X"))), _float_value(v.get("y", v.get("Y"))), _float_value(v.get("z", v.get("Z"))))

def _serialize_vinyl_item(item):
    p = _vector3(item.get("position")); s = _vector3(item.get("scaleRotation", item.get("scale_rotation")))
    ic = _vector3(item.get("iconPosition", item.get("icon_position"))); t = str(item.get("text") or "")
    return (b"\x06" + struct.pack("<9f", *p, *s, *ic) + _memorypack_string(t) + struct.pack("<Iq", _uint32_value(item.get("color")), _int64_value(item.get("packedData"))))

def _serialize_vinyl_list(items):
    return struct.pack("<i", len(items)) + b"".join(_serialize_vinyl_item(i) for i in items)

def _extract_vinyl_items(v):
    if isinstance(v, list): return [i for i in v if isinstance(i, dict)]
    if not isinstance(v, dict): return None
    for k in ("allVynils","oneVynil"):
        if isinstance(v.get(k), list): return [i for i in v[k] if isinstance(i, dict)]
    if {"position","scaleRotation","iconPosition"} & set(v): return [v]
    return None

def _brotli_decompress(p):
    if brotli is None: return None
    try: return brotli.decompress(p)
    except: return None

def _extract_vinyl_raw_candidate(p):
    d = _read_memorypack_vinyl_list(p, 0, len(p))
    if d is not None and d[0] == len(p): return p, d[1]
    if not p: return None
    w = _read_memorypack_vinyl_list(p, 1, len(p))
    if w is None: return None
    if len(p) - w[0] in (0, 4): return p[1:w[0]], w[1]
    return None

def _normalize_cpm1_vinyl_field(v):
    items = _extract_vinyl_items(v)
    if items is not None: return _serialize_vinyl_list(items), len(items)
    if v in (None,"",[]): return _serialize_vinyl_list([]), 0
    if not isinstance(v, str): return None
    try: dec = base64.b64decode(v, validate=True)
    except: return None
    for c in (dec, _brotli_decompress(dec)):
        if not isinstance(c, (bytes, bytearray)): continue
        r = _extract_vinyl_raw_candidate(bytes(c))
        if r: return r
    return None

def _instance_id_from_car(car):
    texts = car.get("texts")
    if isinstance(texts, list):
        for i in (2,1,0):
            if i < len(texts):
                v = str(texts[i] or "").strip()
                if v: return v
    return ""

def _normalize_cpm1_car(raw, idx, names):
    if not isinstance(raw, dict): return None
    cid = _int_value(raw.get("CarID"))
    if cid <= 0: return None
    v = _normalize_cpm1_vinyl_field(raw.get("Vynils")); w = _normalize_cpm1_vinyl_field(raw.get("WindowVinyls"))
    sup = v is not None and w is not None
    return {"id": cid, "index": idx, "name": names.get(str(cid), f"Car {cid}"),
            "instance_id": _instance_id_from_car(raw), "transferable": sup, "style_transferable": sup,
            "vinyls": v[1] if v else -1, "window": w[1] if w else -1,
            "vinyls_raw": v[0] if v else None, "window_raw": w[0] if w else None, "raw": raw}

def _memorypack_xor_key(local_id):
    c = list(local_id or "")
    if len(c) >= 7: c[6], c[4] = c[4], c[6]
    if len(c) >= 9: c.pop(8)
    if c: c.append(c[0])
    return "".join(c).encode()

_B64_TEXT = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n"

def _decode_current_memorypack(v, local_id):
    if not isinstance(v, dict) or v.get("code") != 1 or not isinstance(v.get("data"), str): return None
    if brotli is None: return None
    try:
        enc = base64.b64decode("".join(v["data"].split()), validate=True)
        for _ in range(2):
            if not enc or any(chr(b) not in _B64_TEXT for b in enc[:256]): break
            try: enc = base64.b64decode(enc.translate(None, b"\r\n"), validate=True)
            except: break
        xk = _memorypack_xor_key(local_id)
        if not xk: return None
        packed = bytes(b ^ xk[i % len(xk)] for i, b in enumerate(enc))
        return brotli.decompress(packed)
    except: return None

def _read_memorypack_string(p, o, e):
    if o + 4 > e: return None
    m = struct.unpack_from("<i", p, o)[0]; o += 4
    if m in (-1,0): return o
    if m > 0: bc = m * 2
    else:
        bc = ~m
        if o + 4 > e: return None
        o += 4
    if bc < 0 or o + bc > e: return None
    return o + bc

def _decode_memorypack_string_at(p, o, e):
    if o + 4 > e: return None
    m = struct.unpack_from("<i", p, o)[0]; c = o + 4
    if m in (-1,0): return c, ""
    if m > 0:
        bc = m * 2
        if c + bc > e: return None
        try: return c + bc, p[c:c+bc].decode("utf-16-le")
        except: return None
    bc = ~m
    if c + 4 + bc > e: return None
    cc = struct.unpack_from("<i", p, c)[0]; c += 4
    try: v = p[c:c+bc].decode("utf-8")
    except: return None
    if cc >= 0 and len(v) != cc: return None
    return c + bc, v

def _read_memorypack_vinyl(p, o, e):
    if o >= e: return None
    mc = p[o]; o += 1
    if mc == 255: return o
    if mc != 6 or o + 36 > e: return None
    vals = struct.unpack_from("<9f", p, o)
    if not all(math.isfinite(v) and abs(v) < 1e6 for v in vals): return None
    o += 36
    o = _read_memorypack_string(p, o, e)
    if o is None or o + 12 > e: return None
    return o + 12

def _read_memorypack_vinyl_list(p, o, e):
    if o + 4 > e: return None
    c = struct.unpack_from("<i", p, o)[0]; o += 4
    if c == -1: return o, 0
    if c < 0 or c > 2000: return None
    for _ in range(c):
        o = _read_memorypack_vinyl(p, o, e)
        if o is None: return None
    return o, c

def _read_memorypack_int_list(p, o, e):
    if o + 4 > e: return None
    c = struct.unpack_from("<i", p, o)[0]; o += 4
    if c == -1: return o
    if c < 0 or c > 1000 or o + c*4 > e: return None
    return o + c*4

def _read_memorypack_installed_body_kits(p, o, e):
    if o >= e: return None
    mc = p[o]; o += 1
    if mc == 255: return o
    if mc != 10 or o + 32 > e: return None
    o += 32; ts = o
    o = _read_memorypack_int_list(p, o, e)
    if o is None: o = _read_memorypack_string(p, ts, e)
    if o is None or o + 4 > e: return None
    return o + 4

def _read_memorypack_body_kit_colors(p, o, e):
    if o >= e: return None
    mc = p[o]; o += 1
    if mc == 255: return o
    if mc != 1 or o + 4 > e: return None
    c = struct.unpack_from("<i", p, o)[0]; o += 4
    if c == -1: return o
    if c < 0 or c > 128: return None
    for _ in range(c):
        if o >= e: return None
        im = p[o]; o += 1
        if im == 255: continue
        if im not in (2,3) or o + 12 > e: return None
        o += 12
    return o

def _read_memorypack_colors(p, o, e):
    if o >= e: return None
    mc = p[o]; o += 1
    if mc == 255: return o
    if mc != 8 or o + 32 > e: return None
    o += 32
    return _read_memorypack_body_kit_colors(p, o, e)

def _read_memorypack_bought_body_kits(p, o, e):
    if o >= e: return None
    mc = p[o]; o += 1
    if mc == 255: return o
    if mc != 10: return None
    for _ in range(10):
        o = _read_memorypack_int_list(p, o, e)
        if o is None: return None
    return o

def _extract_memorypack_style_fields(p, s, e, vo, ir):
    ist = s + 5
    ie = _read_memorypack_installed_body_kits(p, ist, e)
    if ie is None: return None
    cs = ie
    ce = _read_memorypack_colors(p, cs, e)
    if ce is None: return None
    ii = p.find(ir, ce, vo)
    if ii < 0: return None
    ien = ii + len(ir)
    bc = [o for o in range(ien, vo) if _read_memorypack_bought_body_kits(p, o, vo) == vo]
    if not bc: return None
    bs = max(bc)
    if not (ce < ii < ien < bs < vo): return None
    return {2: p[bs:vo], 3: p[cs:ce], 4: p[ien:bs], 5: p[ce:ii], 6: p[ist:ie]}

def _find_memorypack_car_instance(p, s, vo):
    strict = re.compile(r"^[A-Za-z]{2}\d{3,}_[A-Za-z]{2}\d{2,}_\d{2,}$")
    fb = None
    for o in range(s + 5, max(s + 5, vo - 3)):
        d = _decode_memorypack_string_at(p, o, vo)
        if d is None: continue
        e, t = d
        if not (8 <= len(t) <= 80 and t.count("_") >= 2 and any(c.isdigit() for c in t)): continue
        raw = p[o:e]
        if strict.fullmatch(t): return t, raw
        if fb is None and re.fullmatch(r"[A-Za-z0-9_-]+", t): fb = (t, raw)
    return fb

def _memorypack_car_offsets(p):
    if len(p) < 4: return None
    n = struct.unpack_from("<i", p, 0)[0]
    if n == 0: return []
    if n < 0 or n > 5000: return None
    ki = {int(c) for c in _load_car_names() if str(c).isdigit()}
    kn, bd = [], []
    for o in range(4, len(p) - 5):
        if p[o] != 9 or p[o+5] not in (10, 255): continue
        cid = struct.unpack_from("<i", p, o+1)[0]
        if 0 < cid <= 5000:
            bd.append((o, cid))
            if cid in ki: kn.append((o, cid))
    if len(kn) == n: return kn
    if len(bd) == n: return bd
    cf = []
    for o, cid in bd:
        ie = _read_memorypack_installed_body_kits(p, o+5, len(p))
        if ie is None: continue
        if _read_memorypack_colors(p, ie, len(p)) is None: continue
        cf.append((o, cid))
    if len(cf) == n: return cf
    return None

def _parse_memorypack_cloud_vinyls(v, local_id):
    p = _decode_current_memorypack(v, local_id)
    if p is None: return None
    recs = _memorypack_car_offsets(p)
    if recs is None: return None
    out = []
    for i, (s, cid) in enumerate(recs):
        e = recs[i+1][0] if i+1 < len(recs) else len(p)
        m = None
        for o in range(s+5, max(s+5, e-7)):
            f = _read_memorypack_vinyl_list(p, o, e)
            if f is None: continue
            s2 = _read_memorypack_vinyl_list(p, f[0], e)
            if s2 is not None and s2[0] == e:
                c = (f[1], s2[1], o, f[0])
                if m is None or (c[0]+c[1], c[2]) > (m[0]+m[1], m[2]): m = c
        car = {"index": i, "id": cid, "vinyls": m[0] if m else -1, "window": m[1] if m else -1,
               "transferable": False, "fingerprint": hashlib.sha256(p[s:e]).hexdigest()}
        if m:
            inst = _find_memorypack_car_instance(p, s, m[2])
            if inst:
                iid, iraw = inst
                sf = _extract_memorypack_style_fields(p, s, e, m[2], iraw)
                car.update({"instance_id": iid, "car_id_raw": p[s+1:s+5], "instance_raw": iraw,
                            "vinyls_raw": p[m[2]:m[3]], "window_raw": p[m[3]:e],
                            "style_fields": sf, "style_transferable": sf is not None, "transferable": True})
        out.append(car)
    return out

async def fetch_cpm1_cars(local_id, id_token):
    url = f"{CPM1_API_BASE}/{CPM1_CARS_FUNCTION}?auth={urllib.parse.quote(id_token)}&localId={urllib.parse.quote(local_id)}"
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
        try:
            async with s.get(url) as r:
                data = await r.json()
                names = _load_car_names()
                if isinstance(data, dict) and "cars" in data:
                    cars = data["cars"]
                    return [_normalize_cpm1_car(c, i, names) for i, c in enumerate(cars) if c]
                return []
        except Exception as e:
            log.error(f"CPM1 fetch error: {e}")
            return []

async def fetch_cpm2_cars(local_id, id_token):
    for func in CPM2_CARS_FUNCTION_CANDIDATES:
        url = f"{CPM2_API_BASE}/{func}?auth={urllib.parse.quote(id_token)}&localId={urllib.parse.quote(local_id)}"
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
            try:
                async with s.get(url) as r:
                    data = await r.json()
                    if isinstance(data, dict) and "code" in data and "data" in data:
                        cars = _parse_memorypack_cloud_vinyls(data, local_id)
                        if cars: return cars
            except Exception as e:
                log.warning(f"CPM2 {func} failed: {e}")
                continue
    return []

async def save_cpm2_car(local_id, id_token, instance_id, vinyls_raw=None, window_raw=None):
    for func in CPM2_SAVE_CAR_FUNCTION_CANDIDATES:
        url = f"{CPM2_API_BASE}/{func}"
        payload = {
            "localId": local_id,
            "auth": id_token,
            "instanceId": instance_id,
        }
        if vinyls_raw is not None: payload["vinyls"] = base64.b64encode(vinyls_raw).decode()
        if window_raw is not None: payload["windowVinyls"] = base64.b64encode(window_raw).decode()
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
            try:
                async with s.post(url, json=payload) as r:
                    result = await r.json()
                    if result.get("success") or result.get("code") == 0:
                        return {"success": True, "result": result}
            except Exception as e:
                log.warning(f"Save {func} failed: {e}")
                continue
    return {"success": False, "error": "All save functions failed"}

async def transfer_vinyls(source_local_id, source_token, source_version,
                          target_local_id, target_token, target_version,
                          source_instance_id, target_instance_id,
                          transfer_vinyls=True, transfer_window=True):
    
    if source_version == "cpm1" and target_version == "cpm2":
        source_cars = await fetch_cpm1_cars(source_local_id, source_token)
        target_cars = await fetch_cpm2_cars(target_local_id, target_token)
    elif source_version == "cpm2" and target_version == "cpm2":
        source_cars = await fetch_cpm2_cars(source_local_id, source_token)
        target_cars = await fetch_cpm2_cars(target_local_id, target_token)
    elif source_version == "cpm2" and target_version == "cpm1":
        return {"success": False, "error": "CPM2 → CPM1 not supported yet"}
    else:
        return {"success": False, "error": "Unsupported combination"}

    source_car = next((c for c in source_cars if c and c.get("instance_id") == source_instance_id), None)
    target_car = next((c for c in target_cars if c and c.get("instance_id") == target_instance_id), None)

    if not source_car: return {"success": False, "error": "Source car not found"}
    if not target_car: return {"success": False, "error": "Target car not found"}
    if not source_car.get("transferable"): return {"success": False, "error": "Source car has no transferable vinyl data"}

    v_raw = source_car.get("vinyls_raw") if transfer_vinyls else None
    w_raw = source_car.get("window_raw") if transfer_window else None

    if target_version == "cpm2":
        result = await save_cpm2_car(target_local_id, target_token, target_instance_id, v_raw, w_raw)
        return result
    
    return {"success": False, "error": "Save function not implemented for target version"}

# ==========================================================
# API ROUTES
# ==========================================================
class LoginRequest(BaseModel):
    email: str
    password: str

class CarsRequest(BaseModel):
    local_id: str
    id_token: str
    version: str

class TransferRequest(BaseModel):
    source_email: str
    source_password: str
    source_version: str
    target_email: str
    target_password: str
    target_version: str
    source_instance_id: str
    target_instance_id: str
    transfer_vinyls: bool = True
    transfer_window: bool = True

@app.on_event("startup")
async def startup():
    await init_db()
    log.info("🚀 MRX Web Server Ready — http://localhost:8080")

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/login")
async def login(req: LoginRequest):
    result = await firebase_verify_password(req.email, req.password, api_key=CPM1_API_KEY)
    if "error" in result:
        result = await firebase_verify_password(req.email, req.password, api_key=CPM2_API_KEY)
    if "error" in result:
        raise HTTPException(401, result.get("error", {}).get("message", "Login failed"))
    
    return {
        "success": True,
        "local_id": result.get("localId"),
        "id_token": result.get("idToken"),
        "email": result.get("email"),
        "expires_in": result.get("expiresIn")
    }

@app.post("/api/cars")
async def get_cars(req: CarsRequest):
    if req.version == "cpm1":
        cars = await fetch_cpm1_cars(req.local_id, req.id_token)
    elif req.version == "cpm2":
        cars = await fetch_cpm2_cars(req.local_id, req.id_token)
    else:
        raise HTTPException(400, "Invalid version")
    
    return {"success": True, "cars": cars}

@app.post("/api/transfer")
async def transfer(req: TransferRequest):
    src_login = await firebase_verify_password(req.source_email, req.source_password, api_key=CPM1_API_KEY)
    if "error" in src_login:
        src_login = await firebase_verify_password(req.source_email, req.source_password, api_key=CPM2_API_KEY)
    if "error" in src_login:
        raise HTTPException(401, "Source account login failed")
    
    tgt_login = await firebase_verify_password(req.target_email, req.target_password, api_key=CPM1_API_KEY)
    if "error" in tgt_login:
        tgt_login = await firebase_verify_password(req.target_email, req.target_password, api_key=CPM2_API_KEY)
    if "error" in tgt_login:
        raise HTTPException(401, "Target account login failed")

    result = await transfer_vinyls(
        source_local_id=src_login["localId"],
        source_token=src_login["idToken"],
        source_version=req.source_version,
        target_local_id=tgt_login["localId"],
        target_token=tgt_login["idToken"],
        target_version=req.target_version,
        source_instance_id=req.source_instance_id,
        target_instance_id=req.target_instance_id,
        transfer_vinyls=req.transfer_vinyls,
        transfer_window=req.transfer_window
    )
    return result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
