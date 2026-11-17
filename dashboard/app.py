"""XAI-SDN-IDS live dashboard backend.

Polls the Ryu controller and the testbed runner (both on the private Docker network),
keeps a short in-memory history and pushes updates to browsers over Server-Sent Events.
Viewing is public; anything that changes the network requires a signed session cookie.
"""
import asyncio
import csv
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

CONTROLLER = os.environ.get("CONTROLLER_URL", "http://controller:8080")
RUNNER = os.environ.get("RUNNER_URL", "http://mininet:9000")
PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
SECRET = (os.environ.get("SESSION_SECRET") or secrets.token_hex(32)).encode()
SECURE_COOKIE = os.environ.get("SECURE_COOKIE", "1") == "1"
PROJECT = Path(os.environ.get("PROJECT_DIR", "/project"))
STATIC = Path(__file__).parent / "static"
SESSION_TTL = 12 * 3600
COOKIE = "sds_session"


class State:
    def __init__(self):
        self.rounds = deque(maxlen=450)
        self.decisions = deque(maxlen=600)
        self.status = {}
        self.mitigations = {}
        self.runner = {}
        self.controller_ok = False
        self.runner_ok = False
        self.subscribers = set()

    def publish(self, event, data):
        msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        for q in list(self.subscribers):
            if q.qsize() < 200:          # drop updates for clients that stopped reading
                q.put_nowait(msg)

    def episodes(self):
        """Runner episodes annotated with live detection / mitigation latency."""
        out = []
        for ep in self.runner.get("episodes", []):
            e = dict(ep)
            mine = [d for d in self.decisions if d["src_ip"] == ep["src_ip"] and d["ts"] >= ep["start"]
                    and (ep["end"] is None or d["ts"] <= ep["end"] + 6)]
            flagged = [d for d in mine if d["label"] != "benign"]
            mitig = [d for d in mine if d.get("mitigation_ts")]
            e["detected_s"] = round(flagged[0]["ts"] - ep["start"], 2) if flagged else None
            e["mitigated_s"] = round(mitig[0]["mitigation_ts"] - ep["start"], 2) if mitig else None
            # strongest action taken during the episode (a rate-limit may escalate to a block)
            e["action"] = (max((d["action"] for d in mitig), key=["RATE_LIMIT", "BLOCK"].index)
                           if mitig else None)
            e["predicted"] = flagged[0]["label"] if flagged else None
            out.append(e)
        return out

    def snapshot(self):
        # Keep the first payload small for slow links: 5 min of rounds, the client grows to 10 min.
        return {"rounds": list(self.rounds)[-150:], "decisions": list(self.decisions)[-100:],
                "status": self.status, "mitigations": self.mitigations,
                "episodes": self.episodes(), "health": self.health(),
                "demo_running": self.runner.get("demo_running", False)}

    def health(self):
        return {"controller": self.controller_ok, "testbed": self.runner_ok}


state = State()


async def poll(client):
    last_round = last_decision = 0.0
    tick = 0
    while True:
        try:
            r = await client.get(f"{CONTROLLER}/xai/rounds", params={"since": last_round})
            d = await client.get(f"{CONTROLLER}/xai/decisions", params={"since": last_decision})
            rounds, decisions = r.json(), d.json()
            for item in rounds:
                state.rounds.append(item)
                last_round = item["ts"]
                state.publish("round", item)
            for item in decisions:
                state.decisions.append(item)
                last_decision = item["ts"]
                state.publish("decision", item)
            if tick % 2 == 0:
                state.status = (await client.get(f"{CONTROLLER}/xai/status")).json()
                state.mitigations = (await client.get(f"{CONTROLLER}/xai/mitigations")).json()
            state.controller_ok = True
        except (httpx.HTTPError, ValueError):
            state.controller_ok = False
        if tick % 2 == 0:
            try:
                state.runner = (await client.get(f"{RUNNER}/status")).json()
                state.runner_ok = True
            except (httpx.HTTPError, ValueError):
                state.runner_ok = False
            state.publish("status", {"status": state.status, "mitigations": state.mitigations,
                                     "episodes": state.episodes(), "health": state.health(),
                                     "demo_running": state.runner.get("demo_running", False)})
        tick += 1
        await asyncio.sleep(1.0)


@asynccontextmanager
async def lifespan(app):
    app.state.client = httpx.AsyncClient(timeout=5.0)
    task = asyncio.create_task(poll(app.state.client))
    yield
    task.cancel()
    await app.state.client.aclose()


app = FastAPI(title="XAI-SDN-IDS dashboard", lifespan=lifespan, docs_url=None, redoc_url=None)

# ------------------------------------------------------------------ auth
def _sign(expiry):
    return hmac.new(SECRET, str(expiry).encode(), hashlib.sha256).hexdigest()


def is_authed(request: Request):
    token = request.cookies.get(COOKIE, "")
    try:
        expiry, sig = token.split(".", 1)
        return int(expiry) > time.time() and hmac.compare_digest(sig, _sign(int(expiry)))
    except ValueError:
        return False


def require_auth(request: Request):
    if not is_authed(request):
        raise HTTPException(401, "Sign in to control the testbed.")


_attempts = defaultdict(deque)


class Login(BaseModel):
    password: str = Field(max_length=200)


@app.post("/api/login")
def login(body: Login, request: Request, response: Response):
    client_ip = request.headers.get("x-real-ip") or request.client.host
    window = _attempts[client_ip]
    while window and window[0] < time.time() - 60:
        window.popleft()
    if len(window) >= 5:
        raise HTTPException(429, "Too many attempts. Wait a minute and try again.")
    window.append(time.time())
    if not PASSWORD or not hmac.compare_digest(body.password.encode(), PASSWORD.encode()):
        raise HTTPException(401, "Wrong password.")
    expiry = int(time.time()) + SESSION_TTL
    response.set_cookie(COOKIE, f"{expiry}.{_sign(expiry)}", max_age=SESSION_TTL, httponly=True,
                        secure=SECURE_COOKIE, samesite="strict")
    return {"ok": True}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE)
    return {"ok": True}


@app.get("/api/me")
def me(request: Request):
    return {"authenticated": is_authed(request)}


# ------------------------------------------------------------------ live data
@app.get("/api/stream")
async def stream(request: Request):
    queue = asyncio.Queue()
    state.subscribers.add(queue)

    async def events():
        try:
            yield f"event: snapshot\ndata: {json.dumps(state.snapshot())}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    yield await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            state.subscribers.discard(queue)

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _check_ip(ip):
    try:
        if ipaddress.ip_address(ip) not in ipaddress.ip_network("10.0.0.0/24"):
            raise ValueError
    except ValueError:
        raise HTTPException(400, "Unknown host address.")


@app.get("/api/explain/{ip}")
async def explain(ip: str):
    _check_ip(ip)
    try:
        r = await app.state.client.get(f"{CONTROLLER}/xai/explain/{ip}")
    except httpx.HTTPError:
        raise HTTPException(503, "Controller is not reachable.")
    return Response(r.content, status_code=r.status_code, media_type="application/json")


@app.get("/api/results")
def results():
    """Offline evaluation results produced by ml/train.py and ml/replay_ablation.py."""
    res = PROJECT / "results"

    def read_csv(name):
        p = res / name
        return list(csv.DictReader(p.open())) if p.exists() else []

    sig = res / "shap_class_signatures.json"
    return {"models": read_csv("model_comparison.csv"), "per_class": read_csv("rf_per_class.csv"),
            "ablation": read_csv("ablation_test2.csv"),
            "signatures": json.loads(sig.read_text()) if sig.exists() else {}}


# ------------------------------------------------------------------ controls
class Attack(BaseModel):
    type: str
    src: str
    dst: str
    duration: int = 30


async def _forward(method, url, **kw):
    try:
        r = await app.state.client.request(method, url, **kw)
    except httpx.HTTPError:
        raise HTTPException(503, "The testbed is not reachable.")
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.json().get("error", "Request failed."))
    return r.json()


@app.post("/api/attack", dependencies=[Depends(require_auth)])
async def attack(body: Attack):
    return await _forward("POST", f"{RUNNER}/attack", json=body.model_dump())


@app.post("/api/demo", dependencies=[Depends(require_auth)])
async def demo():
    return await _forward("POST", f"{RUNNER}/demo")


@app.post("/api/stop", dependencies=[Depends(require_auth)])
async def stop():
    return await _forward("POST", f"{RUNNER}/stop")


@app.post("/api/release/{ip}", dependencies=[Depends(require_auth)])
async def release(ip: str):
    _check_ip(ip)
    return await _forward("DELETE", f"{CONTROLLER}/xai/mitigations/{ip}")


class Mode(BaseModel):
    mode: str


@app.post("/api/mode", dependencies=[Depends(require_auth)])
async def mode(body: Mode):
    return await _forward("POST", f"{CONTROLLER}/xai/mode", json=body.model_dump())


# ------------------------------------------------------------------ static
app.mount("/figures", StaticFiles(directory=PROJECT / "results", check_dir=False), name="figures")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
