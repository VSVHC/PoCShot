#!/usr/bin/env python3
"""
PoCShot (poc_shot.py) - PoC screenshot tool for authorized testing.

Modes
  real  : headed Chrome, maximized, real address bar/padlock, window captured from screen (Windows 11). Sequential.
  frame : headless Chrome, page screenshot wrapped in a drawn Chrome-style frame. Concurrent, supports --full-page.

Setup (Windows 11)
  pip install playwright pillow mss
  (Google Chrome must be installed. If it is not, run: playwright install chromium  -> used for frame mode only)

Examples
  python poc_shot.py -u https://example.com
  python poc_shot.py -u example.com --monitor 2              (real Chrome on 2nd monitor, keep working on main)
  python poc_shot.py -l hosts.txt --scope scope.txt --mode frame --full-page --scroll -t 15
  httpx -l hosts.txt | python poc_shot.py -l - --mode frame
  python poc_shot.py -u 10.0.0.1:8443 --proxy http://127.0.0.1:8080 -H "Authorization: Bearer X" --cookie "sid=abc"
  python poc_shot.py -u "https://t.com/?q=<payload>" --keep-dialogs     (XSS alert stays in the shot)
  python poc_shot.py -u https://t.com/login --steps steps.txt --highlight "Welcome admin"
  python poc_shot.py -l urls.txt --mode frame --device "iPhone 14" --skip-existing --hash --json

steps.txt (one step per line, run after page load, before capture)
  fill #user | admin
  fill #pass | Password1
  click button[type=submit]
  press Enter
  wait 2
  wait_for #dashboard
  goto https://t.com/admin
  eval document.title = 'x'

Module use
  from poc_shot import Config, run
  rows = run(["https://example.com"], Config(mode="frame"))
"""
import argparse
import fnmatch
import hashlib
import io
import ipaddress
import json
import queue
import re
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import Error as PWError
from playwright.sync_api import sync_playwright

IS_WIN = sys.platform == "win32"

if IS_WIN:
    import ctypes
    from ctypes import wintypes

    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # physical pixel coordinates
    except Exception:
        pass
    user32 = ctypes.windll.user32
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsIconic.argtypes = [wintypes.HWND]
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                                    ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    ctypes.windll.dwmapi.DwmGetWindowAttribute.argtypes = [wintypes.HWND, wintypes.DWORD,
                                                           ctypes.c_void_p, wintypes.DWORD]
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

FAST_FAIL = ("ERR_CONNECTION_REFUSED", "ERR_SSL_PROTOCOL_ERROR", "ERR_NAME_NOT_RESOLVED",
             "ERR_ADDRESS_UNREACHABLE")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
BANNER_RE = re.compile(r"^(accept( all)?( cookies)?|i agree|agree|allow all|got it|ok|okay|"
                       r"accept & continue|accept and continue)$", re.I)


@dataclass
class Config:
    mode: str = "real"
    out: str = "evidence"
    threads: int = 10
    full_page: bool = False
    width: int = 1920
    height: int = 1080
    delay: float = 2.0
    wait_selector: str = ""
    timeout: int = 30
    retries: int = 2
    scope: str = ""
    proxy: str = ""
    headers: list = field(default_factory=list)
    cookie: str = ""
    basic_auth: str = ""
    ua: str = ""
    dismiss_banners: bool = False
    monitor: int = 0
    keep_dialogs: bool = False
    scroll: bool = False
    highlight: str = ""
    steps: list = field(default_factory=list)
    skip_existing: bool = False
    device: str = ""
    device_opts: dict = field(default_factory=dict)
    hash: bool = False
    json_out: bool = False


class ScopeBlocked(Exception):
    pass


class StepError(Exception):
    pass


_LOG = [sys.stdout]


def log(msg):
    print(msg, file=_LOG[0], flush=True)


# --------------------------------------------------------------------------- scope / targets
class Scope:
    """Entries: exact host, '*.example.com' (subdomains only), IP, or CIDR. Empty file arg = no scope check."""

    def __init__(self, path):
        self.active = bool(path)
        self.nets, self.pats = [], []
        if path:
            for line in Path(path).read_text(errors="ignore").splitlines():
                line = line.split("#")[0].strip().lower()
                if not line:
                    continue
                try:
                    self.nets.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    self.pats.append(line)

    def allows(self, host):
        if not self.active:
            return True
        host = (host or "").lower().strip("[]")
        try:
            ip = ipaddress.ip_address(host)
            return any(n.version == ip.version and ip in n for n in self.nets)
        except ValueError:
            return any(fnmatch.fnmatch(host, p) for p in self.pats)


def parse_line(line):
    """Accepts plain URLs/hosts, httpx (text or -json), subfinder (text or -json), nmap -oG."""
    line = ANSI.sub("", line).strip()
    if not line or line.startswith("#"):
        return []
    if line.startswith("{"):
        try:
            d = json.loads(line)
        except ValueError:
            return []
        v = d.get("url") or d.get("input") or d.get("host")
        return [v] if v else []
    if line.startswith("Host:") and "Ports:" in line:
        host = line.split()[1]
        out = []
        for item in line.split("Ports:")[1].split("Ignored State")[0].split(","):
            f = item.strip().split("/")
            if len(f) >= 5 and f[1] == "open":
                port, svc = f[0], f[4]
                if "http" in svc or "ssl" in svc or port in ("80", "443", "8000", "8080", "8443", "8888"):
                    https = port in ("443", "8443") or "ssl" in svc or svc == "https"
                    out.append(f"{'https' if https else 'http'}://{host}:{port}")
        return out
    return [line.split()[0]]


def candidates(t):
    t = t.strip()
    if re.match(r"^[a-z][a-z0-9+.-]*://", t, re.I):
        return [t]
    if urlparse("//" + t).port == 80:
        return ["http://" + t, "https://" + t]
    return ["https://" + t, "http://" + t]


# --------------------------------------------------------------------------- drawing
def _font(size, bold=False):
    names = ["segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"] if bold else \
            ["segoeui.ttf", "arial.ttf", "DejaVuSans.ttf"]
    for n in names:
        try:
            return ImageFont.truetype(n, size)
        except OSError:
            pass
    return ImageFont.load_default()


def _fit(d, text, f, maxw):
    if d.textlength(text, font=f) <= maxw:
        return text
    while text and d.textlength(text + "…", font=f) > maxw:
        text = text[:-1]
    return text + "…"


def _wrap(d, text, f, maxw):
    lines = []
    for para in (text or "").split("\n"):
        cur = ""
        for word in para.split(" "):
            t = (cur + " " + word).strip()
            if not cur or d.textlength(t, font=f) <= maxw:
                cur = t
            else:
                lines.append(cur)
                cur = word
        lines.append(cur)
    return lines[:12]


def draw_dialog(img, host, dialog, top):
    """Chrome-style alert/confirm/prompt box (frame mode only)."""
    kind, msg = dialog
    d = ImageDraw.Draw(img)
    f_t, f_b, f_btn = _font(17, True), _font(14), _font(14, True)
    bw = min(512, img.width - 24)
    bx = (img.width - bw) // 2
    lines = _wrap(d, msg, f_b, bw - 48)
    h = 20 + 28 + 8 + 20 * len(lines) + 16 + 34 + 20
    by = top + 8
    d.rounded_rectangle([bx + 3, by + 4, bx + bw + 3, by + h + 4], radius=12, fill="#C9CCD1")
    d.rounded_rectangle([bx, by, bx + bw, by + h], radius=12, fill="#FFFFFF", outline="#DADCE0")
    d.text((bx + 24, by + 20), f"{host} says", font=f_t, fill="#202124")
    y = by + 20 + 28 + 8
    for ln in lines:
        d.text((bx + 24, y), ln, font=f_b, fill="#202124")
        y += 20
    y += 16
    right, ok_w, can_w = bx + bw - 24, 64, 84
    d.rounded_rectangle([right - ok_w, y, right, y + 34], radius=17, fill="#0B57D0")
    d.text((right - ok_w + (ok_w - d.textlength("OK", font=f_btn)) / 2, y + 8), "OK", font=f_btn, fill="#FFFFFF")
    if kind in ("confirm", "prompt"):
        x0 = right - ok_w - 12 - can_w
        d.rounded_rectangle([x0, y, x0 + can_w, y + 34], radius=17, fill="#FFFFFF", outline="#DADCE0")
        d.text((x0 + (can_w - d.textlength("Cancel", font=f_btn)) / 2, y + 8), "Cancel", font=f_btn, fill="#0B57D0")


def chrome_frame(shot, url, title, state, dialog=None):
    """state: 'https' | 'http' | 'tls'. dialog: optional (type, message) drawn as a Chrome alert box."""
    W = shot.width
    compact = W < 700                      # mobile-width shots: address bar only, no tab strip
    tab_h, bar_h = (0, 52) if compact else (40, 46)
    img = Image.new("RGB", (W, tab_h + bar_h + shot.height), "#FFFFFF")
    d = ImageDraw.Draw(img)
    f_tab, f_url = _font(13), _font(15)
    grey, dark = "#5F6368", "#202124"
    cy = tab_h + bar_h // 2

    if not compact:
        d.rectangle([0, 0, W, tab_h], fill="#DEE1E6")
        d.rounded_rectangle([8, 6, 248, tab_h + 6], radius=10, fill="#FFFFFF")
        d.ellipse([20, 15, 36, 31], outline=grey, width=2)
        d.text((44, 13), _fit(d, title or url, f_tab, 165), font=f_tab, fill=dark)
        d.line([(229, 17), (237, 25)], fill=grey, width=2)
        d.line([(229, 25), (237, 17)], fill=grey, width=2)
        d.line([(26, cy), (42, cy)], fill=grey, width=2)                       # back
        d.line([(26, cy), (33, cy - 7)], fill=grey, width=2)
        d.line([(26, cy), (33, cy + 7)], fill=grey, width=2)
        d.line([(64, cy), (80, cy)], fill="#BDC1C6", width=2)                  # forward (disabled)
        d.line([(80, cy), (73, cy - 7)], fill="#BDC1C6", width=2)
        d.line([(80, cy), (73, cy + 7)], fill="#BDC1C6", width=2)
        d.arc([98, cy - 8, 114, cy + 8], start=40, end=330, fill=grey, width=2)  # reload
        d.polygon([(112, cy - 9), (118, cy - 3), (110, cy - 3)], fill=grey)
        ox0, ox1 = 130, max(W - 120, 400)
        for dy in (-6, 0, 6):                                                  # menu dots
            d.ellipse([W - 30, cy + dy - 2, W - 26, cy + dy + 2], fill=grey)
        d.ellipse([W - 76, cy - 11, W - 54, cy + 11], fill="#9AA0A6")           # profile
    else:
        ox0, ox1 = 10, W - 10

    d.rounded_rectangle([ox0, cy - 17, ox1, cy + 17], radius=17, fill="#F1F3F4")
    x = ox0 + 16
    if state == "https":
        d.rounded_rectangle([x, cy - 2, x + 12, cy + 8], radius=2, fill=grey)
        d.arc([x + 2, cy - 9, x + 10, cy + 1], 180, 360, fill=grey, width=2)
        x += 24
    else:
        col = "#B3261E" if state == "tls" else grey
        if state == "tls":
            d.polygon([(x + 7, cy - 8), (x + 15, cy + 7), (x - 1, cy + 7)], outline=col, width=2)
            d.line([(x + 7, cy - 3), (x + 7, cy + 2)], fill=col, width=2)
        else:
            d.ellipse([x - 1, cy - 8, x + 15, cy + 8], outline=col, width=2)
            d.line([(x + 7, cy - 1), (x + 7, cy + 4)], fill=col, width=2)
        x += 24
        d.text((x, cy - 10), "Not secure", font=f_url, fill=col)
        x += int(d.textlength("Not secure", font=f_url)) + 10
        d.line([(x - 5, cy - 9), (x - 5, cy + 9)], fill="#DADCE0", width=1)
        x += 4

    p = urlparse(url)
    rest = (p.path if p.path != "/" else "") + (f"?{p.query}" if p.query else "") + \
           (f"#{p.fragment}" if p.fragment else "")
    host = _fit(d, p.netloc, f_url, ox1 - x - 16)
    d.text((x, cy - 10), host, font=f_url, fill=dark)
    x += int(d.textlength(host, font=f_url))
    if rest and x < ox1 - 30:
        d.text((x, cy - 10), _fit(d, rest, f_url, ox1 - x - 16), font=f_url, fill=grey)

    d.line([(0, tab_h + bar_h), (W, tab_h + bar_h)], fill="#DADCE0")
    img.paste(shot, (0, tab_h + bar_h))
    if dialog:
        draw_dialog(img, p.netloc, dialog, tab_h + bar_h)
    return img


# --------------------------------------------------------------------------- real window capture (Windows)
def _find_hwnd(marker):
    found = []

    def cb(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            n = user32.GetWindowTextLengthW(hwnd)
            if n:
                buf = ctypes.create_unicode_buffer(n + 1)
                user32.GetWindowTextW(hwnd, buf, n + 1)
                if marker in buf.value:
                    found.append(hwnd)
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return found[0] if found else None


def _wait(fn, secs):
    end, v = time.time() + secs, None
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.1)
    return v


def find_chrome_window(page):
    """Find this page's Chrome window while it is still about:blank (works even if a dialog opens later)."""
    marker = "SHOT" + uuid.uuid4().hex[:8]
    page.evaluate("m => { document.title = m }", marker)
    hwnd = _wait(lambda: _find_hwnd(marker), 3)
    if not hwnd:
        raise RuntimeError("Chrome window not found (is it minimized or on another desktop?)")
    return hwnd


def check_monitor(idx):
    import mss
    with mss.mss() as sct:
        n = len(sct.monitors) - 1
    return None if 1 <= idx <= n else f"--monitor {idx} invalid: found {n} monitor(s), use 1..{n}"


def move_to_monitor(hwnd, idx):
    import mss
    with mss.mss() as sct:
        m = sct.monitors[idx]
    user32.ShowWindow(hwnd, 9)                                            # restore
    user32.SetWindowPos(hwnd, None, m["left"] + 60, m["top"] + 60, 900, 600, 0x0004)   # SWP_NOZORDER
    user32.ShowWindow(hwnd, 3)                                            # maximize on that monitor
    time.sleep(1.0)


def grab_window(hwnd, cfg):
    """Capture only the Chrome window (address bar + tab + page), no taskbar."""
    import mss
    front = not cfg.monitor    # on the main screen the window must be brought to front; on --monitor N it is not
    if user32.IsIconic(hwnd):                       # only un-minimize; never un-maximize
        user32.ShowWindow(hwnd, 9)
    if front:
        user32.keybd_event(0x12, 0, 0, 0)           # ALT trick so SetForegroundWindow is allowed
        user32.SetForegroundWindow(hwnd)
        user32.keybd_event(0x12, 0, 2, 0)
        user32.SetWindowPos(hwnd, wintypes.HWND(-1), 0, 0, 0, 0, 0x0003)   # TOPMOST, NOSIZE|NOMOVE
    r = wintypes.RECT()
    ctypes.windll.dwmapi.DwmGetWindowAttribute(hwnd, 9, ctypes.byref(r), ctypes.sizeof(r))  # visible bounds
    if front:
        user32.SetCursorPos((r.left + r.right) // 2, r.top + 12)   # empty tab-strip area: no hover tooltips
    time.sleep(1.0)
    with mss.mss() as sct:
        g = sct.grab({"left": r.left, "top": r.top, "width": r.right - r.left, "height": r.bottom - r.top})
        img = Image.frombytes("RGB", g.size, g.bgra, "raw", "BGRX")
    if front:
        user32.SetWindowPos(hwnd, wintypes.HWND(-2), 0, 0, 0, 0, 0x0003)   # NOTOPMOST
    return img


# --------------------------------------------------------------------------- browser helpers
def launch(p, cfg):
    args = ["--no-first-run", "--no-default-browser-check", "--disable-infobars"]
    kw = {"args": args, "ignore_default_args": ["--enable-automation"]}
    if cfg.proxy:
        kw["proxy"] = {"server": cfg.proxy, "bypass": "<-loopback>"}   # also proxy localhost targets
    if cfg.mode == "real":
        return p.chromium.launch(channel="chrome", headless=False, **kw)
    try:
        return p.chromium.launch(channel="chrome", headless=True, **kw)
    except PWError:
        return p.chromium.launch(headless=True, **kw)


def parse_headers(items):
    out = {}
    for h in items:
        k, _, v = h.partition(":")
        if k.strip():
            out[k.strip().lower()] = v.strip()
    return out


def new_ctx(browser, cfg, url, ignore, scope):
    o = {"ignore_https_errors": ignore}
    if cfg.mode == "real":
        o["no_viewport"] = True
    elif cfg.device_opts:
        o.update(cfg.device_opts)
    else:
        o["viewport"] = {"width": cfg.width, "height": cfg.height}
    if cfg.ua:
        o["user_agent"] = cfg.ua
    if cfg.basic_auth:
        u, _, pw = cfg.basic_auth.partition(":")
        o["http_credentials"] = {"username": u, "password": pw}
    ctx = browser.new_context(**o)
    ctx.set_default_timeout(cfg.timeout * 1000)

    if cfg.cookie:
        if Path(cfg.cookie).is_file():
            ctx.add_cookies(json.loads(Path(cfg.cookie).read_text()))
        else:
            ctx.add_cookies([{"name": k.strip(), "value": v.strip(), "url": url}
                             for k, _, v in (c.partition("=") for c in cfg.cookie.split(";")) if k.strip()])

    hdrs, target_host = parse_headers(cfg.headers), urlparse(url).hostname

    def handler(route):
        req, nav = route.request, False
        try:
            nav = req.is_navigation_request() and req.frame.parent_frame is None
        except Exception:
            pass
        host = urlparse(req.url).hostname
        if nav and not scope.allows(host):
            return route.abort("blockedbyclient")
        if hdrs and host == target_host:       # custom headers only go to the target host
            return route.continue_(headers={**req.headers, **hdrs})
        return route.continue_()

    ctx.route("**/*", handler)
    return ctx


def set_window(ctx, page, cfg):
    s = ctx.new_cdp_session(page)
    w = s.send("Browser.getWindowForTarget")
    s.send("Browser.setWindowBounds", {"windowId": w["windowId"], "bounds": {"windowState": "maximized"}})


def settle(page, cfg):
    try:
        page.wait_for_load_state("networkidle", timeout=cfg.timeout * 1000)
    except PWError:
        pass
    if cfg.wait_selector:
        try:
            page.wait_for_selector(cfg.wait_selector, timeout=cfg.timeout * 1000)
        except PWError:
            log(f"  [warn] wait-selector not found: {cfg.wait_selector}")
    if cfg.dismiss_banners:
        for sel in ("#onetrust-accept-btn-handler", "#accept-recommended-btn-handler"):
            try:
                page.click(sel, timeout=1000)
                break
            except PWError:
                pass
        else:
            try:
                page.get_by_role("button", name=BANNER_RE).first.click(timeout=1500)
            except PWError:
                pass
        time.sleep(0.5)
    time.sleep(cfg.delay)


# --------------------------------------------------------------------------- capture
ACTIONS = {"click", "fill", "type", "press", "wait", "wait_for", "goto", "eval"}
HL_JS = ("els => els.slice(0, 10).forEach(e => { e.style.outline = '3px solid #e11'; "
         "e.style.outlineOffset = '3px'; e.style.boxShadow = '0 0 0 8px rgba(255,0,0,.2)'; })")


def load_steps(path):
    steps = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        act, _, rest = line.partition(" ")
        act = act.lower()
        if act not in ACTIONS:
            raise ValueError(f"steps: unknown action '{act}' (allowed: {', '.join(sorted(ACTIONS))})")
        if act in ("fill", "type"):
            sel, sep, val = rest.partition(" | ")
            if not sep:
                raise ValueError(f"steps: '{line}' needs the form: {act} <selector> | <value>")
            steps.append((act, sel.strip(), val))
        else:
            steps.append((act, rest.strip(), ""))
    return steps


def run_steps(page, steps, dlg):
    for i, (act, a, b) in enumerate(steps, 1):
        if dlg["open"]:                      # a dialog is open (kept for the shot): stop interacting
            break
        try:
            if act == "click":
                page.click(a)
            elif act == "fill":
                page.fill(a, b)
            elif act == "type":
                page.type(a, b)
            elif act == "press":
                page.keyboard.press(a)
            elif act == "wait":
                time.sleep(float(a))
            elif act == "wait_for":
                page.wait_for_selector(a)
            elif act == "goto":
                page.goto(a, wait_until="domcontentloaded")
            elif act == "eval":
                page.evaluate(a)
        except Exception as e:
            first = (str(e).splitlines() or [""])[0][:120]
            raise StepError(f"step {i} ({act} {a}) failed: {first}")
        if act in ("click", "press", "goto") and not dlg["open"]:
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except PWError:
                pass
        time.sleep(0.5)
    time.sleep(1.0)


def on_dialog(d, st, cfg):
    st["msgs"].append((d.type, d.message))
    if cfg.mode == "real":
        st["open"] = d          # leave it open: the real Chrome dialog is captured with the window
    else:
        d.accept()              # headless has no visible dialog: accept it and draw it onto the shot


def autoscroll(page):
    try:
        page.evaluate("""async () => {
            await new Promise(res => { let y = 0;
              const t = setInterval(() => { window.scrollBy(0, 700); y += 700;
                if (y >= document.documentElement.scrollHeight || y > 80000) { clearInterval(t); res(); } }, 120); });
            window.scrollTo(0, 0);
            await new Promise(r => setTimeout(r, 500)); }""")
        page.wait_for_load_state("networkidle", timeout=5000)
    except PWError:
        pass


def do_highlight(page, what):
    try:
        loc = None
        try:
            c = page.locator(what)
            if c.count():
                loc = c
        except PWError:
            pass                                   # not a valid CSS selector: treat as text
        if loc is None:
            t = page.get_by_text(what)
            if t.count():
                loc = t
        if loc is None:
            log(f"  [warn] --highlight: nothing matched '{what}'")
            return
        loc.first.scroll_into_view_if_needed()
        loc.evaluate_all(HL_JS)
        time.sleep(0.3)
    except PWError as e:
        log(f"  [warn] --highlight failed: {(str(e).splitlines() or [''])[0][:100]}")


def file_stem(url):
    p = urlparse(url)
    host = safe(p.hostname or "host")
    slug = safe((p.path.strip("/") + ("_" + p.query if p.query else "")).replace("/", "_"))[:80]
    return host, host + (f"_{slug}" if slug else "")


def safe(s):
    return re.sub(r"[^A-Za-z0-9.\-]", "_", s)


def capture_one(browser, url, target, cfg, scope, out_root):
    tls = ""
    real_keep = cfg.keep_dialogs and cfg.mode == "real"
    for ignore in (False, True):
        ctx = new_ctx(browser, cfg, url, ignore, scope)
        dlg = {"open": None, "msgs": []}
        try:
            page = ctx.new_page()
            hwnd = None
            if cfg.mode == "real":
                set_window(ctx, page, cfg)
                hwnd = find_chrome_window(page)
                if cfg.monitor:
                    move_to_monitor(hwnd, cfg.monitor)
            if cfg.keep_dialogs:
                page.on("dialog", lambda d: on_dialog(d, dlg, cfg))
            try:
                resp = page.goto(url, wait_until="commit" if real_keep else "domcontentloaded",
                                 timeout=cfg.timeout * 1000)
            except PWError as e:
                msg = str(e)
                if "ERR_BLOCKED_BY_CLIENT" in msg:
                    raise ScopeBlocked("navigation to out-of-scope host blocked")
                m = re.search(r"net::ERR_CERT_\w+", msg)
                if not ignore and m:
                    tls = m.group(0)       # retry once with cert errors ignored
                    continue
                raise
            if real_keep:                  # a load-time alert() freezes the page, so don't wait for load events
                time.sleep(2)
                if not dlg["open"]:
                    settle(page, cfg)
            else:
                settle(page, cfg)
            if not dlg["open"] and cfg.steps:
                run_steps(page, cfg.steps, dlg)
            if not dlg["open"]:
                if cfg.scroll:
                    autoscroll(page)
                if cfg.highlight:
                    do_highlight(page, cfg.highlight)

            final = page.url
            title = "" if dlg["open"] else page.title()
            status = resp.status if resp else ""
            state = "tls" if tls else ("https" if final.lower().startswith("https") else "http")

            if cfg.mode == "real":
                img = grab_window(hwnd, cfg)
            else:
                shot = Image.open(io.BytesIO(page.screenshot(full_page=cfg.full_page, scale="css"))).convert("RGB")
                img = chrome_frame(shot, final, title, state, dlg["msgs"][-1] if dlg["msgs"] else None)

            host, stem = file_stem(url)
            folder = out_root / host
            folder.mkdir(parents=True, exist_ok=True)
            png, n = folder / f"{stem}.png", 1
            while png.exists():
                png, n = folder / f"{stem}_{n}.png", n + 1
            img.save(png, "PNG")
            sha = hashlib.sha256(png.read_bytes()).hexdigest() if cfg.hash else ""
            return {"input": target, "final_url": final, "status": status, "title": title,
                    "tls_error": tls, "screenshot": png.relative_to(out_root).as_posix(),
                    "sha256": sha, "error": ""}
        finally:
            if dlg["open"]:
                try:
                    dlg["open"].dismiss()
                except Exception:
                    pass
            ctx.close()
    raise RuntimeError("capture failed")


def fail(target, reason):
    return {"input": target, "final_url": "", "status": "", "title": "", "tls_error": "",
            "screenshot": "", "sha256": "", "error": reason}


def process(browser, target, cfg, scope, out_root):
    cands = candidates(target)
    if not scope.allows(urlparse(cands[0]).hostname):
        return fail(target, "out of scope")
    if cfg.skip_existing:
        host, stem = file_stem(cands[0])
        f = out_root / host / f"{stem}.png"
        if f.exists():
            return {**fail(target, ""), "status": "skipped", "screenshot": f.relative_to(out_root).as_posix()}
    err = ""
    for url in cands:
        for _ in range(cfg.retries + 1):
            try:
                return capture_one(browser, url, target, cfg, scope, out_root)
            except (ScopeBlocked, StepError) as e:
                return fail(target, str(e))
            except Exception as e:
                first = (str(e).splitlines() or [type(e).__name__])[0][:200]
                err = f"{url}: {first}"
                if any(k in err for k in FAST_FAIL):
                    break
        if "ERR_NAME_NOT_RESOLVED" in err:
            break
    return fail(target, err)


# --------------------------------------------------------------------------- runner
def run(targets, cfg):
    _LOG[0] = sys.stderr if cfg.json_out else sys.stdout
    if cfg.device:
        if cfg.mode != "frame":
            raise ValueError("--device works with --mode frame only")
        with sync_playwright() as p0:
            dev = p0.devices.get(cfg.device)
            if not dev:
                names = sorted(n for n in p0.devices if "landscape" not in n)
                raise ValueError(f"unknown device '{cfg.device}'. Available: " + ", ".join(names))
            cfg.device_opts = {k: v for k, v in dev.items() if k != "default_browser_type"}
    scope = Scope(cfg.scope)
    out_root = Path(cfg.out)
    out_root.mkdir(parents=True, exist_ok=True)

    q = queue.Queue()
    for t in targets:
        q.put(t)
    total, rows, lock = len(targets), [], threading.Lock()

    def record(r):
        with lock:
            rows.append(r)
            tag = f"[{len(rows)}/{total}]"
            if r["error"]:
                log(f"{tag} [FAIL] {r['input']}  {r['error']}")
                with open(out_root / "Failed_URL.txt", "a", encoding="utf-8") as ff:
                    ff.write(f"{r['input']}\t{r['error']}\n")
            elif r["status"] == "skipped":
                log(f"{tag} [SKIP] {r['input']} (already captured)")
            else:
                log(f"{tag} [ OK ] {r['input']} -> {r['final_url']} [{r['status']}] {r['screenshot']}"
                    + (f"  (TLS ignored: {r['tls_error']})" if r["tls_error"] else ""))
                if cfg.hash and r["sha256"]:
                    with open(out_root / "SHA256SUMS.txt", "a", encoding="utf-8") as hf:
                        hf.write(f"{r['sha256']}  {r['screenshot']}\n")

    def worker():
        with sync_playwright() as p:
            browser = launch(p, cfg)
            try:
                while True:
                    try:
                        t = q.get_nowait()
                    except queue.Empty:
                        break
                    record(process(browser, t, cfg, scope, out_root))
            finally:
                browser.close()

    n = 1 if cfg.mode == "real" else max(1, min(cfg.threads, len(targets)))
    if n == 1:
        worker()
    else:
        with ThreadPoolExecutor(n) as ex:
            for f in [ex.submit(worker) for _ in range(n)]:
                f.result()

    skipped = sum(1 for r in rows if r["status"] == "skipped")
    failed = sum(1 for r in rows if r["error"])
    log(f"\nDone: {len(rows) - skipped - failed} captured, {skipped} skipped, {failed} failed -> {out_root}")
    return rows


# --------------------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="PoC screenshot tool (real Chrome window or drawn frame).")
    ap.add_argument("-u", "--url", action="append", help="target URL/host[:port] (repeatable)")
    ap.add_argument("-l", "--list", help="file of targets ('-' = stdin). httpx/subfinder/nmap -oG output OK")
    ap.add_argument("-o", "--out", default="evidence")
    ap.add_argument("-m", "--mode", choices=["real", "frame"], default="real")
    ap.add_argument("-t", "--threads", type=int, default=10, help="frame mode only")
    ap.add_argument("--full-page", action="store_true", help="frame mode only")
    ap.add_argument("--scroll", action="store_true", help="scroll the page first so lazy-loaded content appears")
    ap.add_argument("--width", type=int, default=1920, help="frame mode only (real mode is maximized)")
    ap.add_argument("--height", type=int, default=1080, help="frame mode only")
    ap.add_argument("--device", default="", help='frame mode only, e.g. "iPhone 14", "Pixel 7"')
    ap.add_argument("--monitor", type=int, default=0, help="real mode: run Chrome on monitor N (1 = primary)")
    ap.add_argument("--delay", type=float, default=2.0, help="seconds after network idle")
    ap.add_argument("--wait-selector", default="")
    ap.add_argument("--highlight", default="", help="CSS selector or text to box in red before capture")
    ap.add_argument("--steps", default="", help="file of interaction steps (click/fill/press/...) run before capture")
    ap.add_argument("--keep-dialogs", action="store_true", help="keep alert()/confirm()/prompt() boxes in the shot")
    ap.add_argument("--dismiss-banners", action="store_true")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--scope", default="", help="allowlist file: host, *.domain, IP, CIDR per line")
    ap.add_argument("--proxy", default="", help="e.g. http://127.0.0.1:8080")
    ap.add_argument("-H", "--header", action="append", default=[], help='"Name: value" (target host only)')
    ap.add_argument("--cookie", default="", help='"a=b; c=d" or path to Playwright-style JSON cookie file')
    ap.add_argument("--basic-auth", default="", help="user:pass")
    ap.add_argument("--ua", default="")
    ap.add_argument("--skip-existing", action="store_true", help="skip targets that already have a screenshot")
    ap.add_argument("--hash", action="store_true", help="write SHA256SUMS.txt (sha256sum format) next to the shots")
    ap.add_argument("--json", action="store_true", help="print results as JSON on stdout (logs go to stderr)")
    a = ap.parse_args()
    if a.json:
        _LOG[0] = sys.stderr

    targets = list(a.url or [])
    if a.list:
        src = sys.stdin if a.list == "-" else open(a.list, errors="ignore")
        for line in src:
            targets += parse_line(line)
    targets = list(dict.fromkeys(targets))
    if not targets:
        ap.error("no targets: use -u or -l")
    if a.mode == "real" and not IS_WIN:
        ap.error("real mode is Windows-only; use --mode frame")
    if a.mode == "real" and a.full_page:
        log("[warn] --full-page ignored in real mode (use --mode frame)")
    if a.mode == "real" and a.monitor:
        err = check_monitor(a.monitor)
        if err:
            ap.error(err)
    if a.mode == "frame" and a.monitor:
        log("[warn] --monitor ignored in frame mode")
    if a.device and a.mode != "frame":
        ap.error("--device works with --mode frame only")
    steps = []
    if a.steps:
        try:
            steps = load_steps(a.steps)
        except (OSError, ValueError) as e:
            ap.error(str(e))

    cfg = Config(mode=a.mode, out=a.out, threads=a.threads,
                 full_page=a.full_page and a.mode == "frame", width=a.width, height=a.height,
                 delay=a.delay, wait_selector=a.wait_selector, timeout=a.timeout, retries=a.retries,
                 scope=a.scope, proxy=a.proxy, headers=a.header, cookie=a.cookie,
                 basic_auth=a.basic_auth, ua=a.ua, dismiss_banners=a.dismiss_banners,
                 monitor=a.monitor if a.mode == "real" else 0, keep_dialogs=a.keep_dialogs,
                 scroll=a.scroll, highlight=a.highlight, steps=steps, skip_existing=a.skip_existing,
                 device=a.device, hash=a.hash, json_out=a.json)
    try:
        rows = run(targets, cfg)
    except ValueError as e:
        ap.error(str(e))
    if a.json:
        print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
