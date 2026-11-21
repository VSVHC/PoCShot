# PoCShot - PoC Screenshot Tool

Takes proof-of-concept screenshots of web pages with a proper browser address bar (URL, padlock, tab).
Built for authorized penetration testing and red team evidence.

Two capture modes:

| Mode | How it works | Address bar | Speed | Blocks your PC |
|---|---|---|---|---|
| `real` (default) | Opens headed Chrome, maximized, and captures the window from the screen | Real Chrome | One target at a time | Yes (unless `--monitor N`) |
| `frame` | Headless Chrome in the background, page screenshot wrapped in a drawn Chrome-style frame | Drawn by the tool | Parallel (`-t`) | No |

Use `real` for report-grade PoCs. Use `frame` for bulk work.

---

## 1. Requirements

- Windows 11 for `real` mode. `frame` mode also runs on Linux and macOS.
- Python 3.9+
- Google Chrome installed (the tool launches your installed Chrome)

## 2. Installation

```
pip install -r requirements.txt
```

Or manually: `pip install playwright pillow mss`

If Chrome is not installed, `frame` mode can use Playwright's bundled Chromium:

```
playwright install chromium
```

Put `poc_shot.py` anywhere and run it from that folder.

## 3. Quick start

```
python poc_shot.py -u https://example.com                  # real Chrome window
python poc_shot.py -u example.com --mode frame             # background, no window
python poc_shot.py -l urls.txt --mode frame                # many targets from a file
python poc_shot.py -l urls.txt --mode frame -t 6           # faster, 6 at a time
```

Output goes to `evidence/<domain>/<domain>_<page>.png`.

---

## 4. Targets

Give targets with `-u` (repeatable) or `-l file` (`-l -` reads stdin).

Accepted formats, one per line in a list file:

- Full URL: `https://example.com/login`
- Bare domain: `example.com` (tries `https://` first, then `http://`)
- Host and port: `10.0.0.1:8443`
- httpx output (text or `-json`)
- subfinder output (text or `-json`)
- nmap greppable output (`-oG`): open web ports become `http(s)://host:port`

Lines starting with `#` are ignored. Duplicates are removed.

```
httpx -l hosts.txt | python poc_shot.py -l - --mode frame
```

## 5. Output

```
evidence/
  Failed_URL.txt                      only created if something fails (appended on each run)
  SHA256SUMS.txt                      only with --hash
  example.com/
    example.com.png                   homepage
    example.com_login.png             /login
    example.com_admin_users.png       /admin/users
```

- One PNG per target. Folder is the domain only.
- If a file name already exists, the new shot is saved as `name_1.png`, `name_2.png`, and so on. Nothing is overwritten.
- `Failed_URL.txt` lines: `target<TAB>reason`.
- `SHA256SUMS.txt` is in `sha256sum` format. Verify with `cd evidence && sha256sum -c SHA256SUMS.txt`.

---

## 6. Options

### Capture

| Option | Default | Description |
|---|---|---|
| `-u, --url` | | Target (repeatable) |
| `-l, --list` | | File of targets, `-` for stdin |
| `-o, --out` | `evidence` | Output folder |
| `-m, --mode` | `real` | `real` or `frame` |
| `-t, --threads` | `10` | Parallel captures (frame mode only). Capped at the number of targets |
| `--full-page` | off | Capture the whole scrolling page (frame mode only) |
| `--scroll` | off | Scroll the page first so lazy-loaded content appears |
| `--width`, `--height` | `1920`, `1080` | Viewport size (frame mode only). Real mode is always maximized |
| `--device "NAME"` | | Mobile emulation, e.g. `"iPhone 14"`, `"Pixel 7"` (frame mode only) |
| `--monitor N` | off | Real mode: run Chrome on monitor N (1 = primary) so you can keep working on another screen |

### Page timing and cleanup

| Option | Default | Description |
|---|---|---|
| `--delay` | `2` | Seconds to wait after the page is idle |
| `--wait-selector "CSS"` | | Wait until this element appears |
| `--dismiss-banners` | off | Click common cookie-accept buttons |
| `--timeout` | `30` | Page timeout in seconds |
| `--retries` | `2` | Retries per target |

### Evidence helpers

| Option | Description |
|---|---|
| `--highlight "text or CSS"` | Draws a red box around matching elements (up to 10) and scrolls the first into view |
| `--keep-dialogs` | Keep `alert()`, `confirm()` and `prompt()` boxes in the shot (see notes) |
| `--steps FILE` | Run interaction steps (click, fill, ...) before capture |
| `--hash` | Write `SHA256SUMS.txt` |
| `--skip-existing` | Skip targets that already have a screenshot (resume a big list) |
| `--json` | Print results as JSON on stdout. Logs go to stderr |

### Network and auth

| Option | Description |
|---|---|
| `--scope FILE` | Allowlist file. Anything outside is skipped or blocked |
| `--proxy URL` | e.g. `http://127.0.0.1:8080` (Burp) |
| `-H "Name: value"` | Extra request header (repeatable). Sent only to the target host |
| `--cookie "a=b; c=d"` | Cookies for the target, or a path to a Playwright-style JSON cookie file |
| `--basic-auth user:pass` | HTTP Basic auth |
| `--ua "..."` | Custom User-Agent |

---

## 7. Scope file

One entry per line. `#` starts a comment.

```
example.com          # exactly this host
*.example.com        # subdomains only (not example.com itself)
10.0.0.5             # single IP
10.0.1.0/24          # CIDR range
```

```
python poc_shot.py -l urls.txt --mode frame --scope scope.txt
```

- Out-of-scope targets are not visited and go to `Failed_URL.txt` as `out of scope`.
- Redirects to out-of-scope hosts are blocked before the request is made.
- Without `--scope`, nothing is checked.

## 8. Steps file (interactions)

Runs after the page loads and before the screenshot. One step per line.

```
# steps.txt
fill #user | admin
fill #pass | Password1
click button[type=submit]
press Enter
wait 2
wait_for #dashboard
```

| Step | Format |
|---|---|
| `click` | `click <selector>` |
| `fill` | `fill <selector> \| <value>` |
| `type` | `type <selector> \| <value>` (key by key) |
| `press` | `press <key>` e.g. `Enter` |
| `wait` | `wait <seconds>` |
| `wait_for` | `wait_for <selector>` |
| `goto` | `goto <url>` |
| `eval` | `eval <javascript>` |

```
python poc_shot.py -u https://target.com/login --steps steps.txt --highlight "Welcome admin"
```

- A failed step marks the target as failed and does not retry.
- The same steps run on every target, so use it with a single `-u` URL.
- Order of operations: load, steps, `--scroll`, `--highlight`, capture.

---

## 9. Use cases

**Single PoC with the real address bar**
```
python poc_shot.py -u https://target.com/vuln-page
```

**Real address bar without blocking your main screen** (needs a second monitor)
```
python poc_shot.py -u https://target.com/vuln-page --monitor 2
```

**Bulk recon screenshots**
```
python poc_shot.py -l urls.txt --mode frame -t 10 --scroll --full-page
```

**Pipeline from httpx or nmap**
```
httpx -l hosts.txt | python poc_shot.py -l - --mode frame
python poc_shot.py -l nmap.gnmap --mode frame
```

**Reflected XSS, alert box in the shot**
```
python poc_shot.py -u "https://target.com/?q=PAYLOAD" --keep-dialogs
```

**Highlight an exposed value or error**
```
python poc_shot.py -u https://target.com/debug --highlight "stack trace"
python poc_shot.py -u https://target.com/config --highlight "#api-key"
```

**Logged-in page**
```
python poc_shot.py -u https://target.com/account -H "Authorization: Bearer TOKEN" --cookie "sid=abc"
python poc_shot.py -u https://target.com/admin --basic-auth user:pass
```

**Through Burp**
```
python poc_shot.py -u target.com --proxy http://127.0.0.1:8080
```

**Mobile layout finding**
```
python poc_shot.py -u target.com --mode frame --device "iPhone 14"
```

**Resume an interrupted bulk run**
```
python poc_shot.py -l urls.txt --mode frame --skip-existing
```

**Chain of custody**
```
python poc_shot.py -l urls.txt --mode frame --hash
```

**Results for other tools**
```
python poc_shot.py -l urls.txt --mode frame --json > results.json
```

---

## 10. JSON output

`--json` prints a list of objects:

```
input, final_url, status, title, tls_error, screenshot, sha256, error
```

`status` is the HTTP code, or `skipped` for `--skip-existing`. `error` is empty on success. `tls_error` is set when the page only loaded after certificate errors were ignored.

## 11. Use as a Python module

```python
from poc_shot import Config, run

rows = run(["https://example.com", "10.0.0.1:8443"], Config(mode="frame", threads=5))
```

`Config` fields mirror the command-line options.

---

## 12. How it behaves

- **Bare targets:** tries `https://` first, then `http://`. Port 80 tries `http://` first.
- **Certificate errors:** loads strictly first. On a certificate error it retries once with errors ignored, so self-signed and expired certs still get captured. The console and JSON show which targets needed this.
- **Redirects:** followed. The address bar shows the final URL.
- **Retries:** failed targets retry up to `--retries` times. Connection refused and DNS failures skip retries.
- **Real mode:** one target at a time. The window is brought to the front and captured, the mouse is parked in the tab strip so no tooltip appears, and the taskbar is not included.

## 13. Notes and limits

- **Real mode blocks your screen.** Don't use the PC while it runs, or use `--monitor N`. Parallel windows would overlap, so `-t` is ignored in real mode.
- **Frame mode draws the address bar.** It looks like Chrome but is drawn by the tool. If a client needs proof the bar is genuine, use real mode.
- **`--full-page` and `--device` are frame mode only.** A real window only shows what is on screen.
- **`--keep-dialogs`:** in real mode the actual Chrome dialog stays open and is captured. In frame mode headless Chrome cannot show dialogs, so the tool draws a Chrome-style box from the real message. It is a rendering, not a capture.
- **Padlock after ignored certificate errors (real mode):** Chrome may show a different state than for a normal bad cert. Check one result visually.
- **Display scaling:** with monitors of different scaling, `--monitor` placement may be off.
- **`-t` and RAM:** each worker runs its own Chrome. Keep `-t` around 5 to 20.
- **Filenames** use the page path, not the port or a timestamp. Same path on two ports of one domain gets a `_1` suffix.

## 14. Troubleshooting

| Problem | Fix |
|---|---|
| `Chrome window not found` | Window was minimized or on another virtual desktop. Re-run and leave it alone |
| Black or wrong-area screenshot | Close windows overlapping the screen, or use `--monitor 2` |
| Lazy images or sections blank | Add `--scroll` |
| Page not finished loading | Increase `--delay` or use `--wait-selector` |
| Cookie banner covers the page | Add `--dismiss-banners` |
| `ERR_NAME_NOT_RESOLVED` | Wrong domain or no DNS. Check `Failed_URL.txt` |
| Targets missing from the result | Check `--scope`. Out-of-scope targets are skipped |
| `real mode is Windows-only` | Use `--mode frame` on Linux or macOS |
| `--monitor N invalid` | The message shows how many monitors were found |
| Out of memory with many threads | Lower `-t` |

## 15. Responsible use

For authorized testing only. Use `--scope` to keep captures inside the engagement scope, and make sure you have written permission for every target.
