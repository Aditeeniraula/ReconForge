# Getting Started on Windows

A step-by-step guide to running ReconForge on Windows 10/11. No prior setup is
assumed beyond installing Python.

---

## 1. What you need to download

| Requirement | Needed for | Notes |
|---|---|---|
| **Python 3.11 or newer** | Running everything | The project was built and tested on Python 3.14. |
| **pytest + pytest-asyncio** | Running the test suite (optional) | Only if you want to run `pytest`. Not needed to scan. |

**The tool itself has ZERO third-party dependencies** — it uses only the Python
standard library. You do *not* need pip, a virtual environment, or any install
step to run a scan. You only need pip if you want to run the automated tests.

### Install Python (if you don't have it)

1. Go to <https://www.python.org/downloads/> and download the latest Windows installer.
2. Run it and **tick "Add python.exe to PATH"** on the first screen before clicking Install.
3. Open a new **PowerShell** window and confirm it works:

   ```powershell
   python --version
   ```

   You should see `Python 3.11.x` or higher. (On some systems the command is `py`
   instead of `python` — either works; use whichever prints a version.)

---

## 2. Get the project

If you already have the `reconforge` folder, just open PowerShell there:

```powershell
cd C:\Users\Public\Projects\reconforge
```

---

## 3. Run it (the 60-second demo)

The project ships with a **harmless local target** so you can see it work without
touching any real system. You need **two PowerShell windows**.

**Window 1 — start the demo target:**

```powershell
cd C:\Users\Public\Projects\reconforge
python demo_target.py
```

Leave this running. It binds three loopback ports (127.0.0.1) that pretend to be a
vulnerable SSH, Redis, and web server. Nothing here is a real service.

**Window 2 — scan it and build reports:**

```powershell
cd C:\Users\Public\Projects\reconforge
python -m reconforge 127.0.0.1 --ports 2222,6380,8088 --html report.html --json report.json
```

You'll see a findings table in the terminal, and two files appear in the folder:

- `report.html` — open it in your browser (double-click, or `start report.html`)
- `report.json` — machine-readable results

When you're done, press **Ctrl+C** in Window 1 to stop the demo target.

> Note: the scan command exits with code `1` when it finds high/critical issues.
> That's intentional (useful in CI) — it does **not** mean an error occurred.

---

## 4. Scanning your own targets

**Your own lab / private network** (localhost, 10.x, 192.168.x, etc.) works with no
extra flags:

```powershell
python -m reconforge 192.168.1.10 --top --html home-server.html
```

**A public/internet target** is refused unless you prove authorization — both list
it in scope **and** pass the acknowledgement flag:

```powershell
python -m reconforge assets.example.com --scope assets.example.com --i-am-authorized
```

> ⚠️ Only scan systems you own or have **written permission** to test. Unauthorized
> scanning is illegal in most places. The scope gate exists to stop accidents, not
> to grant permission.

### Useful options

```
--top                     scan the built-in high-signal port set (default)
--ports 22,80,8000-8100   custom ports and ranges
--all                     scan all 65,535 TCP ports (slow)
--concurrency 400         more simultaneous connections = faster
--timeout 2.0             per-port connect timeout in seconds
--json PATH / --html PATH write reports
```

---

## 5. Running the tests (optional)

Only if you want to verify everything yourself:

```powershell
cd C:\Users\Public\Projects\reconforge
python -m pip install -r requirements.txt
python -m pytest -q
```

Expected result: **18 passed**.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` not recognized | Reinstall Python with "Add to PATH" ticked, or use `py` instead. |
| `No module named reconforge` | Make sure you `cd` into the `reconforge` project folder first. |
| Scan of a public IP says "refused" | That's the scope gate working — add `--scope <target> --i-am-authorized`. |
| Demo scan finds nothing | Confirm Window 1 (`demo_target.py`) is still running. |
| `pytest` not found | Run `python -m pip install -r requirements.txt` first. |
