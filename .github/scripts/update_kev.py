import html
import json
import os
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

README = Path("README.md")
STATE = Path(".github/state/telegram-kev.json")
FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
START = "<!-- KEV:START -->"
END = "<!-- KEV:END -->"

request = urllib.request.Request(FEED_URL, headers={"User-Agent": "KEV-Monitor/1.0"})
with urllib.request.urlopen(request, timeout=30) as response:
    catalog = json.load(response)

items = sorted(catalog.get("vulnerabilities", []), key=lambda x: x.get("dateAdded", ""), reverse=True)[:5]
if not items:
    raise RuntimeError("CISA KEV feed returned no entries")

lines = [
    START,
    "<details>",
    "  <summary><b>Latest Exploited Vulnerabilities 🦠</b></summary>",
    "  <p></p>",
    f"  <p><sub>Auto-updated hourly · Last update: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</sub></p>",
    "  <p></p>",
]
for item in items:
    cve = item["cveID"]
    name = item.get("vulnerabilityName", "Known exploited vulnerability")
    product = f"{item.get('vendorProject', 'Unknown')} / {item.get('product', 'Unknown')}"
    date_added = item.get("dateAdded", "Unknown")
    lines.append(f"  <p><a href=\"https://nvd.nist.gov/vuln/detail/{cve}\"><b>{cve}</b></a> · {name} · {product} · {date_added}</p>")
lines += [
    "  <p><sub>Source: CISA KEV</sub></p>",
    "</details>",
    END,
]

content = README.read_text(encoding="utf-8")
if START not in content or END not in content:
    raise RuntimeError("README KEV markers are missing")
start = content.index(START)
end = content.index(END) + len(END)
published_cves = set(json.loads(STATE.read_text(encoding="utf-8"))) if STATE.exists() else set()
new_items = [item for item in items if item.get("cveID") not in published_cves]
updated_content = content[:start] + "\n".join(lines) + content[end:]
if updated_content != content:
    README.write_text(updated_content, encoding="utf-8")

if new_items:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        raise RuntimeError("New exploited vulnerabilities found, but TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is missing")

    message = ["<b>🦠 Latest Exploited Vulnerabilities</b>", ""]
    for item in new_items:
        cve = html.escape(item["cveID"])
        name = html.escape(item.get("vulnerabilityName", "Known exploited vulnerability"))
        vendor = html.escape(item.get("vendorProject", "Unknown"))
        product = html.escape(item.get("product", "Unknown"))
        date_added = html.escape(item.get("dateAdded", "Unknown"))
        link = f"https://nvd.nist.gov/vuln/detail/{cve}"
        message.extend([
            f'<a href="{link}"><b>{cve}</b></a> · {name}',
            f'{vendor} / {product} · Added: {date_added}',
            "",
        ])

    message.extend(["", "<i>Source: CISA KEV</i>"])

    payload = json.dumps({
        "chat_id": chat_id,
        "text": "\n".join(message).strip(),
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=25) as response:
        result = json.load(response)
    if not result.get("ok"):
        raise RuntimeError(f"Telegram rejected vulnerability post: {result}")
    print(f"Published {len(new_items)} new exploited vulnerability item(s) to Telegram")

published_cves.update(item["cveID"] for item in items)
STATE.parent.mkdir(parents=True, exist_ok=True)
STATE.write_text(json.dumps(sorted(published_cves)[-1000:], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
if not new_items:
    print("No new exploited vulnerabilities; Telegram post skipped")
