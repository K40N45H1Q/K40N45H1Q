import html
import json
import os
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

README = Path("README.md")
STATE = Path(".github/state/telegram-news.json")
START = "<!-- CYBERNEWS:START -->"
END = "<!-- CYBERNEWS:END -->"
FEEDS = [
    ("Reuters", "https://news.google.com/rss/search?q=site%3Areuters.com+cyberattack+OR+ransomware+OR+%22data+breach%22&hl=en-US&gl=US&ceid=US:en"),
    ("Associated Press", "https://flipboard.com/@associatedpress/technology-uvt65hdqz.rss"),
]
KEYWORDS = re.compile(r"cyberattack|cyber attack|ransomware|data breach|hacked|hackers|cybercrime|stolen data|extortion|malware|intrusion|data leak", re.I)


def clean(value):
    value = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


articles = []
for source, url in FEEDS:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Cybercrime-News/1.0"})
        with urllib.request.urlopen(request, timeout=25) as response:
            root = ET.fromstring(response.read())
        for item in root.findall(".//item"):
            title = clean(item.findtext("title"))
            link = clean(item.findtext("link"))
            description = clean(item.findtext("description"))
            pub_date = item.findtext("pubDate") or ""
            if not title or not link or not KEYWORDS.search(title + " " + description):
                continue
            try:
                published = parsedate_to_datetime(pub_date)
                if published.tzinfo is None:
                    published = published.replace(tzinfo=timezone.utc)
                published = published.astimezone(timezone.utc)
            except (TypeError, ValueError, OverflowError):
                continue
            articles.append({
                "title": title,
                "link": link,
                "description": description,
                "date": published,
                "source": source,
            })
    except Exception as error:
        print(f"Feed unavailable ({source}): {error}")

articles.sort(key=lambda article: article["date"], reverse=True)
selected = []
seen = set()
for article in articles:
    key = re.sub(r"[^a-z0-9]", "", article["title"].lower())
    if key in seen:
        continue
    seen.add(key)
    selected.append(article)
    if len(selected) == 5:
        break

if not selected:
    raise RuntimeError("No matching cybercrime news found; README was not changed")

lines = [
    START,
    "<details>",
    "  <summary><b>Latest Cybercrime & Attack News 📰</b></summary>",
    "  <p></p>",
    f"  <p><sub>Auto-updated hourly · Last update: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</sub></p>",
    "  <p></p>",
]
for article in selected:
    date = article["date"].strftime("%Y-%m-%d")
    summary = article["description"]
    if len(summary) > 180:
        summary = summary[:177].rsplit(" ", 1)[0] + "..."
    detail = f" · {summary}" if summary else ""
    lines.append(f'  <p><a href="{article["link"]}"><b>{article["title"]}</b></a> · {article["source"]} · {date}{detail}</p>')
sources = " · ".join(sorted({article["source"] for article in selected}))
lines += [f"  <p><sub>Sources: {sources}</sub></p>", "</details>", END]

content = README.read_text(encoding="utf-8")
if START not in content or END not in content:
    raise RuntimeError("Cybercrime news markers are missing")
start = content.index(START)
end = content.index(END) + len(END)
published_links = set(json.loads(STATE.read_text(encoding="utf-8"))) if STATE.exists() else set()
new_articles = [article for article in selected if article["link"] not in published_links]
updated = content[:start] + "\n".join(lines) + content[end:]
if updated != content:
    README.write_text(updated, encoding="utf-8")

if new_articles:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        raise RuntimeError("New cybercrime news found, but TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is missing")

    message = ["<b>📰 Cybercrime & Attack News</b>", ""]
    for article in new_articles:
        title = html.escape(article["title"])
        link = html.escape(article["link"], quote=True)
        source = html.escape(article["source"])
        date = article["date"].strftime("%Y-%m-%d")
        summary = article["description"]
        if len(summary) > 180:
            summary = summary[:177].rsplit(" ", 1)[0] + "..."
        entry = f'<a href="{link}"><b>{title}</b></a>\n{source} · {date}'
        if summary:
            entry += f'\n{html.escape(summary)}'
        message.extend([entry, ""])

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
        raise RuntimeError(f"Telegram rejected cybercrime post: {result}")
    print(f"Published {len(new_articles)} new cybercrime item(s) to Telegram")

published_links.update(article["link"] for article in selected)
STATE.parent.mkdir(parents=True, exist_ok=True)
STATE.write_text(json.dumps(sorted(published_links)[-500:], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
if not new_articles:
    print("No new cybercrime items; Telegram post skipped")
