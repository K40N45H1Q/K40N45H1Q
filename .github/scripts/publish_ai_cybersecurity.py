import html
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import time
from pathlib import Path

STATE = Path(".github/state/ai-cybersecurity-posts.json")

# Curated facts and primary references keep the posts focused and verifiable.
PROTOCOLS = [
    {
        "id": "tls",
        "name": "TLS",
        "facts": "TLS protects data in transit. Main risks include obsolete SSL/TLS versions and weak cipher suites, certificate validation failures, and implementation flaws. TLS 1.3 removes many legacy cryptographic options; operators should disable obsolete versions, validate certificates, and keep TLS libraries patched.",
        "source": "https://datatracker.ietf.org/doc/html/rfc8446"
    },
    {
        "id": "dns",
        "name": "DNS",
        "facts": "DNS translates domain names to IP addresses. Risks include cache poisoning and spoofed responses when transaction validation is weak, plus privacy exposure because traditional DNS queries are often unencrypted. Use DNSSEC validation where appropriate and encrypted DNS transport when the threat model requires it.",
        "source": "https://www.rfc-editor.org/rfc/rfc4033"
    },
    {
        "id": "bgp",
        "name": "BGP",
        "facts": "BGP exchanges routing information between autonomous systems. Its original trust model does not inherently authenticate route announcements, enabling route leaks and prefix hijacks. Filtering, RPKI Route Origin Validation, and monitoring reduce risk, but RPKI does not solve every path-security problem.",
        "source": "https://www.rfc-editor.org/rfc/rfc6811"
    },
    {
        "id": "http2",
        "name": "HTTP/2",
        "facts": "HTTP/2 multiplexes many requests over one connection. Poorly managed implementations can be exposed to resource exhaustion, including rapid-reset-style denial of service. Keep server and proxy software patched, enforce concurrency and rate limits, and monitor connection-level resource use.",
        "source": "https://www.cve.org/CVERecord?id=CVE-2023-44487"
    },
    {
        "id": "oauth2",
        "name": "OAuth 2.0",
        "facts": "OAuth 2.0 delegates authorization without sharing a user's password with the client. Common risks include redirect URI validation errors, leaked bearer tokens, and misuse of the implicit flow. Use exact redirect URI matching, short-lived tokens, secure storage, and Authorization Code with PKCE for public clients.",
        "source": "https://www.rfc-editor.org/rfc/rfc9700"
    },
    {
        "id": "ssh",
        "name": "SSH",
        "facts": "SSH provides encrypted remote access. Risks include accepting unverified host keys, exposed private keys, password guessing, and outdated implementations. Verify host keys, protect keys with appropriate permissions and passphrases, prefer strong authentication, restrict access, and keep the server updated.",
        "source": "https://www.openssh.com/security.html"
    },
    {
        "id": "smb",
        "name": "SMB",
        "facts": "SMB provides network file and printer sharing, especially on Windows networks. Exposed SMB services and unpatched implementations have enabled serious remote attacks; SMBv1 is obsolete. Disable SMBv1, patch systems, block internet exposure, restrict access, and require signing or encryption where appropriate.",
        "source": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security"
    },
    {
        "id": "kerberos",
        "name": "Kerberos",
        "facts": "Kerberos uses tickets for network authentication. Risks include ticket theft, password-based attacks against service accounts, and weak account secrets that enable offline cracking. Use long random service-account secrets or managed accounts, minimize privileges, monitor ticket activity, and protect endpoints where tickets are stored.",
        "source": "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview"
    },
    {
        "id": "mqtt",
        "name": "MQTT",
        "facts": "MQTT is a lightweight publish/subscribe protocol common in IoT. The protocol itself does not guarantee that deployments enforce authentication, authorization, or encryption. Public brokers and overly broad topic permissions can expose data or allow device control. Require TLS, authenticate clients, and apply per-topic access control.",
        "source": "https://mqtt.org/mqtt-specification/"
    },
    {
        "id": "snmp",
        "name": "SNMP",
        "facts": "SNMP monitors and manages network devices. SNMPv1 and v2c use community strings that are not encrypted, so credentials and management data can be exposed. Prefer SNMPv3 with authentication and privacy, restrict management access by network, and rotate credentials.",
        "source": "https://www.rfc-editor.org/rfc/rfc3414"
    },
    {
        "id": "ipsec",
        "name": "IPsec",
        "facts": "IPsec secures IP traffic and is widely used for VPNs. Risk comes from weak or outdated cryptographic settings, poor key management, and permissive tunnel policies rather than encryption alone. Use modern algorithms, strong authentication, timely updates, and narrowly scoped security policies.",
        "source": "https://www.rfc-editor.org/rfc/rfc7296"
    },
    {
        "id": "quic",
        "name": "QUIC",
        "facts": "QUIC transports streams over UDP and underpins HTTP/3, integrating TLS 1.3 security. Risks include denial of service through resource exhaustion and deployment mistakes around address validation or rate limits. Keep implementations patched and apply anti-amplification protections and sensible resource limits.",
        "source": "https://www.rfc-editor.org/rfc/rfc9000"
    },
    {
        "id": "websocket",
        "name": "WebSocket",
        "facts": "WebSocket keeps a two-way connection open between a browser and server. Security failures often involve missing Origin checks, weak authentication, and accepting untrusted messages, which can lead to cross-site WebSocket hijacking or application-level injection. Validate Origin, authorize each action, and validate message data.",
        "source": "https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html"
    },
    {
        "id": "ftp",
        "name": "FTP",
        "facts": "Traditional FTP sends credentials and data without encryption, exposing them to network interception. Plain FTP should not be used across untrusted networks. Replace it with SFTP or FTPS, disable anonymous access unless explicitly required, and restrict file permissions.",
        "source": "https://www.rfc-editor.org/rfc/rfc959"
    },
    {
        "id": "ldap",
        "name": "LDAP",
        "facts": "LDAP provides directory access and is often used for identity lookups. Risks include cleartext binds without TLS, injection through unescaped filter input, and excessive directory permissions. Use TLS, escape user-controlled filter values, enforce least privilege, and avoid exposing directory services publicly.",
        "source": "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
    },
    {
        "id": "ntp",
        "name": "NTP",
        "facts": "NTP synchronizes system clocks, which are important for logs, certificates, and authentication. Misconfigured or exposed servers can be abused for reflection/amplification attacks, and incorrect time can undermine security controls. Patch NTP software, restrict queries and administration, and use trusted time sources.",
        "source": "https://www.cisa.gov/news-events/alerts/2014/01/14/udp-based-amplification-attacks"
    },
    {
        "id": "rdp",
        "name": "RDP",
        "facts": "RDP enables remote desktop access. Internet-exposed services face password attacks and exploitation of unpatched vulnerabilities; weak access controls can turn one account into a foothold. Avoid direct internet exposure, use VPN or a secure gateway, enable MFA, restrict source networks, and patch promptly.",
        "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    },
    {
        "id": "smtp",
        "name": "SMTP",
        "facts": "SMTP transfers email between servers. Risks include unauthenticated open relays, spoofing when sender validation is weak, and downgrade or interception risks when TLS is not enforced. Disable open relay, configure SPF, DKIM and DMARC, and use modern TLS policies appropriate to the mail environment.",
        "source": "https://www.rfc-editor.org/rfc/rfc5321"
    },
    {
        "id": "saml",
        "name": "SAML",
        "facts": "SAML exchanges authentication assertions between an identity provider and a service provider. Incorrect XML signature validation, assertion audience or recipient checks, and replay protection can allow authentication bypass. Use maintained libraries and validate signatures, issuer, audience, recipient, time limits, and request correlation.",
        "source": "https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html"
    },
    {
        "id": "ntlm",
        "name": "NTLM",
        "facts": "NTLM is a legacy Windows authentication protocol. It is vulnerable to relay-style attacks in environments lacking protections, and password hashes can be targeted with offline cracking. Prefer Kerberos where possible, enable protections such as SMB signing and Extended Protection where supported, and reduce NTLM usage.",
        "source": "https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview"
    }
]

def get_json(url, payload=None, timeout=35, retries=0):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"},
        method="POST" if data else "GET"
    )
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code not in (429, 500, 502, 503, 504) or attempt >= retries:
                body = error.read().decode("utf-8", errors="replace")[:1000]
                raise RuntimeError(
                    f"HTTP {error.code} from {urllib.parse.urlsplit(url).hostname}: {body}"
                ) from error
            retry_after = error.headers.get("Retry-After")
            delay = min(int(retry_after), 60) if retry_after and retry_after.isdigit() else min(2 ** attempt, 30)
            print(f"Temporary HTTP {error.code}; retrying in {delay}s ({attempt + 1}/{retries})")
            time.sleep(delay)

state = json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else []
if not isinstance(state, list):
    raise RuntimeError("Post history must be a JSON list")
seen = set(state)
protocol = next((p for p in PROTOCOLS if p["id"] not in seen), None)

if protocol is None:
    print("All curated protocols have been covered; add more topics to PROTOCOLS.")
    raise SystemExit(0)

prompt = f"""Write a FULL-LENGTH English Telegram cybersecurity article for developers and security professionals about the protocol {protocol['name']}.
Use only the facts below. Do not add vulnerabilities, CVEs, incidents, or claims not listed.
Use this structure: (1) explain what the protocol does, how it works, and where it is used; (2) provide exactly five numbered major security vulnerabilities, each with the weakness, a high-level abuse scenario, and potential impact; (3) provide practical mitigations; (4) conclude with the key takeaway. Do not claim a universal statistical ranking and do not invent facts.
Write 350-450 words and never exceed 3200 characters. Keep each risk concise. Use these exact section headings: "Protocol Overview", "Top 5 Security Risks", "Mitigations", and "Conclusion". Put each heading on its own line in <b> tags. Number the five risks exactly 1. through 5., each on a separate line. Stop immediately after the source link; do not add extra sections or commentary. Format as a bold title followed by these sections and numbered items using Telegram HTML (<b> only). Include the source as a clickable link on the final line. No hashtags, no generic intro, no markdown fences.

FACTS:
{protocol['facts']}

SOURCE URL: {protocol['source']}
"""
model = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
api = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    + urllib.parse.quote(model, safe="")
    + ":generateContent?key="
    + urllib.parse.quote(os.environ["GEMINI_API_KEY"], safe="")
)
required_sections = ("Protocol Overview", "Top 5 Security Risks", "Mitigations", "Conclusion")
article = None
last_error = "unknown validation error"

for generation_attempt in range(1, 4):
    attempt_prompt = prompt
    if generation_attempt > 1:
        attempt_prompt += (
            "\n\nRETRY REQUIREMENTS: Your previous response failed validation. "
            "Use the four exact section headings specified above, include five separate numbered risks (1. to 5.), "
            "and keep the complete article under 3200 characters."
        )
    result = get_json(api, {
        "contents": [{"parts": [{"text": attempt_prompt}]}],
        "generationConfig": {"maxOutputTokens": 4096, "thinkingConfig": {"thinkingLevel": "low"}}
    }, timeout=120, retries=5)

    try:
        candidate = result["candidates"][0]["content"]["parts"][0]["text"].strip()
        finish_reason = result["candidates"][0].get("finishReason", "STOP")
    except (KeyError, IndexError, TypeError):
        last_error = "Gemini returned no article"
        print(f"Generation attempt {generation_attempt}/3 failed: {last_error}")
        continue

    candidate = candidate.replace("```html", "").replace("```", "").strip()
    plain_text = re.sub(r"<[^>]+>", " ", candidate)
    missing_sections = [section for section in required_sections if section.lower() not in plain_text.lower()]
    numbered_risks = re.findall(r"(?m)^\s*[1-5]\.\s+", plain_text)
    if finish_reason != "STOP":
        last_error = "Gemini output truncated (finishReason=" + str(finish_reason) + ")"
    elif missing_sections:
        last_error = "missing required sections: " + ", ".join(missing_sections)
    elif len(numbered_risks) != 5:
        last_error = "expected exactly five separately numbered risks; found " + str(len(numbered_risks))
    elif len(candidate) < 900:
        last_error = "article too short (" + str(len(candidate)) + " characters)"
    elif len(candidate) > 3900:
        last_error = "article exceeds Telegram's message limit (" + str(len(candidate)) + " characters)"
    else:
        article = candidate
        break

    print(f"Generation attempt {generation_attempt}/3 rejected: {last_error}")

if article is None:
    raise RuntimeError("Gemini failed article validation after 3 attempts: " + last_error + "; nothing was published")

if protocol["source"] not in article:
    article += '\n\n🔎 <a href="' + html.escape(protocol["source"], quote=True) + '">Source</a>'
if len(article) > 3900:
    raise RuntimeError("Generated article exceeds Telegram's message limit; nothing was published")

telegram = get_json(
    "https://api.telegram.org/bot" + os.environ["TELEGRAM_BOT_TOKEN"] + "/sendMessage",
    {
        "chat_id": os.environ["TELEGRAM_CHAT_ID"],
        "text": article,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    },
    timeout=35
)
if not telegram.get("ok"):
    raise RuntimeError("Telegram rejected the article: " + json.dumps(telegram)[:1000])

state.append(protocol["id"])
STATE.parent.mkdir(parents=True, exist_ok=True)
STATE.write_text(json.dumps(state[-500:], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print("Published protocol explainer: " + protocol["name"])
