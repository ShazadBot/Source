
import os, re, io, json, socket, asyncio, ipaddress, mimetypes, logging, hashlib
from pathlib import PurePosixPath
from urllib.parse import urlparse, urljoin, unquote

import httpx
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
MAX_FILE = 5 * 1024 * 1024
MAX_TOTAL = 25 * 1024 * 1024
MAX_FILES = 60
MAX_PAGES = 6
TIMEOUT = 12
UA = "ShbloodWebsiteScanner/1.0"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("shblood-scanner")

CSS_URL = re.compile(r"url\(\s*[\x22\x27]?(.*?)[\x22\x27]?\s*\)", re.I)
CSS_IMPORT = re.compile(r"@import\s+(?:url\()?[\x22\x27](.*?)[\x22\x27]\)?", re.I)
SUSPICIOUS = [
    (re.compile(r"\beval\s*\(", re.I), "JavaScript eval()"),
    (re.compile(r"\bdocument\.write\s*\(", re.I), "document.write()"),
    (re.compile(r"\batob\s*\(", re.I), "Base64 decoding (atob)"),
    (re.compile(r"\bfromCharCode\s*\(", re.I), "fromCharCode()"),
]

def public_url(url):
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
            return False, "تەنها لینکی دروستی http/https ڕێگەپێدراوە."
        host = p.hostname.rstrip(".").lower()
        if host == "localhost" or host.endswith((".local", ".localhost")):
            return False, "ناونیشانی ناوخۆیی ڕێگەپێدراو نییە."
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80))
            addresses = [ipaddress.ip_address(x[4][0].split("%")[0]) for x in infos]
        if not addresses or any(not ip.is_global for ip in addresses):
            return False, "ئەم دۆمەینە بۆ IP ـی تایبەت/ناوخۆیی دەچێت."
        return True, ""
    except Exception:
        return False, "لینکەکە دروست نییە یان دۆمەینەکە نەدۆزرایەوە."

def same_origin(a, b):
    x, y = urlparse(a), urlparse(b)
    return (x.scheme, x.hostname, x.port or (443 if x.scheme == "https" else 80)) == (
        y.scheme, y.hostname, y.port or (443 if y.scheme == "https" else 80))

def safe_name(url, ctype=""):
    raw = unquote(urlparse(url).path).strip("/")
    parts = [p for p in PurePosixPath(raw or "index.html").parts if p not in ("", ".", "..")]
    if "." not in PurePosixPath(parts[-1]).name:
        parts[-1] += mimetypes.guess_extension(ctype.split(";")[0]) or ".bin"
    parts = [re.sub(r"[^A-Za-z0-9._-]", "_", p)[:100] or "file" for p in parts]
    return str(PurePosixPath("site_files") / PurePosixPath(*parts))

async def fetch(client, url):
    current = url
    for _ in range(5):
        ok, reason = public_url(current)
        if not ok:
            raise ValueError(reason)
        async with client.stream("GET", current, headers={"User-Agent": UA}) as response:
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if not location:
                    raise ValueError("Redirect ناتەواوە.")
                current = urljoin(current, location)
                continue
            if response.status_code >= 400:
                raise ValueError(f"HTTP {response.status_code}")
            length = response.headers.get("content-length")
            if length and int(length) > MAX_FILE:
                raise ValueError("فایل لە 5MB گەورەترە.")
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data.extend(chunk)
                if len(data) > MAX_FILE:
                    raise ValueError("فایل لە 5MB گەورەترە.")
            return current, bytes(data), dict(response.headers), response.status_code
    raise ValueError("Redirect زۆرە.")

def references(html, base):
    soup = BeautifulSoup(html, "html.parser")
    assets, pages = set(), set()
    for tag in soup.find_all(["script", "img", "source", "video", "audio", "iframe"]):
        for attr in ("src", "poster"):
            if tag.get(attr):
                assets.add(urljoin(base, tag[attr]))
        if tag.get("srcset"):
            for item in tag["srcset"].split(","):
                candidate = item.strip().split()[0]
                if candidate:
                    assets.add(urljoin(base, candidate))
    for tag in soup.find_all("link"):
        rel = " ".join(tag.get("rel", [])).lower()
        if tag.get("href") and any(x in rel for x in ("stylesheet", "icon", "preload", "manifest", "font")):
            assets.add(urljoin(base, tag["href"]))
    for tag in soup.find_all("a", href=True):
        link = urljoin(base, tag["href"]).split("#")[0]
        if same_origin(base, link) and urlparse(link).path.lower().endswith((".html", ".htm", "/")):
            pages.add(link)
    for tag in soup.find_all(style=True):
        assets.update(urljoin(base, x) for x in CSS_URL.findall(tag["style"]))
    for tag in soup.find_all("style"):
        assets.update(urljoin(base, x) for x in CSS_URL.findall(tag.get_text(" ", strip=True)))
    return assets, pages

def code_signals(files):
    hits = []
    for name, data in files.items():
        if name.lower().endswith((".js", ".html", ".htm")):
            source = data.decode("utf-8", errors="ignore")
            for pattern, label in SUSPICIOUS:
                if pattern.search(source):
                    hits.append(f"{label} — {PurePosixPath(name).name}")
    return sorted(set(hits))

async def scan(url):
    ok, reason = public_url(url)
    if not ok:
        raise ValueError(reason)
    files, seen, page_queue = {}, set(), [url]
    total, page_count = 0, 0
    home_headers, status, final_url = {}, None, url
    errors, types = [], set()
    limits = httpx.Limits(max_connections=4, max_keepalive_connections=2)
    async with httpx.AsyncClient(timeout=httpx.Timeout(TIMEOUT), follow_redirects=False,
                                 trust_env=False, limits=limits, verify=True) as client:
        while page_queue and page_count < MAX_PAGES and len(files) < MAX_FILES:
            page = page_queue.pop(0).split("#")[0]
            if page in seen or not same_origin(url, page):
                continue
            seen.add(page)
            try:
                final, data, headers, code = await fetch(client, page)
                if not same_origin(url, final):
                    continue
                ctype = headers.get("content-type", "")
                if "text/html" not in ctype.lower():
                    if page_count == 0:
                        raise ValueError("ئەم لینکە HTML نییە.")
                    continue
                final_url = final
                if page_count == 0:
                    home_headers, status = headers, code
                name = safe_name(final, "text/html")
                if name in files:
                    name = f"site_files/page_{page_count + 1}.html"
                files[name] = data
                total += len(data)
                types.add(ctype.split(";")[0])
                page_count += 1
                assets, pages = references(data.decode("utf-8", "replace"), final)
                page_queue.extend(p for p in pages if p not in seen and same_origin(url, p))
                for asset_url in assets:
                    if asset_url in seen or not same_origin(url, asset_url):
                        continue
                    seen.add(asset_url)
                    try:
                        af, adata, ah, _ = await fetch(client, asset_url)
                        if not same_origin(url, af):
                            continue
                        if total + len(adata) > MAX_TOTAL or len(files) >= MAX_FILES:
                            errors.append("سنووری قەبارە/ژمارەی فایل پڕ بوو.")
                            break
                        atype = ah.get("content-type", "")
                        aname = safe_name(af, atype)
                        if aname in files:
                            stem, ext = os.path.splitext(aname)
                            aname = stem + "_" + hashlib.sha1(af.encode()).hexdigest()[:7] + ext
                        files[aname] = adata
                        total += len(adata)
                        types.add(atype.split(";")[0])
                        if "css" in atype.lower() or aname.lower().endswith(".css"):
                            css = adata.decode("utf-8", errors="ignore")
                            for ref in CSS_URL.findall(css) + CSS_IMPORT.findall(css):
                                cu = urljoin(af, ref.strip().strip("\x22\x27"))
                                if cu in seen or not same_origin(url, cu):
                                    continue
                                seen.add(cu)
                                try:
                                    cf, cd, ch, _ = await fetch(client, cu)
                                    if same_origin(url, cf) and total + len(cd) <= MAX_TOTAL and len(files) < MAX_FILES:
                                        cn = safe_name(cf, ch.get("content-type", ""))
                                        if cn not in files:
                                            files[cn] = cd
                                            total += len(cd)
                                except Exception as exc:
                                    errors.append(f"CSS asset: {str(exc)[:80]}")
                    except Exception as exc:
                        errors.append(f"Asset: {str(exc)[:80]}")
            except Exception as exc:
                errors.append(f"Page: {str(exc)[:100]}")
    if not files:
        raise ValueError("هیچ فایلێکی گشتی نەدۆزرایەوە.")
    header_names = ["content-security-policy", "strict-transport-security",
                    "x-content-type-options", "x-frame-options", "referrer-policy"]
    present = [h for h in header_names if h in {k.lower() for k in home_headers}]
    return {"url": url, "final_url": final_url, "status": status,
            "https": urlparse(final_url).scheme == "https", "files": files,
            "total": total, "types": sorted(types), "headers": present,
            "missing": [h for h in header_names if h not in present],
            "signals": code_signals(files), "errors": errors[:10]}

def make_zip(result):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in result["files"].items():
            z.writestr(name, data)
        report = {
            "url": result["url"], "final_url": result["final_url"],
            "http_status": result["status"], "https": result["https"],
            "files_collected": len(result["files"]), "total_bytes": result["total"],
            "content_types": result["types"], "security_headers_found": result["headers"],
            "security_headers_missing": result["missing"],
            "suspicious_code_signals": result["signals"], "warnings": result["errors"],
            "limitations": ["Public same-origin resources only.",
                "No backend source, database, secrets, or protected files.",
                "Heuristic indicators are not antivirus results."]
        }
        z.writestr("SCAN_REPORT.json", json.dumps(report, ensure_ascii=False, indent=2))
        z.writestr("README.txt", "Shblood Website Scanner\nPublic files only; no backend/private source.\n"
                                 "Heuristic checks cannot prove a website is safe.\n\nShbloodTeam\n")
    output.seek(0)
    return output

def size_text(n):
    return f"{n / 1048576:.2f} MB" if n >= 1048576 else f"{n / 1024:.1f} KB"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "سڵاو! بەخێربێیت بۆ Shblood Website Scanner 🔎\n\n"
        "لینکی سایتێک بنێرە کە خاوەندارێتی یان مۆڵەتی پشکنینت هەیە.\n"
        "فایلە گشتییەکانی HTML/CSS/JS و وێنە و asset ـەکان کۆدەکەینەوە.\n\n"
        "⚠️ Backend، داتابەیس و فایلە نهێنییەکان وەرناگیرێن.\n"
        "ئەم بۆتە دڵنیایی ١٠٠٪ لە بێ‌ڤایرۆس بوونی سایت نادات.\n\nShbloodTeam")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("لینکێکی وەک https://example.com بنێرە.\n"
        "تەنها سایتەکانی خۆت یان ئەوانەی مۆڵەتی پشکنینت هەیە بەکاربهێنە.\n\nShbloodTeam")

async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    raw = (update.message.text or "").strip()
    if len(raw) > 2048:
        await update.message.reply_text("لینکەکە زۆر درێژە.")
        return
    url = raw if "://" in raw else "https://" + raw
    ok, reason = public_url(url)
    if not ok:
        await update.message.reply_text(reason)
        return
    msg = await update.message.reply_text("⏳ چاوەڕێ بە... پشکنین دەستی پێکرد.")
    try:
        result = await scan(url)
        await asyncio.sleep(3)
        await msg.edit_text("✅ پشکنین تەواو")
        await asyncio.sleep(2)
        if result["signals"]:
            security = "⚠️ نیشانەی کۆدی گوماناوی دۆزرایەوە؛ پێویستی بە پشکنینی زیاتر هەیە."
        else:
            security = "ℹ️ نیشانەیەک لە پشکنینە سادەکاندا نەدۆزرایەوە؛ ئەمە بەڵگەی بێ‌مەترسی بوون نییە."
        report = ("🔎 ڕاپۆرتی Shblood Website Scanner\n\n"
            f"🌐 لینک: {result['url']}\n📡 HTTP: {result['status']}\n"
            f"🔐 HTTPS: {'چالاکە' if result['https'] else 'چالاک نییە'}\n"
            f"📁 فایلەکان: {len(result['files'])}\n💾 قەبارە: {size_text(result['total'])}\n"
            f"🛡 Security Headers: {len(result['headers'])}/5\n\n{security}\n"
            "⚠️ پشکنینەکە سنووردارە، نەک گەرەنتیی تەواوی ئەمنی.\n\nShbloodTeam")
        await msg.edit_text(report)
        await asyncio.sleep(2)
        archive = make_zip(result)
        archive.name = "Shblood_Website_Source.zip"
        await update.message.reply_document(document=archive,
            caption="📦 فایلە گشتییە کۆکراوەکان + SCAN_REPORT.json\n"
                    "Backend و فایلە نهێنییەکان تێدا نین.\n\nShbloodTeam")
    except Exception as exc:
        log.exception("Scan failed")
        await msg.edit_text(f"❌ پشکنین سەرکەوتوو نەبوو.\nهۆکار: {str(exc)[:250]}\n\nShbloodTeam")

async def error_handler(update, context):
    log.exception("Unhandled bot error", exc_info=context.error)

def main():
    if not BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN environment variable is missing.")
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_url))
    app.add_error_handler(error_handler)
    log.info("Shblood Website Scanner started.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
