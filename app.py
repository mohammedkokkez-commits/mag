import os
import sqlite3
import json
import ssl
import socket
import datetime
from urllib.parse import urlparse

import requests
from flask import (
    Flask, render_template_string, request, redirect,
    url_for, flash
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-to-random-secret")
DB = os.environ.get("DB_PATH", "vuln.db")


# =========================================================
# قاعدة البيانات
# =========================================================
def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                findings TEXT NOT NULL
            )
        """)


# =========================================================
# محرك الفحص
# =========================================================
SECURITY_HEADERS = {
    "Strict-Transport-Security": "فعّل HSTS مع max-age لا يقل عن 31536000.",
    "Content-Security-Policy": "أضف سياسة CSP مناسبة لتقليل XSS.",
    "X-Frame-Options": "اضبطها على DENY أو SAMEORIGIN.",
    "X-Content-Type-Options": "اضبطها على nosniff.",
    "Referrer-Policy": "حدد سياسة مثل strict-origin-when-cross-origin.",
    "Permissions-Policy": "حدد الأذونات المسموحة.",
}


def check_tls(url):
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return findings
    try:
        host = parsed.hostname
        port = parsed.port or 443
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                exp_ts = ssl.cert_time_to_seconds(cert["notAfter"])
                exp = datetime.datetime.fromtimestamp(
                    exp_ts, datetime.timezone.utc
                )
                now = datetime.datetime.now(datetime.timezone.utc)
                days = (exp - now).days
                if days < 30:
                    findings.append({
                        "severity": "high" if days < 7 else "medium",
                        "title": "شهادة TLS قاربت على الانتهاء",
                        "details": f"تنتهي خلال {days} يوم.",
                        "fix": "جدد شهادة TLS قبل انتهائها.",
                    })
    except Exception as e:
        findings.append({
            "severity": "medium",
            "title": "تعذر فحص شهادة TLS",
            "details": str(e),
            "fix": "تحقق يدويًا من الشهادة.",
        })
    return findings


def scan_url(url):
    findings = []

    try:
        resp = requests.get(
            url, timeout=10, allow_redirects=True,
            headers={"User-Agent": "DefensiveVulnManager/1.0"}
        )
    except Exception as e:
        return [{
            "severity": "high",
            "title": "فشل الاتصال",
            "details": str(e),
            "fix": "تأكد من صحة الرابط وأن الموقع متاح.",
        }]

    # HTTPS
    if not resp.url.startswith("https://"):
        findings.append({
            "severity": "high",
            "title": "لا يستخدم HTTPS",
            "details": f"الموقع يعمل عبر: {resp.url}",
            "fix": "فعّل TLS وأعد التوجيه الإجباري من HTTP إلى HTTPS.",
        })

    # ترويسات أمنية
    for header, fix in SECURITY_HEADERS.items():
        if header not in resp.headers:
            findings.append({
                "severity": "medium",
                "title": f"ترويسة أمنية مفقودة: {header}",
                "details": f"لم يتم العثور على الترويسة {header}.",
                "fix": fix,
            })

    if resp.headers.get("X-Content-Type-Options", "").lower() not in ("nosniff",):
        if "X-Content-Type-Options" in resp.headers:
            findings.append({
                "severity": "medium",
                "title": "X-Content-Type-Options غير صحيحة",
                "details": f"القيمة الحالية: {resp.headers.get('X-Content-Type-Options')}",
                "fix": "اضبطها على nosniff.",
            })

    # الكوكيز
    for sc in resp.raw.headers.getlist("Set-Cookie"):
        lower = sc.lower()
        name = sc.split("=", 1)[0].strip()

        if "secure" not in lower:
            findings.append({
                "severity": "medium",
                "title": f"كوكي بدون Secure: {name}",
                "details": "الكوكي قد يُرسل عبر HTTP.",
                "fix": "أضف خاصية Secure إلى الكوكي.",
            })
        if "httponly" not in lower:
            findings.append({
                "severity": "medium",
                "title": f"كوكي بدون HttpOnly: {name}",
                "details": "يمكن الوصول للكوكي عبر JavaScript.",
                "fix": "أضف HttpOnly.",
            })
        if "samesite" not in lower:
            findings.append({
                "severity": "low",
                "title": f"كوكي بدون SameSite: {name}",
                "details": "قد يكون عرضة لهجمات CSRF.",
                "fix": "أضف SameSite=Lax أو Strict.",
            })

    # كشف إصدار السيرفر
    server = resp.headers.get("Server")
    if server:
        findings.append({
            "severity": "low",
            "title": "كشف معلومات السيرفر",
            "details": f"Server: {server}",
            "fix": "أخفِ إصدار السيرفر أو قلل المعلومات الظاهرة.",
        })

    # TLS
    findings += check_tls(resp.url)

    # CORS خطير
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials")
    if acao == "*" and acac and acac.lower() == "true":
        findings.append({
            "severity": "high",
            "title": "CORS خطير",
            "details": "Access-Control-Allow-Origin: * مع Credentials: true",
            "fix": "حدد الأصول المسموح بها بشكل صريح ولا تستخدم * مع credentials.",
        })

    if not findings:
        findings.append({
            "severity": "info",
            "title": "لا توجد مشاكل واضحة",
            "details": "الفحوصات الأساسية لم تجد مشاكل.",
            "fix": "استمر في التحديث والمراقبة.",
        })

    return findings


# =========================================================
# القوالب
# =========================================================
BASE_HTML = """
<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>مدير الثغرات الدفاعي</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 1rem; background: #f7f7f7; color: #222; }
    header h1 { margin-bottom: 1rem; font-size: 1.3rem; }
    form { background: white; padding: 1rem; margin-bottom: 1rem; border-radius: 8px; }
    input[type=url] { width: 100%; padding: 8px; margin-bottom: 8px; box-sizing: border-box; }
    button { padding: 10px 16px; background: #0a7a0a; color: white; border: 0; border-radius: 6px; }
    table { border-collapse: collapse; width: 100%; background: white; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: right; word-break: break-all; }
    .flash { background: #fff3cd; padding: 1rem; border-radius: 8px; list-style: none; }
    .sev-high { color: #b00020; }
    .sev-medium { color: #b26a00; }
    .sev-low { color: #555; }
    .sev-info { color: #0a7a0a; }
    section { background: white; padding: 1rem; margin-bottom: 1rem; border-radius: 8px; }
    ul.findings { list-style: none; padding: 0; }
    ul.findings li { border-bottom: 1px solid #eee; padding: 8px 0; }
  </style>
</head>
<body>
  <header><h1>مدير الثغرات الدفاعي</h1></header>
  <main>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul class="flash">
          {% for m in messages %}<li>{{ m }}</li>{% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
  </main>
</body>
</html>
"""

INDEX_HTML = BASE_HTML.replace(
    "{% block content %}{% endblock %}",
    """
    <form method="post" action="{{ url_for('add') }}">
      <input type="url" name="url" placeholder="https://example.com" required>
      <label style="display:block; margin-bottom:8px;">
        <input type="checkbox" name="authorized" required>
        أملك الموقع أو لدي إذن كتابي بفحصه.
      </label>
      <button type="submit">إضافة أصل</button>
    </form>

    <h2>الأصول</h2>
    <table>
      <tr><th>ID</th><th>الرابط</th><th>إجراء</th></tr>
      {% for a in assets %}
      <tr>
        <td>{{ a[0] }}</td>
        <td>{{ a[1] }}</td>
        <td>
          <a href="{{ url_for('scan', asset_id=a[0]) }}">فحص</a> |
          <a href="{{ url_for('asset', asset_id=a[0]) }}">النتائج</a>
        </td>
      </tr>
      {% endfor %}
    </table>
    """
)

ASSET_HTML = BASE_HTML.replace(
    "{% block content %}{% endblock %}",
    """
    <h2>نتائج: {{ asset[1] }}</h2>
    <p><a href="{{ url_for('index') }}">عودة</a></p>

    {% for s in scans %}
    <section>
      <h3>فحص #{{ s.id }} - {{ s.created_at }}</h3>
      <ul class="findings">
        {% for f in s.findings %}
        <li class="sev-{{ f.severity }}">
          <strong>{{ f.title }}</strong> [{{ f.severity }}]<br>
          {{ f.details }}<br>
          <em>الإصلاح: {{ f.fix }}</em>
        </li>
        {% endfor %}
      </ul>
    </section>
    {% endfor %}
    """
)


# =========================================================
# المسارات
# =========================================================
@app.route("/")
def index():
    con = sqlite3.connect(DB)
    assets = con.execute("SELECT * FROM assets ORDER BY id DESC").fetchall()
    con.close()
    return render_template_string(INDEX_HTML, assets=assets)


@app.route("/add", methods=["POST"])
def add():
    url = request.form.get("url", "").strip()
    authorized = request.form.get("authorized")

    if not url or not authorized:
        flash("يجب إدخال رابط وتأكيد أنك تملك الموقع أو لديك إذن بفحصه.")
        return redirect(url_for("index"))

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    con = sqlite3.connect(DB)
    con.execute(
        "INSERT INTO assets(url, created_at) VALUES (?, ?)",
        (url, datetime.datetime.now(datetime.timezone.utc).isoformat()),
    )
    con.commit()
    con.close()
    return redirect(url_for("index"))


@app.route("/scan/<int:asset_id>")
def scan(asset_id):
    con = sqlite3.connect(DB)
    asset = con.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    con.close()

    if not asset:
        flash("الأصل غير موجود.")
        return redirect(url_for("index"))

    findings = scan_url(asset[1])

    con = sqlite3.connect(DB)
    con.execute(
        "INSERT INTO scans(asset_id, created_at, findings) VALUES (?, ?, ?)",
        (
            asset_id,
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
            json.dumps(findings, ensure_ascii=False),
        ),
    )
    con.commit()
    con.close()
    return redirect(url_for("asset", asset_id=asset_id))


@app.route("/asset/<int:asset_id>")
def asset(asset_id):
    con = sqlite3.connect(DB)
    asset_row = con.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    scans = con.execute(
        "SELECT * FROM scans WHERE asset_id = ? ORDER BY id DESC", (asset_id,)
    ).fetchall()
    con.close()

    if not asset_row:
        flash("الأصل غير موجود.")
        return redirect(url_for("index"))

    parsed_scans = [
        {"id": s[0], "created_at": s[2], "findings": json.loads(s[3])}
        for s in scans
    ]

    return render_template_string(ASSET_HTML, asset=asset_row, scans=parsed_scans)


init_db()

if __name__ == "__main__":
    app.run(debug=True)