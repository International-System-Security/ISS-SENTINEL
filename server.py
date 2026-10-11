import os
import asyncio
import secrets
import sqlite3
import threading
from datetime import datetime, date, timedelta
from functools import wraps

import discord
from discord import app_commands
from discord.ext import commands
from typing import Literal
from flask import (Flask, Response, render_template_string, request, redirect,
                   url_for, session, abort, g)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ------------------------------------------------------------------
# Config (সব সিক্রেট এনভায়রনমেন্ট ভেরিয়েবল থেকে আসবে)
# ------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

DB_FILE = os.environ.get("DB_FILE", "iss.db")
OWNER_EMAIL = os.environ["OWNER_EMAIL"]
OWNER_USERNAME = os.environ.get("OWNER_USERNAME", "owner")
OWNER_PASSWORD = os.environ["OWNER_PASSWORD"]
BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN")

limiter = Limiter(get_remote_address, app=app,
                  default_limits=["200 per hour"], storage_uri="memory://")


# ------------------------------------------------------------------
# Database (sqlite - নিজে থেকেই তৈরি হবে)
# ------------------------------------------------------------------
def connect():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = connect()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS admins(
        email TEXT PRIMARY KEY, username TEXT, password_hash TEXT);
    CREATE TABLE IF NOT EXISTS licenses(
        key TEXT PRIMARY KEY, name TEXT, org TEXT, expiry TEXT,
        max_devices INTEGER, plan TEXT, client_user TEXT,
        client_pwd_hash TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS tickets(
        id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT,
        subject TEXT, status TEXT DEFAULT 'open', created TEXT);
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS ticket_messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER,
        sender TEXT, body TEXT, created TEXT);
    """)
    if not conn.execute("SELECT 1 FROM admins WHERE email=?", (OWNER_EMAIL,)).fetchone():
        conn.execute("INSERT INTO admins VALUES(?,?,?)",
                     (OWNER_EMAIL, OWNER_USERNAME, generate_password_hash(OWNER_PASSWORD)))
    conn.commit()
    conn.close()


def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M")


# ------------------------------------------------------------------
# ডিসকর্ড অ্যালার্ট (বট নিজেই নির্ধারিত চ্যানেলে পাঠায়, ওয়েবহুক লাগে না)
# ------------------------------------------------------------------
def send_discord_alert(text):
    try:
        if not bot.is_ready():
            return
        conn = connect()
        row = conn.execute("SELECT value FROM settings WHERE key='alert_channel'").fetchone()
        conn.close()
        if not row:
            return

        async def _send():
            ch = bot.get_channel(int(row["value"]))
            if ch:
                await ch.send(text)
        asyncio.run_coroutine_threadsafe(_send(), bot.loop)
    except Exception as e:
        print(f"Alert error: {e}")


# ------------------------------------------------------------------
# CSRF + Auth helpers
# ------------------------------------------------------------------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid CSRF token")


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return f(*a, **kw)
    return wrapper


def client_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        key = session.get("client_license")
        if not key:
            return redirect(url_for("client_login"))
        lic = get_db().execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
        if not lic:
            session.pop("client_license", None)
            return redirect(url_for("client_login"))
        g.lic = lic
        return f(*a, **kw)
    return wrapper


# ------------------------------------------------------------------
# Layout
# ------------------------------------------------------------------
LAYOUT = """
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }}</title>
<style>
 body{font-family:'Segoe UI',sans-serif;background:#060913;color:#fff;margin:0;padding:24px}
 .card{background:#111827;border:1px solid #1e293b;border-radius:8px;padding:20px;margin:16px 0}
 input,select,textarea{width:100%;padding:9px;margin:5px 0;background:#060913;border:1px solid #334155;color:#fff;border-radius:6px;box-sizing:border-box}
 button,.btn{background:#0ea5e9;color:#fff;padding:10px 18px;border:none;border-radius:6px;font-weight:bold;cursor:pointer;text-decoration:none;display:inline-block}
 .btn2{background:#1e293b;color:#38bdf8}
 a{color:#38bdf8} table{width:100%;border-collapse:collapse}
 td,th{padding:8px;border-bottom:1px solid #1e293b;text-align:left;font-size:14px}
 .ok{color:#34d399}.err{color:#fca5a5}.wrap{max-width:900px;margin:auto}
 .me{background:#0c4a6e;padding:8px;border-radius:6px;margin:6px 0}
 .them{background:#1e293b;padding:8px;border-radius:6px;margin:6px 0}
</style></head>
<body><div class="wrap">{{ body|safe }}</div></body></html>
"""


def page(title, body_tpl, **ctx):
    body = render_template_string(body_tpl, **ctx)
    return render_template_string(LAYOUT, title=title, body=body)


# ------------------------------------------------------------------
# Home
# ------------------------------------------------------------------
LANDING_HTML = r'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ISS Enterprise & Cloud Security</title>
<meta name="description" content="ISS: license management, client portal, support tickets and Discord control for your security business.">
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
:root{--ink:#050914;--line:rgba(140,170,255,.13);--text:#e8eefc;--mute:#93a3c7;--cy:#2de2ff;--vi:#7a5cff;--mg:#ff4fd8;--ok:#3dffb0}
*{box-sizing:border-box;margin:0}
html{scroll-behavior:smooth}
body{font-family:'DM Sans',system-ui,sans-serif;background:var(--ink);color:var(--text);line-height:1.6;overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(60% 50% at 82% 0%,rgba(122,92,255,.3),transparent 70%),radial-gradient(45% 40% at 0% 35%,rgba(45,226,255,.14),transparent 70%),linear-gradient(var(--line) 1px,transparent 1px) 0 0/56px 56px,linear-gradient(90deg,var(--line) 1px,transparent 1px) 0 0/56px 56px}
a{color:inherit;text-decoration:none}
:focus-visible{outline:2px solid var(--cy);outline-offset:3px;border-radius:6px}
.wrap{max-width:1120px;margin:auto;padding:0 22px}
h1,h2,h3{font-family:'Syne',sans-serif;line-height:1.08}
nav{position:sticky;top:0;z-index:5;backdrop-filter:blur(14px);background:rgba(5,9,20,.7);border-bottom:1px solid var(--line)}
nav .wrap{display:flex;align-items:center;justify-content:space-between;height:66px}
.brand{font-family:'Syne';font-weight:800;font-size:1.25rem;display:flex;gap:10px;align-items:center}
.brand i{width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,var(--cy),var(--vi));display:grid;place-items:center;font-style:normal;font-size:16px}
.links{display:flex;gap:26px;align-items:center;color:var(--mute);font-size:.95rem}
.links a:hover{color:#fff}
.btn{display:inline-block;padding:12px 24px;border-radius:12px;font-weight:700;background:linear-gradient(120deg,var(--cy),var(--vi));color:#04101c;box-shadow:0 8px 30px rgba(45,226,255,.28);transition:transform .2s,box-shadow .2s}
.btn:hover{transform:translateY(-2px);box-shadow:0 12px 40px rgba(122,92,255,.45)}
.btn.ghost{background:transparent;color:var(--text);border:1px solid rgba(255,255,255,.22);box-shadow:none}
.btn.ghost:hover{border-color:var(--cy)}
.hero{display:grid;grid-template-columns:1.1fr .9fr;gap:40px;align-items:center;padding:70px 0 90px}
.hero h1{font-size:clamp(2.5rem,6vw,4.7rem);font-weight:800;letter-spacing:-.02em}
.hero h1 span{display:block;background:linear-gradient(100deg,var(--cy),var(--vi) 55%,var(--mg));-webkit-background-clip:text;background-clip:text;color:transparent}
.hero p{color:var(--mute);font-size:1.15rem;max-width:34rem;margin:22px 0 32px}
.cta{display:flex;gap:14px;flex-wrap:wrap}
.hero .in{opacity:0;transform:translateY(22px);animation:up .8s cubic-bezier(.2,.7,.2,1) forwards}
.hero .in:nth-child(2){animation-delay:.12s}.hero .in:nth-child(3){animation-delay:.24s}
@keyframes up{to{opacity:1;transform:none}}
.radar{width:min(430px,88vw);aspect-ratio:1;border-radius:50%;position:relative;margin:auto;border:1px solid rgba(45,226,255,.45);background:repeating-radial-gradient(circle,transparent 0 39px,rgba(45,226,255,.2) 40px 41px),radial-gradient(circle,rgba(45,226,255,.1),transparent 72%);box-shadow:0 0 90px rgba(45,226,255,.2),inset 0 0 70px rgba(122,92,255,.25);animation:up 1.1s .3s both}
.radar:before,.radar:after{content:"";position:absolute;background:rgba(45,226,255,.18)}
.radar:before{left:50%;top:0;bottom:0;width:1px}.radar:after{top:50%;left:0;right:0;height:1px}
.sweep{position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,rgba(45,226,255,.6),rgba(45,226,255,0) 30%);animation:spin 4.5s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.b{position:absolute;width:11px;height:11px;border-radius:50%;background:var(--mg);box-shadow:0 0 16px var(--mg);opacity:0;animation:blip 4.5s infinite}
@keyframes blip{0%{opacity:0;transform:scale(.3)}8%{opacity:1;transform:scale(1.5)}45%{opacity:0;transform:scale(1)}100%{opacity:0}}
.shield{position:absolute;inset:0;display:grid;place-items:center;filter:drop-shadow(0 0 22px rgba(45,226,255,.7))}
.chip{position:absolute;padding:8px 14px;border-radius:999px;font-size:.82rem;font-weight:500;background:rgba(8,14,30,.85);border:1px solid var(--line);backdrop-filter:blur(8px);display:flex;gap:8px;align-items:center}
.chip:before{content:"";width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 10px var(--ok)}
section{padding:80px 0}
h2{font-size:clamp(1.9rem,4vw,3rem);font-weight:800;max-width:30rem}
.sub{color:var(--mute);max-width:34rem;margin:14px 0 40px}
.bento{display:grid;grid-template-columns:repeat(6,1fr);gap:16px}
.bt{position:relative;overflow:hidden;padding:28px;border-radius:22px;border:1px solid var(--line);background:linear-gradient(160deg,rgba(255,255,255,.05),rgba(255,255,255,.01));grid-column:span 2}
.bt.big{grid-column:span 4}
.bt:before{content:"";position:absolute;inset:0;pointer-events:none;background:radial-gradient(260px circle at var(--x,50%) var(--y,-40%),rgba(45,226,255,.16),transparent 70%)}
.bt h3{font-size:1.35rem;margin-bottom:8px}
.bt p{color:var(--mute);font-size:.98rem}
.rows{margin-top:22px;display:grid;gap:10px}
.row{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-radius:12px;background:rgba(5,9,20,.7);border:1px solid var(--line);font-size:.9rem;font-family:ui-monospace,Menlo,monospace;color:var(--mute)}
.pill{padding:3px 12px;border-radius:99px;font:700 .75rem 'DM Sans';color:#04101c;background:var(--ok)}
.pill.v{background:var(--vi);color:#fff}.pill.c{background:var(--cy)}
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:24px;position:relative}
.steps:before{content:"";position:absolute;top:27px;left:6%;right:6%;height:2px;background:linear-gradient(90deg,var(--cy),var(--vi),var(--mg));opacity:.5}
.step b{position:relative;display:grid;place-items:center;width:54px;height:54px;border-radius:50%;background:var(--ink);border:2px solid var(--cy);font:800 1.2rem 'Syne';margin-bottom:18px}
.step h3{font-size:1.25rem;margin-bottom:6px}.step p{color:var(--mute)}
.band{border-radius:28px;padding:54px 34px;text-align:center;border:1px solid rgba(122,92,255,.4);background:radial-gradient(70% 120% at 50% 0%,rgba(122,92,255,.35),rgba(45,226,255,.06))}
.band h2{margin:0 auto 12px;max-width:none}.band p{color:var(--mute);margin-bottom:26px}
.soc{display:grid;gap:12px;max-width:640px}
.s{display:flex;align-items:center;gap:18px;padding:18px 22px;border-radius:16px;border:1px solid var(--line);background:rgba(255,255,255,.03);border-left:4px solid var(--c);transition:transform .2s,background .2s}
.s:hover{transform:translateX(6px);background:rgba(255,255,255,.07)}
.s small{display:block;color:var(--mute);font-size:.82rem}.s strong{font-size:1.05rem}
.s em{margin-left:auto;font-style:normal;color:var(--c);font-weight:700;font-size:.9rem}
footer{border-top:1px solid var(--line);padding:30px 0;color:var(--mute);font-size:.9rem}
footer .wrap{display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px}
@media(max-width:860px){.hero{grid-template-columns:1fr;padding-top:40px}.bt,.bt.big{grid-column:span 6}.steps{grid-template-columns:1fr}.steps:before{display:none}.links a:not(.btn){display:none}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;opacity:1!important;transform:none!important}}
</style></head><body>
<nav><div class="wrap"><a class="brand" href="/"><i>🛡️</i>ISS Security</a>
<div class="links"><a href="#features">Features</a><a href="#how">How it works</a><a href="#connect">Connect</a><a class="btn" href="/client-login" style="padding:9px 20px;color:#04101c">Client Portal</a></div></div></nav>

<main class="wrap">
<header class="hero">
<div>
<h1 class="in">Your clients' security,<span>managed in one place.</span></h1>
<p class="in">ISS gives your team licenses, client dashboards, support tickets and Discord control in a single platform, so protection stays organized and clients stay informed.</p>
<div class="cta in"><a class="btn" href="/client-login">Open Client Portal</a><a class="btn ghost" href="https://discord.gg/mxRgm2R3ud" target="_blank" rel="noopener noreferrer">Join our Discord</a></div>
</div>
<div class="radar" aria-hidden="true">
<div class="sweep"></div>
<i class="b" style="top:20%;left:70%;animation-delay:.55s"></i><i class="b" style="top:70%;left:76%;animation-delay:1.7s"></i><i class="b" style="top:78%;left:24%;animation-delay:2.8s"></i><i class="b" style="top:30%;left:18%;animation-delay:3.7s"></i>
<div class="shield"><svg width="112" height="112" viewBox="0 0 24 24" fill="none"><path d="M12 2.5l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10v-6l8-3z" fill="rgba(45,226,255,.16)" stroke="#2de2ff" stroke-width="1.4" stroke-linejoin="round"/><path d="M8.3 12.2l2.7 2.7 4.9-5.4" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
<span class="chip" style="top:6%;left:-4%">Protection active</span><span class="chip" style="bottom:8%;right:-3%">Discord alerts on</span>
</div>
</header>

<section id="features"><h2>Everything you need to run client security</h2><p class="sub">Built for security providers who want fewer spreadsheets and faster answers.</p>
<div class="bento">
<div class="bt big"><h3>License management</h3><p>Create a license with a plan and expiry date, hand over the login, and delete it when the contract ends.</p>
<div class="rows"><div class="row"><span>KEY-••••••••A1</span><span class="pill">Active</span></div><div class="row"><span>KEY-••••••••7F</span><span class="pill v">Pro Plan</span></div><div class="row"><span>KEY-••••••••C9</span><span class="pill c">Enterprise</span></div></div></div>
<div class="bt"><h3>Client portal</h3><p>Every client signs in to their own dashboard and sees their plan, expiry and protection status.</p></div>
<div class="bt"><h3>Support tickets</h3><p>Clients open a ticket and your team replies in the same thread until it is closed.</p></div>
<div class="bt"><h3>Discord control</h3><p>Run /newlicense, /tickets and /report right from your server and get alerts in your channel.</p></div>
<div class="bt"><h3>Safer sign-in</h3><p>Passwords are hashed, login attempts are limited and every form is protected against forgery.</p></div>
</div></section>

<section id="how"><h2>Up and running in three steps</h2><p class="sub">No installs for your clients, only a browser.</p>
<div class="steps">
<div class="step"><b>1</b><h3>Get a license</h3><p>Ask our team on Discord and receive your key, username and password.</p></div>
<div class="step"><b>2</b><h3>Sign in</h3><p>Open the Client Portal and enter your license key and login.</p></div>
<div class="step"><b>3</b><h3>Stay covered</h3><p>Check your status any time and open a ticket if you need help.</p></div>
</div></section>

<section><div class="band"><h2>Ready to get a license?</h2><p>Tell us about your organization on Discord and we will set you up.</p><a class="btn" href="https://discord.gg/mxRgm2R3ud" target="_blank" rel="noopener noreferrer">Join our Discord</a></div></section>

<section id="connect"><h2>Find Muhib online</h2><p class="sub">Questions, projects or just saying hello, pick your platform.</p>
<div class="soc">
<a class="s" style="--c:#ff4f8b" href="https://instagram.com/mrshadow6000" target="_blank" rel="noopener noreferrer"><div><small>Instagram</small><strong>mrshadow6000</strong></div><em>Follow</em></a>
<a class="s" style="--c:#7a8cff" href="https://discord.gg/mxRgm2R3ud" target="_blank" rel="noopener noreferrer"><div><small>Discord</small><strong>ISS community server</strong></div><em>Join</em></a>
<a class="s" style="--c:#3b9cff" href="https://www.linkedin.com/search/results/people/?keywords=Muhib%20Ibrahim" target="_blank" rel="noopener noreferrer"><div><small>LinkedIn</small><strong>Muhib Ibrahim</strong></div><em>Connect</em></a>
<a class="s" style="--c:#c9d4f0" href="https://github.com/muhibibrahim-6" target="_blank" rel="noopener noreferrer"><div><small>GitHub</small><strong>muhibibrahim-6</strong></div><em>Follow</em></a>
<a class="s" style="--c:#3dffb0" href="https://medium.com/@Muhibibrahim" target="_blank" rel="noopener noreferrer"><div><small>Medium</small><strong>@Muhibibrahim</strong></div><em>Read</em></a>
</div></section>
</main>

<footer><div class="wrap"><span>© 2026 ISS Enterprise & Cloud Security</span><span><a href="/client-login">Client login</a> &nbsp;·&nbsp; <a href="/admin">Admin</a></span></div></footer>
<script>
document.querySelectorAll('.bt').forEach(function(c){c.addEventListener('pointermove',function(e){var r=c.getBoundingClientRect();c.style.setProperty('--x',(e.clientX-r.left)+'px');c.style.setProperty('--y',(e.clientY-r.top)+'px')})});
</script>
</body></html>
'''


@app.route("/")
def home():
    return Response(LANDING_HTML, mimetype="text/html")


# ------------------------------------------------------------------
# Admin
# ------------------------------------------------------------------
@app.route("/admin-login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_login():
    err = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        pwd = request.form.get("password", "")
        a = get_db().execute("SELECT * FROM admins WHERE email=?", (email,)).fetchone()
        if a and check_password_hash(a["password_hash"], pwd):
            session.clear()
            session["is_admin"] = True
            session["admin_email"] = email
            return redirect(url_for("admin_panel"))
        err = "Wrong email or password"
        send_discord_alert(f"⚠️ Failed admin login attempt for `{email[:60]}`")
    return page("Admin Login", """
    <div class="card" style="max-width:340px;margin:60px auto">
      <h3>Admin Login</h3>
      {% if err %}<p class="err">{{ err }}</p>{% endif %}
      <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
        <input name="email" type="email" placeholder="Email" required>
        <input name="password" type="password" placeholder="Password" required>
        <button type="submit" style="width:100%">Login</button>
      </form><br><a href="/">&larr; Home</a>
    </div>""", err=err)


@app.route("/admin-logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin_panel():
    db = get_db()
    msg = ""
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add_license":
            key = request.form.get("l_key", "").strip() or "KEY-" + secrets.token_hex(6).upper()
            name = request.form.get("l_name", "").strip()
            org = request.form.get("l_org", "").strip()
            plan = request.form.get("l_plan", "Basic Plan").strip()
            expiry = request.form.get("l_expiry", "").strip() or "2027-01-01"
            user = request.form.get("l_user", "").strip()
            pwd = request.form.get("l_pwd", "")
            try:
                date.fromisoformat(expiry)
            except ValueError:
                msg = "❌ Invalid expiry date (use YYYY-MM-DD)"
            else:
                if not (name and org and user and len(pwd) >= 8):
                    msg = "❌ Fill all fields (password min 8 chars)"
                elif db.execute("SELECT 1 FROM licenses WHERE key=?", (key,)).fetchone():
                    msg = "❌ License key already exists"
                else:
                    db.execute("INSERT INTO licenses VALUES(?,?,?,?,?,?,?,?,?)",
                               (key, name, org, expiry, 5, plan, user,
                                generate_password_hash(pwd), now()))
                    db.commit()
                    send_discord_alert(f"🔑 New license `{key}` | **{name}** ({org}) | {plan}")
                    msg = f"✅ License '{key}' created"
        elif action == "delete_license":
            db.execute("DELETE FROM licenses WHERE key=?", (request.form.get("key", ""),))
            db.commit()
            msg = "🗑️ License deleted"
        elif action == "add_admin":
            em = request.form.get("a_email", "").strip()
            un = request.form.get("a_user", "").strip()
            pw = request.form.get("a_pwd", "")
            if em and un and len(pw) >= 8:
                try:
                    db.execute("INSERT INTO admins VALUES(?,?,?)",
                               (em, un, generate_password_hash(pw)))
                    db.commit()
                    msg = "✅ Admin added"
                except sqlite3.IntegrityError:
                    msg = "❌ Admin already exists"
            else:
                msg = "❌ Invalid admin data (password min 8 chars)"

    licenses = db.execute("SELECT * FROM licenses ORDER BY created DESC").fetchall()
    open_tickets = db.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0]
    return page("Admin Panel", """
    <h2>🛡️ Admin Panel</h2>
    <a href="/">&larr; Home</a> |
    <a href="/admin/tickets">Support Tickets ({{ open_tickets }} open)</a>
    <form method="POST" action="/admin-logout" style="display:inline;float:right">
      <input type="hidden" name="csrf" value="{{ csrf() }}"><button class="btn2">Logout</button></form>
    {% if msg %}<p class="ok">{{ msg }}</p>{% endif %}

    <div class="card"><h3>Create Client License</h3>
      <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
        <input type="hidden" name="action" value="add_license">
        <input name="l_key" placeholder="License Key (empty = auto generate)">
        <input name="l_name" placeholder="Client Name" required>
        <input name="l_org" placeholder="Organization" required>
        <select name="l_plan"><option>Basic Plan</option><option>Pro Plan</option><option>Enterprise Plan</option></select>
        <input name="l_expiry" placeholder="Expiry YYYY-MM-DD (default 2027-01-01)">
        <input name="l_user" placeholder="Client username" required>
        <input name="l_pwd" type="password" placeholder="Client password (min 8)" required>
        <button type="submit">Create License & Notify Discord</button>
      </form></div>

    <div class="card"><h3>Licenses</h3>
      <table><tr><th>Key</th><th>Client</th><th>Org</th><th>Plan</th><th>Expiry</th><th></th></tr>
      {% for l in licenses %}<tr>
        <td><code>{{ l.key }}</code></td><td>{{ l.name }}</td><td>{{ l.org }}</td>
        <td>{{ l.plan }}</td><td>{{ l.expiry }}</td>
        <td><form method="POST" onsubmit="return confirm('Delete?')">
          <input type="hidden" name="csrf" value="{{ csrf() }}">
          <input type="hidden" name="action" value="delete_license">
          <input type="hidden" name="key" value="{{ l.key }}"><button class="btn2">Delete</button></form></td>
      </tr>{% endfor %}</table></div>

    <div class="card"><h3>Add Admin</h3>
      <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
        <input type="hidden" name="action" value="add_admin">
        <input name="a_email" type="email" placeholder="Email" required>
        <input name="a_user" placeholder="Username" required>
        <input name="a_pwd" type="password" placeholder="Password (min 8)" required>
        <button type="submit">Add Admin</button></form></div>
    """, msg=msg, licenses=licenses, open_tickets=open_tickets)


@app.route("/admin/tickets")
@admin_required
def admin_tickets():
    rows = get_db().execute("""SELECT t.*, l.org FROM tickets t
        LEFT JOIN licenses l ON l.key=t.license_key ORDER BY t.id DESC""").fetchall()
    return page("Tickets", """
    <h2>🎫 Support Tickets</h2><a href="/admin">&larr; Admin</a>
    <div class="card"><table><tr><th>#</th><th>Org</th><th>Subject</th><th>Status</th><th>Date</th></tr>
    {% for t in rows %}<tr><td><a href="/admin/tickets/{{ t.id }}">{{ t.id }}</a></td>
      <td>{{ t.org }}</td><td>{{ t.subject }}</td><td>{{ t.status }}</td><td>{{ t.created }}</td></tr>
    {% endfor %}</table></div>""", rows=rows)


@app.route("/admin/tickets/<int:tid>", methods=["GET", "POST"])
@admin_required
def admin_ticket(tid):
    db = get_db()
    t = db.execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone()
    if not t:
        abort(404)
    if request.method == "POST":
        if request.form.get("action") == "close":
            db.execute("UPDATE tickets SET status='closed' WHERE id=?", (tid,))
        else:
            body = request.form.get("body", "").strip()[:2000]
            if body:
                db.execute("INSERT INTO ticket_messages(ticket_id,sender,body,created) VALUES(?,?,?,?)",
                           (tid, "support", body, now()))
        db.commit()
        return redirect(url_for("admin_ticket", tid=tid))
    msgs = db.execute("SELECT * FROM ticket_messages WHERE ticket_id=? ORDER BY id", (tid,)).fetchall()
    return page("Ticket", """
    <h2>🎫 #{{ t.id }} - {{ t.subject }} ({{ t.status }})</h2>
    <a href="/admin/tickets">&larr; Tickets</a>
    <div class="card">{% for m in msgs %}
      <div class="{{ 'me' if m.sender=='support' else 'them' }}"><b>{{ m.sender }}</b> · {{ m.created }}<br>{{ m.body }}</div>
    {% endfor %}</div>
    {% if t.status == 'open' %}
    <div class="card"><form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
      <textarea name="body" rows="3" placeholder="Reply..." required></textarea>
      <button type="submit">Send Reply</button></form><br>
      <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
      <input type="hidden" name="action" value="close"><button class="btn2">Close Ticket</button></form></div>
    {% endif %}""", t=t, msgs=msgs)


# ------------------------------------------------------------------
# Client portal
# ------------------------------------------------------------------
@app.route("/client-login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def client_login():
    err = ""
    if request.method == "POST":
        key = request.form.get("lic_key", "").strip()
        user = request.form.get("username", "").strip()
        pwd = request.form.get("password", "")
        lic = get_db().execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
        if not lic or lic["client_user"] != user or not check_password_hash(lic["client_pwd_hash"], pwd):
            err = "Invalid credentials!"
        elif lic["expiry"] < date.today().isoformat():
            err = "License expired. Please contact support."
        else:
            session.clear()
            session["client_license"] = key
            return redirect(url_for("client_dashboard"))
    return page("Client Login", """
    <div class="card" style="max-width:340px;margin:60px auto"><h3>Client Portal Login</h3>
      {% if err %}<p class="err">{{ err }}</p>{% endif %}
      <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
        <input name="lic_key" placeholder="License Key" required>
        <input name="username" placeholder="Username" required>
        <input name="password" type="password" placeholder="Password" required>
        <button type="submit" style="width:100%">Login</button></form>
      <br><a href="/">&larr; Home</a></div>""", err=err)


@app.route("/client-dashboard")
@client_required
def client_dashboard():
    tickets = get_db().execute("SELECT * FROM tickets WHERE license_key=? ORDER BY id DESC",
                               (g.lic["key"],)).fetchall()
    return page("Client Dashboard", """
    <h2>🛡️ Client Security Dashboard</h2>
    <form method="POST" action="/client-logout" style="float:right">
      <input type="hidden" name="csrf" value="{{ csrf() }}"><button class="btn2">Logout</button></form>
    <p>Organization: <b>{{ v.org }}</b> | Plan: {{ v.plan }} | Expiry: {{ v.expiry }}</p>
    <p>License: <code>{{ v.key }}</code></p>
    <p class="ok">Protection Status: <b>Active & Secured</b></p>

    <div class="card"><h3>New Support Ticket</h3>
      <form method="POST" action="/client/tickets/new"><input type="hidden" name="csrf" value="{{ csrf() }}">
        <input name="subject" placeholder="Subject" maxlength="120" required>
        <textarea name="body" rows="3" placeholder="Describe your problem" required></textarea>
        <button type="submit">Submit Ticket</button></form></div>

    <div class="card"><h3>My Tickets</h3><table>
      {% for t in tickets %}<tr><td><a href="/client/tickets/{{ t.id }}">#{{ t.id }}</a></td>
        <td>{{ t.subject }}</td><td>{{ t.status }}</td><td>{{ t.created }}</td></tr>{% endfor %}
    </table></div>""", v=g.lic, tickets=tickets)


@app.route("/client-logout", methods=["POST"])
def client_logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/client/tickets/new", methods=["POST"])
@client_required
def client_ticket_new():
    subject = request.form.get("subject", "").strip()[:120]
    body = request.form.get("body", "").strip()[:2000]
    if subject and body:
        db = get_db()
        cur = db.execute("INSERT INTO tickets(license_key,subject,created) VALUES(?,?,?)",
                         (g.lic["key"], subject, now()))
        db.execute("INSERT INTO ticket_messages(ticket_id,sender,body,created) VALUES(?,?,?,?)",
                   (cur.lastrowid, "client", body, now()))
        db.commit()
        send_discord_alert(f"🎫 New ticket #{cur.lastrowid} from **{g.lic['org']}**: {subject}")
        return redirect(url_for("client_ticket", tid=cur.lastrowid))
    return redirect(url_for("client_dashboard"))


@app.route("/client/tickets/<int:tid>", methods=["GET", "POST"])
@client_required
def client_ticket(tid):
    db = get_db()
    t = db.execute("SELECT * FROM tickets WHERE id=? AND license_key=?",
                   (tid, g.lic["key"])).fetchone()
    if not t:
        abort(404)
    if request.method == "POST" and t["status"] == "open":
        body = request.form.get("body", "").strip()[:2000]
        if body:
            db.execute("INSERT INTO ticket_messages(ticket_id,sender,body,created) VALUES(?,?,?,?)",
                       (tid, "client", body, now()))
            db.commit()
        return redirect(url_for("client_ticket", tid=tid))
    msgs = db.execute("SELECT * FROM ticket_messages WHERE ticket_id=? ORDER BY id", (tid,)).fetchall()
    return page("Ticket", """
    <h2>🎫 #{{ t.id }} - {{ t.subject }} ({{ t.status }})</h2>
    <a href="/client-dashboard">&larr; Dashboard</a>
    <div class="card">{% for m in msgs %}
      <div class="{{ 'them' if m.sender=='support' else 'me' }}"><b>{{ m.sender }}</b> · {{ m.created }}<br>{{ m.body }}</div>
    {% endfor %}</div>
    {% if t.status == 'open' %}
    <div class="card"><form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
      <textarea name="body" rows="3" placeholder="Write a message..." required></textarea>
      <button type="submit">Send</button></form></div>{% endif %}""", t=t, msgs=msgs)


# ------------------------------------------------------------------
# Health check (UptimeRobot এখানে পিং করবে, সার্ভার জেগে থাকবে)
# ------------------------------------------------------------------
@app.route("/health")
@limiter.exempt
def health():
    return "OK"


# ------------------------------------------------------------------
# Discord bot - Slash (/) কমান্ড, শুধু Administrator-দের জন্য
# ------------------------------------------------------------------
intents = discord.Intents.default()
bot = commands.Bot(command_prefix=commands.when_mentioned, intents=intents)
GUILD_ID = os.environ.get("DISCORD_GUILD_ID")  # ঐচ্ছিক: দিলে কমান্ড সাথে সাথে আসে


async def _setup_hook():
    if GUILD_ID:
        guild = discord.Object(id=int(GUILD_ID))
        bot.tree.copy_global_to(guild=guild)
        await bot.tree.sync(guild=guild)
    else:
        await bot.tree.sync()


bot.setup_hook = _setup_hook


def q_one(sql, args=()):
    conn = connect()
    v = conn.execute(sql, args).fetchone()[0]
    conn.close()
    return v


def q_all(sql, args=()):
    conn = connect()
    rows = conn.execute(sql, args).fetchall()
    conn.close()
    return rows


def slash(name, desc):
    def deco(fn):
        fn = app_commands.checks.has_permissions(administrator=True)(fn)
        fn = app_commands.default_permissions(administrator=True)(fn)
        fn = app_commands.guild_only()(fn)
        return bot.tree.command(name=name, description=desc)(fn)
    return deco


@bot.event
async def on_ready():
    print(f"Discord Bot logged in as {bot.user.name}")


@bot.tree.error
async def on_app_error(interaction: discord.Interaction, error):
    if isinstance(error, app_commands.MissingPermissions):
        msg = "⛔ শুধু সার্ভারের Administrator এই কমান্ড চালাতে পারবে।"
    else:
        print(f"Command error: {error}")
        msg = "⚠️ কিছু একটা সমস্যা হয়েছে।"
    if interaction.response.is_done():
        await interaction.followup.send(msg, ephemeral=True)
    else:
        await interaction.response.send_message(msg, ephemeral=True)


@bot.tree.command(name="report", description="সিস্টেমের বর্তমান অবস্থা")
@app_commands.guild_only()
async def report(interaction: discord.Interaction):
    lic = q_one("SELECT COUNT(*) FROM licenses")
    op = q_one("SELECT COUNT(*) FROM tickets WHERE status='open'")
    await interaction.response.send_message(
        f"🛡️ ISS Report: system active.\nLicenses: {lic} | Open tickets: {op}")


@bot.tree.command(name="weekly_report", description="গত ৭ দিনের রিপোর্ট")
@app_commands.guild_only()
async def weekly_report(interaction: discord.Interaction):
    since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M")
    nl = q_one("SELECT COUNT(*) FROM licenses WHERE created>=?", (since,))
    nt = q_one("SELECT COUNT(*) FROM tickets WHERE created>=?", (since,))
    op = q_one("SELECT COUNT(*) FROM tickets WHERE status='open'")
    await interaction.response.send_message(
        f"📈 ISS Weekly Report (7 days)\nNew licenses: {nl} | New tickets: {nt} | Open tickets now: {op}")


@slash("setalert", "এই চ্যানেলে অ্যালার্ট পাঠানো শুরু করো")
async def setalert(interaction: discord.Interaction):
    conn = connect()
    conn.execute("INSERT OR REPLACE INTO settings VALUES('alert_channel', ?)",
                 (str(interaction.channel_id),))
    conn.commit()
    conn.close()
    await interaction.response.send_message("✅ এখন থেকে অ্যালার্ট এই চ্যানেলে আসবে।")


@slash("licenses", "সর্বশেষ ১৫টি লাইসেন্স দেখাও")
async def licenses_cmd(interaction: discord.Interaction):
    rows = q_all("SELECT key,name,org,plan,expiry FROM licenses ORDER BY created DESC LIMIT 15")
    if not rows:
        return await interaction.response.send_message("কোনো লাইসেন্স নেই।", ephemeral=True)
    lines = [f"`{r['key']}` | {r['name']} ({r['org']}) | {r['plan']} | {r['expiry']}" for r in rows]
    await interaction.response.send_message("🔑 **Licenses**\n" + "\n".join(lines), ephemeral=True)


@slash("newlicense", "নতুন ক্লায়েন্ট লাইসেন্স তৈরি করো")
@app_commands.describe(name="ক্লায়েন্টের নাম", org="প্রতিষ্ঠানের নাম",
                       plan="প্ল্যান", days="কত দিনের মেয়াদ (ডিফল্ট ৩৬৫)")
async def newlicense(interaction: discord.Interaction, name: str, org: str,
                     plan: Literal["Basic Plan", "Pro Plan", "Enterprise Plan"] = "Basic Plan",
                     days: app_commands.Range[int, 1, 3650] = 365):
    key = "KEY-" + secrets.token_hex(6).upper()
    user = "client" + secrets.token_hex(2)
    pwd = secrets.token_urlsafe(9)
    expiry = (date.today() + timedelta(days=days)).isoformat()
    conn = connect()
    conn.execute("INSERT INTO licenses VALUES(?,?,?,?,?,?,?,?,?)",
                 (key, name, org, expiry, 5, plan, user, generate_password_hash(pwd), now()))
    conn.commit()
    conn.close()
    # শুধু আপনি দেখতে পাবেন (ephemeral)
    await interaction.response.send_message(
        f"🔑 **নতুন লাইসেন্স** (শুধু আপনি দেখছেন)\nClient: {name} ({org}) | {plan}\n"
        f"License Key: `{key}`\nUsername: `{user}`\nPassword: `{pwd}`\nExpiry: {expiry}\n"
        f"⚠️ পাসওয়ার্ড আর দেখা যাবে না, এখনই ক্লায়েন্টকে দিন।", ephemeral=True)
    send_discord_alert(f"🔑 New license `{key}` | **{name}** ({org}) | {plan}")


@slash("deletelicense", "লাইসেন্স মুছে ফেলো")
@app_commands.describe(key="লাইসেন্স কী, যেমন KEY-ABC123")
async def deletelicense(interaction: discord.Interaction, key: str):
    conn = connect()
    cur = conn.execute("DELETE FROM licenses WHERE key=?", (key.strip(),))
    conn.commit()
    conn.close()
    await interaction.response.send_message(
        "🗑️ মুছে ফেলা হয়েছে।" if cur.rowcount else "⚠️ এই কী পাওয়া যায়নি।", ephemeral=True)


@slash("tickets", "খোলা সাপোর্ট টিকিটের তালিকা")
async def tickets_cmd(interaction: discord.Interaction):
    rows = q_all("""SELECT t.id,t.subject,t.created,l.org FROM tickets t
        LEFT JOIN licenses l ON l.key=t.license_key WHERE t.status='open' ORDER BY t.id DESC LIMIT 15""")
    if not rows:
        return await interaction.response.send_message("✅ কোনো খোলা টিকিট নেই।")
    lines = [f"#{r['id']} | {r['org']} | {r['subject']} | {r['created']}" for r in rows]
    await interaction.response.send_message("🎫 **Open tickets**\n" + "\n".join(lines))


def run_discord_bot():
    if not BOT_TOKEN:
        print("DISCORD_BOT_TOKEN not set - bot disabled.")
        return
    try:
        asyncio.run(bot.start(BOT_TOKEN))
    except Exception as e:
        print(f"Bot error: {e}")


init_db()

if __name__ == "__main__":
    threading.Thread(target=run_discord_bot, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG", "0") == "1", use_reloader=False)
