import os
import sys
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
from flask import (Flask, Response, send_from_directory, render_template_string, request, redirect,
                   url_for, session, abort, g)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

try:
    sys.stdout.reconfigure(line_buffering=True)  # Render লগে সাথে সাথে লেখা দেখাবে
except Exception:
    pass

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
BUILD = "v4-light-2026-10-11"

LANDING_HTML = r'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>International System Security (ISS) | Cyber Security Services</title>
<meta name="description" content="International System Security: cyber security services and a client platform for licenses, access and support.">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px);--bg:#07090c;--panel:#0c1117;--line:#1d2a35;--txt:#dce6ee;--mute:#7f93a3;--cy:#00d9ff;--am:#ffb224}
*{box-sizing:border-box;margin:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--txt);font:400 16px/1.65 'JetBrains Mono',ui-monospace,monospace;overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(255,255,255,.025) 0 1px,transparent 1px 3px),linear-gradient(rgba(0,217,255,.05) 1px,transparent 1px) 0 0/64px 64px,linear-gradient(90deg,rgba(0,217,255,.05) 1px,transparent 1px) 0 0/64px 64px,radial-gradient(80% 60% at 70% 0%,rgba(0,217,255,.09),transparent 70%)}
a{color:inherit;text-decoration:none}
:focus-visible{outline:2px solid var(--am);outline-offset:3px}
.wrap{max-width:1140px;margin:auto;padding:0 22px}
h1,h2,h3{font-family:'Chakra Petch',sans-serif;font-weight:700;line-height:1.05;letter-spacing:.01em}
nav{position:sticky;top:env(safe-area-inset-top,0px);z-index:5;background:rgba(7,9,12,.88);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
nav .wrap{display:flex;align-items:center;justify-content:space-between;height:64px}
.brand{display:flex;align-items:center;gap:12px;font:700 1.15rem 'Chakra Petch'}
.brand svg{width:30px;height:30px}
.links{display:flex;gap:26px;align-items:center;font-size:.85rem;color:var(--mute)}
.links a:hover{color:var(--cy)}
.btn{display:inline-block;padding:13px 26px;font:700 .95rem 'Chakra Petch';letter-spacing:.04em;background:var(--cy);color:#001014;clip-path:polygon(0 0,calc(100% - 12px) 0,100% 12px,100% 100%,12px 100%,0 calc(100% - 12px));transition:background .15s,transform .15s}
.btn:hover{background:#fff;transform:translateY(-2px)}
.btn.line{background:transparent;color:var(--txt);border:1px solid var(--mute);clip-path:none}
.btn.line:hover{border-color:var(--cy);color:var(--cy);background:transparent}
.hero{display:grid;grid-template-columns:1.05fr .95fr;gap:48px;align-items:center;padding:76px 0 90px}
.hero h1{font-size:clamp(2.6rem,6.2vw,4.9rem)}
.hero h1 em{display:block;font-style:normal;color:var(--cy);text-shadow:0 0 28px rgba(0,217,255,.45)}
.hero p{color:var(--mute);max-width:33rem;margin:24px 0 34px;font-size:.95rem}
.cta{display:flex;gap:14px;flex-wrap:wrap}
.hud{position:relative;background:var(--panel);border:1px solid var(--line);padding:0}
.hud:before,.hud:after,.card:before,.card:after{content:"";position:absolute;width:18px;height:18px;border:2px solid var(--cy);pointer-events:none}
.hud:before,.card:before{top:-1px;left:-1px;border-right:0;border-bottom:0}
.hud:after,.card:after{bottom:-1px;right:-1px;border-left:0;border-top:0}
.bar{display:flex;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--line);font-size:.75rem;color:var(--mute)}
.bar b{color:var(--am);font-weight:500}
#log{padding:20px 18px;min-height:216px;font-size:.84rem;color:#a8f3ff;white-space:pre-wrap}
#log .ok{color:#5dffb4}
.cur{display:inline-block;width:9px;height:1em;background:var(--cy);vertical-align:-2px;animation:bl 1s steps(1) infinite}
@keyframes bl{50%{opacity:0}}
.read{display:grid;grid-template-columns:repeat(3,1fr);border-top:1px solid var(--line)}
.read div{padding:14px 16px;border-right:1px solid var(--line);font-size:.72rem;color:var(--mute)}
.read div:last-child{border:0}.read strong{display:block;color:var(--txt);font-size:.95rem;margin-top:2px}
section{padding:84px 0}
h2{font-size:clamp(1.9rem,4vw,3rem);max-width:34rem}
.sub{color:var(--mute);max-width:36rem;margin:14px 0 42px;font-size:.92rem}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.card{position:relative;background:var(--panel);border:1px solid var(--line);padding:26px;transition:border-color .2s}
.card:hover{border-color:rgba(0,217,255,.5)}
.card code{display:inline-block;color:var(--am);font-size:.8rem;margin-bottom:12px}
.card h3{font-size:1.35rem;margin-bottom:8px}.card p{color:var(--mute);font-size:.88rem}
.seq{display:grid;grid-template-columns:repeat(3,1fr);gap:0;border:1px solid var(--line);background:var(--panel)}
.seq div{padding:30px;border-right:1px solid var(--line)}.seq div:last-child{border:0}
.seq b{color:var(--cy);font:700 .8rem 'JetBrains Mono'}
.seq h3{font-size:1.3rem;margin:8px 0}.seq p{color:var(--mute);font-size:.88rem}
.band{position:relative;border:1px solid var(--cy);padding:56px 30px;text-align:center;background:linear-gradient(180deg,rgba(0,217,255,.1),transparent)}
.band h2{margin:0 auto 12px;max-width:none}.band p{color:var(--mute);margin-bottom:28px;font-size:.92rem}
.soc{border:1px solid var(--line);max-width:680px;background:var(--panel)}
.s{display:flex;align-items:center;gap:16px;padding:18px 22px;border-bottom:1px solid var(--line);transition:background .15s,padding .15s}
.s:last-child{border:0}.s:hover{background:rgba(0,217,255,.07);padding-left:30px}
.s span{color:var(--mute);width:96px;font-size:.82rem}.s strong{font-weight:500}
.s em{margin-left:auto;font-style:normal;color:var(--cy);font-size:.8rem}
footer{border-top:1px solid var(--line);padding:28px 0;color:var(--mute);font-size:.78rem}
footer .wrap{display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px}
.term{border:1px solid var(--line);background:#05080b;max-width:820px;margin:0 auto;box-shadow:0 0 60px rgba(0,217,255,.08)}.tbar{display:flex;gap:7px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line);font-size:.72rem;color:var(--mute)}.tbar i{width:9px;height:9px;background:var(--line);display:block}.tbar i:first-child{background:var(--am)}.tbar span{margin-left:10px}#tout{padding:20px 18px;min-height:310px;font:400 .82rem/1.75 'JetBrains Mono',monospace;color:#a8f3ff;white-space:pre-wrap;overflow-x:auto}#tout .p{color:var(--am)}#tout .g{color:#5dffb4}#tout .m{color:var(--mute)}.brand img{height:38px;width:auto}.brand span{font-size:1rem}.lock{display:flex;align-items:center;gap:16px;margin-bottom:34px}.lock img{height:92px;width:auto;filter:drop-shadow(0 0 20px rgba(124,92,255,.55))}.lock b{display:block;font:700 1.05rem 'Chakra Petch';letter-spacing:.03em}.lock span{display:block;color:var(--am);font-size:.76rem;margin-top:2px}.seq4{grid-template-columns:repeat(4,1fr)}.seq4 div{padding:24px}
@media(max-width:860px){.brand span{display:none}.seq4{grid-template-columns:1fr}.hero{grid-template-columns:1fr;padding-top:40px}.grid,.seq{grid-template-columns:1fr}.seq div{border-right:0;border-bottom:1px solid var(--line)}.links a:not(.btn){display:none}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style></head><body>
<nav><div class="wrap"><a class="brand" href="#"><img src="/shield.png" alt="ISS logo"><span>International System Security</span></a>
<div class="links"><a href="#services">Services</a><a href="#platform">Platform</a><a href="#deploy">Deploy</a><a href="#connect">Connect</a><a class="btn" href="/client-login" style="padding:9px 20px;font-size:.85rem">Client Portal</a></div></div></nav>

<main class="wrap">
<header class="hero">
<div>
<div class="lock"><img src="/logo.png" alt="ISS shield logo"><div><b>International System Security</b><span>New window of world wide web</span></div></div>
<h1>Security operations,<em>under control.</em></h1>
<p>International System Security (ISS) delivers cyber security services and a client platform that keeps licenses, access and support in one place.</p>
<div class="cta"><a class="btn" href="/client-login">Open Client Portal</a><a class="btn line" href="https://discord.gg/mxRgm2R3ud" target="_blank" rel="noopener noreferrer">Join Discord</a></div>
</div>
<div class="hud" aria-label="System console">
<div class="bar"><span>iss-core / console</span><b>live</b></div>
<div id="log"></div>
<div class="read"><div>plan tiers<strong>3</strong></div><div>passwords<strong>hashed</strong></div><div>sign-in<strong>rate limited</strong></div></div>
</div>
</header>

<section id="services"><h2>Cyber security services.</h2><p class="sub">Protection for organizations that cannot afford downtime or data loss.</p>
<div class="grid">
<div class="card"><code>scan.vuln</code><h3>Vulnerability assessment</h3><p>Find weak points in systems and applications before attackers do.</p></div>
<div class="card"><code>test.pentest</code><h3>Penetration testing</h3><p>Controlled attack simulations that show what is really exposed.</p></div>
<div class="card"><code>net.guard</code><h3>Network security</h3><p>Secure configuration and monitoring of your network perimeter.</p></div>
<div class="card"><code>endpoint.av</code><h3>Endpoint protection</h3><p>Cloud-managed antivirus agents on the devices your team uses.</p></div>
<div class="card"><code>ir.respond</code><h3>Incident response</h3><p>Fast containment and recovery when something goes wrong.</p></div>
<div class="card"><code>advise.sec</code><h3>Security consulting</h3><p>Clear, practical advice on policy, risk and next steps.</p></div>
</div></section>

<section id="platform"><h2>The ISS client platform.</h2><p class="sub">Every client gets one place to manage protection and reach our team.</p>
<div class="seq seq4">
<div><b>/newlicense</b><h3>License registry</h3><p>Keys with plan and expiry date.</p></div>
<div><b>/client-login</b><h3>Client portal</h3><p>A private dashboard per client.</p></div>
<div><b>/tickets</b><h3>Support desk</h3><p>Ticket threads with our team.</p></div>
<div><b>/report</b><h3>Discord control</h3><p>Reports and alerts in your server.</p></div>
</div></section>

<section id="deploy"><h2>Deployment sequence</h2><p class="sub">From request to protected in three steps.</p>
<div class="seq">
<div><b>step 1</b><h3>Request a key</h3><p>Contact the team on Discord and receive your license, username and password.</p></div>
<div><b>step 2</b><h3>Authenticate</h3><p>Open the Client Portal and sign in with your license key.</p></div>
<div><b>step 3</b><h3>Operate</h3><p>Check your status and open a ticket whenever you need support.</p></div>
</div></section>

<section><div class="band card"><h2>Need a license?</h2><p>Tell us about your organization on Discord and we will set you up.</p><a class="btn" href="https://discord.gg/mxRgm2R3ud" target="_blank" rel="noopener noreferrer">Join Discord</a></div></section>

<section id="connect"><h2>Contact Muhib.</h2><p class="sub">Pick a channel. Messages and follows are welcome.</p>
<div class="soc">
<a class="s" href="https://instagram.com/mrshadow6000" target="_blank" rel="noopener noreferrer"><span>instagram</span><strong>mrshadow6000</strong><em>follow</em></a>
<a class="s" href="https://discord.gg/mxRgm2R3ud" target="_blank" rel="noopener noreferrer"><span>discord</span><strong>ISS community</strong><em>join</em></a>
<a class="s" href="https://www.linkedin.com/search/results/people/?keywords=Muhib%20Ibrahim" target="_blank" rel="noopener noreferrer"><span>linkedin</span><strong>Muhib Ibrahim</strong><em>connect</em></a>
<a class="s" href="https://github.com/muhibibrahim-6" target="_blank" rel="noopener noreferrer"><span>github</span><strong>muhibibrahim-6</strong><em>follow</em></a>
<a class="s" href="https://medium.com/@Muhibibrahim" target="_blank" rel="noopener noreferrer"><span>medium</span><strong>@Muhibibrahim</strong><em>read</em></a>
</div></section>
<section id="terminal"><h2>Watch it work.</h2><p class="sub">A simulated session of the ISS toolkit, running on a loop.</p>
<div class="term"><div class="tbar"><i></i><i></i><i></i><span>iss@secure: ~ (simulated demo)</span></div><pre id="tout" aria-label="Simulated terminal session"></pre></div></section>
</main>
<footer><div class="wrap"><span>© 2026 International System Security · build __BUILD__</span><span><a href="/client-login">client login</a> / <a href="/admin">admin</a></span></div></footer>
<script>
(function(){
var L=['> boot iss-core','> load license.registry ..... [ok]','> load client.portal ....... [ok]','> load support.desk ........ [ok]','> link discord.control ..... [ok]','> status: ready'];
var el=document.getElementById('log'),cur='<span class="cur"></span>';
function paint(t){el.innerHTML=t.replace(/\[ok\]/g,'<span class="ok">[ok]</span>')+cur}
if(window.matchMedia('(prefers-reduced-motion:reduce)').matches){paint(L.join('\n'));return}
var i=0,j=0,out='';
(function tick(){if(i>=L.length){paint(out);return}
var line=L[i];out+=line.charAt(j++);paint(out);
if(j>=line.length){out+='\n';i++;j=0;setTimeout(tick,260)}else setTimeout(tick,22)})();
})();
</script>
<script>
(function(){
var el=document.getElementById('tout');if(!el)return;
var P='<span class="p">iss@secure:~$</span> ';
var S=[['c','iss scan --target client-network'],['o','<span class="m">resolving hosts</span> ........ <span class="g">done</span>'],['o','<span class="m">checking open ports</span> ... <span class="g">done</span>'],['b','scanning files'],['o','<span class="m">verifying license</span> ..... <span class="g">valid</span>'],['o','<span class="g">scan complete: no threats found in this demo</span>'],['c','iss status'],['o','protection ........ <span class="g">active</span>'],['o','plan ............. pro'],['c','iss support --new "need help"'],['o','<span class="g">ticket created. our team will reply in the thread.</span>']];
var html='';
function esc(t){return t.replace(/&/g,'&amp;').replace(/</g,'&lt;')}
function draw(x){el.innerHTML=html+(x||'')+'<span class="cur"></span>'}
function sleep(n){return new Promise(function(r){setTimeout(r,n)})}
function bar(l,p){return '<span class="m">'+l+'</span> ['+'█'.repeat(p)+'░'.repeat(10-p)+'] '+(p*10)+'%'}
if(window.matchMedia('(prefers-reduced-motion:reduce)').matches){S.forEach(function(s){html+=(s[0]=='c'?P+esc(s[1]):s[0]=='b'?bar(s[1],10):s[1])+'\n'});draw();return}
async function run(){
while(true){html='';draw();
for(var i=0;i<S.length;i++){var s=S[i];
if(s[0]=='c'){html+=P;for(var k=1;k<=s[1].length;k++){draw(esc(s[1].slice(0,k)));await sleep(40)}html+=esc(s[1])+'\n';draw();await sleep(380)}
else if(s[0]=='o'){html+=s[1]+'\n';draw();await sleep(430)}
else{for(var p=0;p<=10;p++){draw(bar(s[1],p));await sleep(130)}html+=bar(s[1],10)+'\n';draw();await sleep(300)}}
await sleep(3800)}}
var started=false;function go(){if(!started){started=true;run()}}
if('IntersectionObserver' in window){new IntersectionObserver(function(e){if(e[0].isIntersecting)go()},{threshold:.25}).observe(el)}else go();
})();
</script>
</body></html>
'''


@app.route("/")
def home():
    resp = Response(LANDING_HTML.replace("__BUILD__", BUILD), mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store"
    return resp


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.route("/logo.png")
def logo_png():
    return send_from_directory(BASE_DIR, "iss-logo.png", max_age=3600)


@app.route("/shield.png")
def shield_png():
    return send_from_directory(BASE_DIR, "iss-shield.png", max_age=3600)


@app.route("/version")
def version():
    return BUILD


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
