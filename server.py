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
from flask import (Flask, render_template_string, request, redirect,
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
@app.route("/")
def home():
    return page("ISS Security", """
    <div style="text-align:center;padding:40px">
      <h1>🛡️ ISS Enterprise & Cloud Security Platform</h1>
      <p>System status: Active & Secured</p><br>
      <a class="btn" href="/client-login">Client Portal</a>
      <a class="btn btn2" href="/admin">Admin Panel</a>
    </div>""")


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
