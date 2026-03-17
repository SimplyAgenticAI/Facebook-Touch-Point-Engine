
from flask import Flask, request, redirect, session, url_for, Response
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import csv
import io
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
DB_NAME = os.environ.get("DB_NAME", "touchpoints.db")

TOUCHPOINT_FIELDS = [
    ("reactions", "Reactions"),
    ("comments", "Comments"),
    ("dms", "DMs"),
    ("invites_to_follow", "Invites to Follow"),
    ("friend_requests_sent", "Friend Requests Sent"),
    ("friend_requests_accepted", "Friend Requests Accepted"),
    ("follows", "Follows"),
    ("story_replies", "Story Replies"),
    ("post_shares", "Post Shares"),
    ("page_invites", "Page Invites"),
    ("profile_visits", "Profile Visits"),
    ("group_invites", "Group Invites"),
    ("event_invites", "Event Invites"),
    ("post_likes", "Post Likes"),
    ("video_views", "Video Views"),
    ("voice_notes", "Voice Notes"),
    ("follow_ups", "Follow Ups"),
    ("lead_conversations", "Lead Conversations"),
]

PERIODS = {"daily": 1, "weekly": 7, "monthly": 30}


def utcnow():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def today_str():
    return datetime.utcnow().strftime("%Y-%m-%d")


def parse_dt(value):
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    return None


def dt_local_input(value=None):
    dt = parse_dt(value) if value else datetime.utcnow()
    if not dt:
        dt = datetime.utcnow()
    return dt.strftime("%Y-%m-%dT%H:%M")


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(conn, table_name, column_name):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(row[1] == column_name for row in rows)


def add_column_if_missing(conn, table_name, column_name, column_sql):
    if not column_exists(conn, table_name, column_name):
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}")


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            display_name TEXT,
            role TEXT NOT NULL DEFAULT 'client',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS client_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            company_name TEXT,
            report_email TEXT,
            send_daily INTEGER NOT NULL DEFAULT 0,
            send_weekly INTEGER NOT NULL DEFAULT 0,
            send_monthly INTEGER NOT NULL DEFAULT 0,
            cc_email TEXT,
            client_notes TEXT,
            last_daily_sent_at TEXT,
            last_weekly_sent_at TEXT,
            last_monthly_sent_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS touchpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            client TEXT,
            platform TEXT NOT NULL DEFAULT 'Facebook',
            date TEXT NOT NULL,
            notes TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    for field, _label in TOUCHPOINT_FIELDS:
        add_column_if_missing(conn, "touchpoints", field, "INTEGER NOT NULL DEFAULT 0")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS report_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            period TEXT NOT NULL,
            sent_to TEXT NOT NULL,
            sent_at TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 1,
            message TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS mail_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL DEFAULT 'gmail',
            sender_name TEXT,
            sender_email TEXT,
            smtp_host TEXT,
            smtp_port INTEGER NOT NULL DEFAULT 587,
            smtp_username TEXT,
            smtp_password TEXT,
            smtp_use_tls INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    # backward compatibility
    add_column_if_missing(conn, "users", "email", "TEXT")
    add_column_if_missing(conn, "users", "display_name", "TEXT")
    add_column_if_missing(conn, "users", "is_active", "INTEGER NOT NULL DEFAULT 1")
    add_column_if_missing(conn, "users", "created_at", "TEXT")
    add_column_if_missing(conn, "users", "updated_at", "TEXT")
    add_column_if_missing(conn, "touchpoints", "user_id", "INTEGER")
    add_column_if_missing(conn, "touchpoints", "platform", "TEXT NOT NULL DEFAULT 'Facebook'")
    add_column_if_missing(conn, "touchpoints", "notes", "TEXT")
    add_column_if_missing(conn, "touchpoints", "created_by", "TEXT")
    add_column_if_missing(conn, "touchpoints", "created_at", "TEXT")
    add_column_if_missing(conn, "client_settings", "cc_email", "TEXT")
    add_column_if_missing(conn, "client_settings", "client_notes", "TEXT")

    now = utcnow()
    conn.execute("UPDATE users SET created_at = COALESCE(created_at, ?), updated_at = COALESCE(updated_at, ?)", (now, now))
    conn.execute("UPDATE touchpoints SET created_at = COALESCE(created_at, date)")
    conn.execute("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('app_title', 'Touchpoint Tracker Pro')")

    if not conn.execute("SELECT id FROM mail_settings LIMIT 1").fetchone():
        conn.execute("""
            INSERT INTO mail_settings (
                provider, sender_name, sender_email, smtp_host, smtp_port,
                smtp_username, smtp_password, smtp_use_tls, created_at, updated_at
            ) VALUES ('gmail', '', '', 'smtp.gmail.com', 587, '', '', 1, ?, ?)
        """, (now, now))

    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    admin_email = os.environ.get("ADMIN_EMAIL", "")
    existing_admin = conn.execute("SELECT id FROM users WHERE username = ?", (admin_username,)).fetchone()
    if not existing_admin:
        conn.execute("""
            INSERT INTO users (username, password, email, display_name, role, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'admin', 1, ?, ?)
        """, (
            admin_username,
            generate_password_hash(admin_password),
            admin_email,
            "Admin",
            now,
            now,
        ))

    conn.commit()
    conn.close()


def login_required(role=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                return redirect(url_for("dashboard"))
            return func(*args, **kwargs)
        return wrapper
    return decorator


def nav_links():
    if "user_id" not in session:
        return "<a class='btn secondary' href='/'>Login</a><a class='btn' href='/register'>Create Account</a>"
    links = ["<a class='btn secondary' href='/dashboard'>Dashboard</a>"]
    if session.get("role") == "admin":
        links.extend([
            "<a class='btn secondary' href='/admin/clients'>Clients</a>",
            "<a class='btn secondary' href='/admin/reports'>Reports</a>",
            "<a class='btn secondary' href='/admin/mail'>Gmail</a>",
        ])
    else:
        links.extend([
            "<a class='btn secondary' href='/settings'>Settings</a>",
            "<a class='btn secondary' href='/my-reports'>My Reports</a>",
        ])
    links.append("<a class='btn red' href='/logout'>Logout</a>")
    return "".join(links)


def base_html(title, body, subtitle=""):
    return f"""
    <!doctype html>
    <html>
    <head>
      <meta charset='utf-8'>
      <meta name='viewport' content='width=device-width, initial-scale=1'>
      <title>{title}</title>
      <style>
        *{{box-sizing:border-box;}}
        body{{margin:0;font-family:Arial,Helvetica,sans-serif;background:#020617;color:#e5e7eb;}}
        .wrap{{max-width:1280px;margin:0 auto;padding:24px;}}
        .top{{display:flex;justify-content:space-between;gap:20px;align-items:center;flex-wrap:wrap;margin-bottom:20px;}}
        .brand{{font-size:28px;font-weight:700;color:white;}}
        .sub{{color:#94a3b8;margin-top:6px;}}
        .card{{background:#0f172a;border:1px solid #1e293b;border-radius:18px;padding:20px;margin-bottom:18px;box-shadow:0 20px 60px rgba(0,0,0,.25);}}
        .grid{{display:grid;gap:16px;}}
        .grid-2{{grid-template-columns:repeat(auto-fit,minmax(300px,1fr));}}
        .grid-3{{grid-template-columns:repeat(auto-fit,minmax(220px,1fr));}}
        .grid-4{{grid-template-columns:repeat(auto-fit,minmax(180px,1fr));}}
        .stat{{background:#111827;border:1px solid #1f2937;border-radius:16px;padding:18px;}}
        .stat .label{{font-size:13px;color:#94a3b8;}}
        .stat .value{{font-size:32px;font-weight:700;color:white;margin-top:8px;}}
        input, select, textarea{{width:100%;padding:12px 14px;margin-top:8px;border-radius:12px;border:1px solid #334155;background:#020617;color:#fff;}}
        textarea{{min-height:110px;resize:vertical;}}
        label{{display:block;margin-bottom:12px;color:#cbd5e1;font-size:14px;}}
        button, .btn{{display:inline-block;padding:12px 16px;border-radius:12px;border:none;background:#7c3aed;color:white;text-decoration:none;font-weight:700;cursor:pointer;}}
        .btn.secondary{{background:#1e293b;color:#e2e8f0;border:1px solid #334155;}}
        .btn.green{{background:#059669;}}
        .btn.red{{background:#dc2626;}}
        .btn.orange{{background:#ea580c;}}
        .btnrow{{display:flex;gap:10px;flex-wrap:wrap;}}
        table{{width:100%;border-collapse:collapse;margin-top:10px;}}
        th,td{{padding:10px 12px;border-bottom:1px solid #1e293b;text-align:left;font-size:14px;vertical-align:top;}}
        th{{color:#93c5fd;font-weight:700;}}
        .notice{{padding:14px 16px;border-radius:12px;margin-bottom:16px;background:#052e16;border:1px solid #166534;color:#dcfce7;}}
        .error{{padding:14px 16px;border-radius:12px;margin-bottom:16px;background:#450a0a;border:1px solid #991b1b;color:#fecaca;}}
        .muted{{color:#94a3b8;}}
        .pill{{display:inline-block;padding:6px 10px;border-radius:999px;background:#111827;border:1px solid #334155;color:#cbd5e1;font-size:12px;}}
        .field-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;}}
        .small{{font-size:12px;color:#94a3b8;}}
        .metric{{font-size:12px;color:#94a3b8;margin-top:4px;}}
        a{{color:#c4b5fd;}}
        .sticky{{position:sticky;top:12px;}}
        .section-title{{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;}}
      </style>
    </head>
    <body>
      <div class='wrap'>
        <div class='top'>
          <div>
            <div class='brand'>Touchpoint Tracker Pro</div>
            <div class='sub'>{subtitle}</div>
          </div>
          <div class='btnrow'>
            {nav_links()}
          </div>
        </div>
        {body}
      </div>
    </body>
    </html>
    """


def safe_int(form, key):
    value = str(form.get(key, "0")).strip()
    if not value:
        return 0
    try:
        return max(0, int(value))
    except ValueError:
        return 0


def selected_client_id():
    try:
        cid = int(session.get("active_client_id", 0))
        return cid
    except Exception:
        return 0


def set_active_client(client_id):
    session["active_client_id"] = int(client_id)


def clear_active_client():
    session.pop("active_client_id", None)


def ensure_client_settings(conn, user_id, email=""):
    row = conn.execute("SELECT * FROM client_settings WHERE user_id = ?", (user_id,)).fetchone()
    if row:
        return row
    now = utcnow()
    conn.execute("""
        INSERT INTO client_settings (
            user_id, company_name, report_email, send_daily, send_weekly, send_monthly,
            cc_email, client_notes, created_at, updated_at
        ) VALUES (?, '', ?, 0, 0, 0, '', '', ?, ?)
    """, (user_id, email, now, now))
    conn.commit()
    return conn.execute("SELECT * FROM client_settings WHERE user_id = ?", (user_id,)).fetchone()


def totals_from_rows(rows):
    totals = {field: 0 for field, _ in TOUCHPOINT_FIELDS}
    total_all = 0
    for row in rows:
        keys = row.keys() if hasattr(row, "keys") else []
        for field, _ in TOUCHPOINT_FIELDS:
            value = row[field] if field in keys else 0
            value = value or 0
            totals[field] += value
            total_all += value
    return totals, total_all


def get_period_rows(user_id, days):
    conn = get_db()
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    rows = conn.execute(
        "SELECT * FROM touchpoints WHERE user_id = ? AND date >= ? ORDER BY date DESC, id DESC",
        (user_id, since),
    ).fetchall()
    conn.close()
    return rows


def get_client_summary(conn, user_id):
    user = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'client'", (user_id,)).fetchone()
    if not user:
        return None
    settings = ensure_client_settings(conn, user_id, user["email"] or "")
    daily_rows = get_period_rows(user_id, 1)
    weekly_rows = get_period_rows(user_id, 7)
    monthly_rows = get_period_rows(user_id, 30)
    _a, daily_total = totals_from_rows(daily_rows)
    _b, weekly_total = totals_from_rows(weekly_rows)
    _c, monthly_total = totals_from_rows(monthly_rows)
    return {
        "user": user,
        "settings": settings,
        "daily_total": daily_total,
        "weekly_total": weekly_total,
        "monthly_total": monthly_total,
    }


def get_mail_settings(conn):
    row = conn.execute("SELECT * FROM mail_settings ORDER BY id ASC LIMIT 1").fetchone()
    if not row:
        now = utcnow()
        conn.execute("""
            INSERT INTO mail_settings (
                provider, sender_name, sender_email, smtp_host, smtp_port,
                smtp_username, smtp_password, smtp_use_tls, created_at, updated_at
            ) VALUES ('gmail', '', '', 'smtp.gmail.com', 587, '', '', 1, ?, ?)
        """, (now, now))
        conn.commit()
        row = conn.execute("SELECT * FROM mail_settings ORDER BY id ASC LIMIT 1").fetchone()
    return row


def get_effective_mail_config():
    conn = get_db()
    db_settings = get_mail_settings(conn)
    conn.close()
    return {
        "provider": "gmail",
        "sender_name": os.environ.get("SMTP_SENDER_NAME", db_settings["sender_name"] or ""),
        "sender_email": os.environ.get("SMTP_FROM", db_settings["sender_email"] or ""),
        "smtp_host": os.environ.get("SMTP_HOST", db_settings["smtp_host"] or "smtp.gmail.com"),
        "smtp_port": int(os.environ.get("SMTP_PORT", str(db_settings["smtp_port"] or 587))),
        "smtp_username": os.environ.get("SMTP_USER", db_settings["smtp_username"] or ""),
        "smtp_password": os.environ.get("SMTP_PASS", db_settings["smtp_password"] or ""),
        "smtp_use_tls": os.environ.get("SMTP_USE_TLS", str(db_settings["smtp_use_tls"] or 1)).lower() in ("1", "true", "yes", "on"),
    }


def report_subject(period, client_name):
    return f"{client_name} {period.capitalize()} Touchpoint Report"


def build_report_html(user, settings, period, rows):
    totals, grand_total = totals_from_rows(rows)
    item_rows = ""
    for field, label in TOUCHPOINT_FIELDS:
        item_rows += f"<tr><td>{label}</td><td>{totals[field]}</td></tr>"

    activity_rows = ""
    for row in rows[:50]:
        row_total = sum((row[field] or 0) for field, _ in TOUCHPOINT_FIELDS)
        activity_rows += (
            f"<tr><td>{row['date']}</td><td>{row['platform']}</td>"
            f"<td>{row_total}</td><td>{row['notes'] or ''}</td></tr>"
        )

    client_name = user["display_name"] or user["username"]
    company = settings["company_name"] or client_name
    return f"""
    <html>
    <body style='font-family:Arial,Helvetica,sans-serif;color:#111827;'>
      <h2>{company} {period.capitalize()} Touchpoint Report</h2>
      <p>This report shows proof of work completed for your social media outreach and relationship-building activity.</p>
      <p><strong>Total touchpoints:</strong> {grand_total}</p>
      <table border='1' cellpadding='8' cellspacing='0' style='border-collapse:collapse;width:100%;max-width:700px;'>
        <tr><th align='left'>Category</th><th align='left'>Count</th></tr>
        {item_rows}
      </table>
      <h3 style='margin-top:24px;'>Recent logged activity</h3>
      <table border='1' cellpadding='8' cellspacing='0' style='border-collapse:collapse;width:100%;max-width:900px;'>
        <tr><th align='left'>Date</th><th align='left'>Platform</th><th align='left'>Touchpoints</th><th align='left'>Notes</th></tr>
        {activity_rows if activity_rows else "<tr><td colspan='4'>No activity logged for this period.</td></tr>"}
      </table>
    </body>
    </html>
    """


def send_email_report(user_id, period):
    if period not in PERIODS:
        return False, "Invalid period"

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        conn.close()
        return False, "User not found"

    settings = ensure_client_settings(conn, user_id, user["email"] or "")
    recipient = (settings["report_email"] or user["email"] or "").strip()
    cc_email = (settings["cc_email"] or "").strip()
    if not recipient:
        conn.close()
        return False, "No report email configured for this client"

    rows = get_period_rows(user_id, PERIODS[period])
    html = build_report_html(user, settings, period, rows)

    cfg = get_effective_mail_config()
    if not cfg["smtp_host"] or not cfg["sender_email"] or not cfg["smtp_username"] or not cfg["smtp_password"]:
        conn.execute(
            "INSERT INTO report_log (user_id, period, sent_to, sent_at, success, message) VALUES (?, ?, ?, ?, 0, ?)",
            (user_id, period, recipient, utcnow(), "Gmail is not configured yet"),
        )
        conn.commit()
        conn.close()
        return False, "Gmail is not configured yet. Add your Gmail address and app password in Admin > Gmail."

    msg = MIMEMultipart("alternative")
    display_from = cfg["sender_email"]
    if cfg["sender_name"]:
        display_from = f"{cfg['sender_name']} <{cfg['sender_email']}>"
    msg["Subject"] = report_subject(period, user["display_name"] or user["username"])
    msg["From"] = display_from
    msg["To"] = recipient
    if cc_email:
        msg["Cc"] = cc_email
    msg.attach(MIMEText(html, "html"))

    recipients = [recipient] + ([cc_email] if cc_email else [])

    try:
        server = smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=20)
        if cfg["smtp_use_tls"]:
            server.starttls()
        server.login(cfg["smtp_username"], cfg["smtp_password"])
        server.sendmail(cfg["sender_email"], recipients, msg.as_string())
        server.quit()

        now = utcnow()
        last_field = f"last_{period}_sent_at"
        conn.execute(
            f"UPDATE client_settings SET {last_field} = ?, updated_at = ? WHERE user_id = ?",
            (now, now, user_id),
        )
        conn.execute(
            "INSERT INTO report_log (user_id, period, sent_to, sent_at, success, message) VALUES (?, ?, ?, ?, 1, ?)",
            (user_id, period, ", ".join(recipients), now, "Report sent successfully"),
        )
        conn.commit()
        conn.close()
        return True, f"{period.capitalize()} report sent to {', '.join(recipients)}"
    except Exception as exc:
        conn.execute(
            "INSERT INTO report_log (user_id, period, sent_to, sent_at, success, message) VALUES (?, ?, ?, ?, 0, ?)",
            (user_id, period, ", ".join(recipients), utcnow(), str(exc)),
        )
        conn.commit()
        conn.close()
        return False, str(exc)


def maybe_send_due_reports():
    conn = get_db()
    users = conn.execute("""
        SELECT u.id AS user_id, u.username, u.is_active, cs.*
        FROM users u
        JOIN client_settings cs ON cs.user_id = u.id
        WHERE u.role = 'client' AND u.is_active = 1
    """).fetchall()
    conn.close()

    results = []
    now = datetime.utcnow()
    for row in users:
        for period in ("daily", "weekly", "monthly"):
            if not row[f"send_{period}"]:
                continue
            last_sent = parse_dt(row[f"last_{period}_sent_at"])
            due = last_sent is None or ((now - last_sent) >= timedelta(days=PERIODS[period]))
            if due:
                success, message = send_email_report(row["user_id"], period)
                results.append({"user": row["username"], "period": period, "success": success, "message": message})
    return results


def quick_form_html(prefix=""):
    return "".join(
        [f"<label>{label}<input type='number' min='0' name='{prefix}{field}' value='0'></label>" for field, label in TOUCHPOINT_FIELDS]
    )


@app.route("/", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if not user:
            error = "No account found with that username."
        elif not user["is_active"]:
            error = "This account is inactive."
        elif not check_password_hash(user["password"], password):
            error = "Incorrect password."
        else:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            if user["role"] != "admin":
                session["active_client_id"] = user["id"]
            return redirect(url_for("dashboard"))

    body = ""
    if error:
        body += f"<div class='error'>{error}</div>"
    body += """
    <div class='grid grid-2'>
      <div class='card'>
        <h2>Login</h2>
        <p class='muted'>Track every touchpoint, prove the work, and send polished client reports.</p>
        <form method='POST'>
          <label>Username<input name='username' placeholder='Enter username' required></label>
          <label>Password<input name='password' type='password' placeholder='Enter password' required></label>
          <button type='submit'>Login</button>
        </form>
      </div>
      <div class='card'>
        <h2>What this app tracks</h2>
        <p class='muted'>Facebook touchpoints like reactions, comments, DMs, invites to follow, friend requests, follow ups, lead conversations, story replies, page invites, shares, and more.</p>
        <div class='btnrow'>
          <a class='btn' href='/register'>Create First-Time Account</a>
        </div>
      </div>
    </div>
    """
    return base_html("Login", body, "Client proof reports for social media growth work")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    notice = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        email = request.form.get("email", "").strip()
        display_name = request.form.get("display_name", "").strip() or username

        if len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            conn = get_db()
            existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                error = "That username is already taken."
            else:
                now = utcnow()
                conn.execute("""
                    INSERT INTO users (username, password, email, display_name, role, is_active, created_at, updated_at)
                    VALUES (?, ?, ?, ?, 'client', 1, ?, ?)
                """, (username, generate_password_hash(password), email, display_name, now, now))
                user_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
                ensure_client_settings(conn, user_id, email)
                conn.commit()
                conn.close()
                notice = "Account created. You can log in now."

    body = ""
    if error:
        body += f"<div class='error'>{error}</div>"
    if notice:
        body += f"<div class='notice'>{notice}</div>"
    body += """
    <div class='card' style='max-width:700px;'>
      <h2>Create Account</h2>
      <form method='POST'>
        <label>Display Name<input name='display_name' placeholder='Client name or company name'></label>
        <label>Username<input name='username' placeholder='Choose a username' required></label>
        <label>Email<input name='email' type='email' placeholder='Report email'></label>
        <label>Password<input name='password' type='password' placeholder='Choose a password' required></label>
        <label>Confirm Password<input name='confirm_password' type='password' placeholder='Re-enter password' required></label>
        <button type='submit'>Create Account</button>
      </form>
    </div>
    """
    return base_html("Create Account", body, "First-time users can create their own client account here")


@app.route("/dashboard")
@login_required()
def dashboard():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("client_dashboard"))


@app.route("/admin", methods=["GET", "POST"])
@login_required(role="admin")
def admin_dashboard():
    notice = ""
    error = ""
    conn = get_db()
    clients = conn.execute("""
        SELECT id, username, display_name, email, is_active
        FROM users
        WHERE role = 'client'
        ORDER BY COALESCE(display_name, username), username
    """).fetchall()

    active_id = selected_client_id()
    if not active_id and clients:
        active_id = clients[0]["id"]
        set_active_client(active_id)

    if request.method == "POST":
        action = request.form.get("action", "").strip()

        if action == "switch_client":
            client_id = int(request.form.get("user_id", "0") or "0")
            if conn.execute("SELECT id FROM users WHERE id = ? AND role = 'client'", (client_id,)).fetchone():
                set_active_client(client_id)
                active_id = client_id
                notice = "Active client switched."
            else:
                error = "Please select a valid client."

        elif action == "add_client":
            display_name = request.form.get("display_name", "").strip()
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "").strip()
            report_email = request.form.get("report_email", "").strip()
            if not username or len(username) < 3:
                error = "Client username must be at least 3 characters."
            elif not password or len(password) < 6:
                error = "Client password must be at least 6 characters."
            elif conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
                error = "That username already exists."
            else:
                now = utcnow()
                conn.execute("""
                    INSERT INTO users (username, password, email, display_name, role, is_active, created_at, updated_at)
                    VALUES (?, ?, ?, ?, 'client', 1, ?, ?)
                """, (
                    username,
                    generate_password_hash(password),
                    email,
                    display_name or username,
                    now,
                    now,
                ))
                new_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
                ensure_client_settings(conn, new_id, report_email or email)
                conn.execute("""
                    UPDATE client_settings SET report_email = ?, updated_at = ? WHERE user_id = ?
                """, (report_email or email, now, new_id))
                conn.commit()
                set_active_client(new_id)
                active_id = new_id
                notice = "Client added and selected."

        elif action == "save_client_profile":
            client_id = int(request.form.get("user_id", "0") or "0")
            display_name = request.form.get("display_name", "").strip()
            email = request.form.get("email", "").strip()
            company_name = request.form.get("company_name", "").strip()
            report_email = request.form.get("report_email", "").strip()
            cc_email = request.form.get("cc_email", "").strip()
            client_notes = request.form.get("client_notes", "").strip()
            send_daily = 1 if request.form.get("send_daily") == "on" else 0
            send_weekly = 1 if request.form.get("send_weekly") == "on" else 0
            send_monthly = 1 if request.form.get("send_monthly") == "on" else 0
            is_active = 1 if request.form.get("is_active") == "on" else 0
            user = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'client'", (client_id,)).fetchone()
            if not user:
                error = "Client not found."
            else:
                ensure_client_settings(conn, client_id, email)
                now = utcnow()
                conn.execute("UPDATE users SET display_name = ?, email = ?, is_active = ?, updated_at = ? WHERE id = ?",
                             (display_name, email, is_active, now, client_id))
                conn.execute("""
                    UPDATE client_settings
                    SET company_name = ?, report_email = ?, cc_email = ?, client_notes = ?,
                        send_daily = ?, send_weekly = ?, send_monthly = ?, updated_at = ?
                    WHERE user_id = ?
                """, (company_name, report_email, cc_email, client_notes, send_daily, send_weekly, send_monthly, now, client_id))
                conn.commit()
                notice = "Client profile updated."

        elif action == "log_touchpoints":
            client_id = int(request.form.get("user_id", "0") or "0")
            platform = request.form.get("platform", "Facebook").strip() or "Facebook"
            date_raw = request.form.get("date", "").strip()
            date = parse_dt(date_raw).strftime("%Y-%m-%d %H:%M:%S") if parse_dt(date_raw) else utcnow()
            notes = request.form.get("notes", "").strip()
            user = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'client'", (client_id,)).fetchone()
            if not user:
                error = "Please select a valid client."
            else:
                values = [safe_int(request.form, field) for field, _ in TOUCHPOINT_FIELDS]
                total_logged = sum(values)
                if total_logged <= 0 and not notes:
                    error = "Add at least one touchpoint count or a note."
                else:
                    conn.execute(f"""
                        INSERT INTO touchpoints (
                            user_id, client, platform, date, notes, created_by, created_at,
                            {', '.join(field for field, _ in TOUCHPOINT_FIELDS)}
                        ) VALUES (
                            ?, ?, ?, ?, ?, ?, ?,
                            {', '.join('?' for _ in TOUCHPOINT_FIELDS)}
                        )
                    """, [
                        user["id"],
                        user["username"],
                        platform,
                        date,
                        notes,
                        session.get("username", "admin"),
                        utcnow(),
                        *values,
                    ])
                    conn.commit()
                    set_active_client(client_id)
                    active_id = client_id
                    notice = f"Saved {total_logged} touchpoints for {user['display_name'] or user['username']}."

        elif action == "quick_add":
            client_id = int(request.form.get("user_id", "0") or "0")
            category = request.form.get("category", "").strip()
            qty = max(1, safe_int(request.form, "qty"))
            notes = request.form.get("notes", "").strip()
            user = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'client'", (client_id,)).fetchone()
            valid_fields = {field for field, _ in TOUCHPOINT_FIELDS}
            if not user:
                error = "Please select a valid client."
            elif category not in valid_fields:
                error = "Choose a valid touchpoint type."
            else:
                values = [0 for _ in TOUCHPOINT_FIELDS]
                idx = [field for field, _ in TOUCHPOINT_FIELDS].index(category)
                values[idx] = qty
                conn.execute(f"""
                    INSERT INTO touchpoints (
                        user_id, client, platform, date, notes, created_by, created_at,
                        {', '.join(field for field, _ in TOUCHPOINT_FIELDS)}
                    ) VALUES (
                        ?, ?, 'Facebook', ?, ?, ?, ?,
                        {', '.join('?' for _ in TOUCHPOINT_FIELDS)}
                    )
                """, [
                    user["id"],
                    user["username"],
                    utcnow(),
                    notes or f"Quick add: {category.replace('_', ' ').title()}",
                    session.get("username", "admin"),
                    utcnow(),
                    *values,
                ])
                conn.commit()
                set_active_client(client_id)
                active_id = client_id
                notice = f"Quick-added {qty} {category.replace('_', ' ')} for {user['display_name'] or user['username']}."

        elif action == "send_report":
            client_id = int(request.form.get("user_id", "0") or "0")
            period = request.form.get("period", "daily").strip()
            success, msg = send_email_report(client_id, period)
            notice = msg if success else ""
            error = "" if success else msg
            active_id = client_id
            set_active_client(client_id)

    selected = get_client_summary(conn, active_id) if active_id else None
    total_clients = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role='client'").fetchone()["c"]
    total_entries = conn.execute("SELECT COUNT(*) AS c FROM touchpoints").fetchone()["c"]
    all_rows = conn.execute(f"SELECT {', '.join(field for field, _ in TOUCHPOINT_FIELDS)} FROM touchpoints").fetchall()
    _totals, total_touchpoints = totals_from_rows(all_rows)
    recent = []
    selected_recent = []
    if active_id:
        selected_recent = conn.execute(
            f"SELECT id, date, platform, notes, {', '.join(field for field, _ in TOUCHPOINT_FIELDS)} FROM touchpoints WHERE user_id = ? ORDER BY date DESC, id DESC LIMIT 25",
            (active_id,),
        ).fetchall()
    recent = conn.execute(
        "SELECT id, client, platform, date, notes FROM touchpoints ORDER BY date DESC, id DESC LIMIT 12"
    ).fetchall()
    conn.close()

    body = ""
    if notice:
        body += f"<div class='notice'>{notice}</div>"
    if error:
        body += f"<div class='error'>{error}</div>"

    selector_options = "".join([
        f"<option value='{c['id']}' {'selected' if selected and c['id']==selected['user']['id'] else ''}>{c['display_name'] or c['username']} ({c['username']})</option>"
        for c in clients
    ])

    quick_buttons = "".join([
        f"<option value='{field}'>{label}</option>" for field, label in TOUCHPOINT_FIELDS
    ])

    body += f"""
    <div class='grid grid-3'>
      <div class='stat'><div class='label'>Clients</div><div class='value'>{total_clients}</div></div>
      <div class='stat'><div class='label'>Logged Entries</div><div class='value'>{total_entries}</div></div>
      <div class='stat'><div class='label'>Total Touchpoints</div><div class='value'>{total_touchpoints}</div></div>
    </div>

    <div class='grid grid-2'>
      <div class='card sticky'>
        <div class='section-title'><h2>Switch Client</h2></div>
        <form method='POST'>
          <input type='hidden' name='action' value='switch_client'>
          <label>Active Client
            <select name='user_id' required>{selector_options}</select>
          </label>
          <button type='submit'>Open Client</button>
        </form>
        <p class='small'>This keeps one client selected so you can move fast without hunting around the dashboard.</p>
      </div>

      <div class='card'>
        <div class='section-title'><h2>Add Client</h2></div>
        <form method='POST'>
          <input type='hidden' name='action' value='add_client'>
          <div class='grid grid-2'>
            <label>Display Name<input name='display_name' placeholder='Client name'></label>
            <label>Username<input name='username' placeholder='Client login username' required></label>
          </div>
          <div class='grid grid-2'>
            <label>Email<input name='email' type='email' placeholder='Client email'></label>
            <label>Report Email<input name='report_email' type='email' placeholder='Where reports should go'></label>
          </div>
          <label>Password<input name='password' type='text' placeholder='Temporary password' required></label>
          <button type='submit'>Add Client</button>
        </form>
      </div>
    </div>
    """

    if selected:
        user = selected["user"]
        settings = selected["settings"]
        selected_name = user["display_name"] or user["username"]
        recent_rows_html = "".join([
            f"<tr><td>{r['date']}</td><td>{r['platform']}</td><td>{sum((r[field] or 0) for field, _ in TOUCHPOINT_FIELDS)}</td><td>{r['notes'] or ''}</td></tr>"
            for r in selected_recent
        ]) or "<tr><td colspan='4'>No activity yet.</td></tr>"

        body += f"""
        <div class='card'>
          <div class='section-title'>
            <h2>{selected_name}</h2>
            <div class='btnrow'>
              <form method='POST' style='display:inline;'>
                <input type='hidden' name='action' value='send_report'>
                <input type='hidden' name='user_id' value='{user['id']}'>
                <input type='hidden' name='period' value='daily'>
                <button class='btn green' type='submit'>Send Daily</button>
              </form>
              <form method='POST' style='display:inline;'>
                <input type='hidden' name='action' value='send_report'>
                <input type='hidden' name='user_id' value='{user['id']}'>
                <input type='hidden' name='period' value='weekly'>
                <button class='btn green' type='submit'>Send Weekly</button>
              </form>
              <form method='POST' style='display:inline;'>
                <input type='hidden' name='action' value='send_report'>
                <input type='hidden' name='user_id' value='{user['id']}'>
                <input type='hidden' name='period' value='monthly'>
                <button class='btn green' type='submit'>Send Monthly</button>
              </form>
            </div>
          </div>
          <div class='grid grid-3'>
            <div class='stat'><div class='label'>Today</div><div class='value'>{selected['daily_total']}</div></div>
            <div class='stat'><div class='label'>7 Days</div><div class='value'>{selected['weekly_total']}</div></div>
            <div class='stat'><div class='label'>30 Days</div><div class='value'>{selected['monthly_total']}</div></div>
          </div>
          <p class='metric'>Report email: {settings['report_email'] or user['email'] or 'Not set'} | Daily: {'On' if settings['send_daily'] else 'Off'} | Weekly: {'On' if settings['send_weekly'] else 'Off'} | Monthly: {'On' if settings['send_monthly'] else 'Off'}</p>
        </div>

        <div class='grid grid-2'>
          <div class='card'>
            <h2>Quick Add for Today</h2>
            <form method='POST'>
              <input type='hidden' name='action' value='quick_add'>
              <input type='hidden' name='user_id' value='{user['id']}'>
              <div class='grid grid-2'>
                <label>Touchpoint Type
                  <select name='category'>{quick_buttons}</select>
                </label>
                <label>How Many<input type='number' min='1' name='qty' value='1'></label>
              </div>
              <label>Note<input name='notes' placeholder='Optional proof note'></label>
              <button type='submit'>Quick Save</button>
            </form>
            <p class='small'>Use this when you just want to quickly add how many you did today without filling out the full form.</p>
          </div>

          <div class='card'>
            <h2>Client Profile</h2>
            <form method='POST'>
              <input type='hidden' name='action' value='save_client_profile'>
              <input type='hidden' name='user_id' value='{user['id']}'>
              <div class='grid grid-2'>
                <label>Display Name<input name='display_name' value='{user['display_name'] or ''}'></label>
                <label>Email<input name='email' type='email' value='{user['email'] or ''}'></label>
              </div>
              <div class='grid grid-2'>
                <label>Company Name<input name='company_name' value='{settings['company_name'] or ''}'></label>
                <label>Report Email<input name='report_email' type='email' value='{settings['report_email'] or ''}'></label>
              </div>
              <label>CC Email<input name='cc_email' type='email' value='{settings['cc_email'] or ''}' placeholder='Optional copy to you or another address'></label>
              <label>Client Notes<textarea name='client_notes' placeholder='Any notes about this client'>{settings['client_notes'] or ''}</textarea></label>
              <label><input type='checkbox' name='send_daily' {'checked' if settings['send_daily'] else ''}> Enable daily reports</label>
              <label><input type='checkbox' name='send_weekly' {'checked' if settings['send_weekly'] else ''}> Enable weekly reports</label>
              <label><input type='checkbox' name='send_monthly' {'checked' if settings['send_monthly'] else ''}> Enable monthly reports</label>
              <label><input type='checkbox' name='is_active' {'checked' if user['is_active'] else ''}> Client is active</label>
              <button type='submit'>Save Client Profile</button>
            </form>
          </div>
        </div>

        <div class='card'>
          <h2>Full Touchpoint Entry</h2>
          <form method='POST'>
            <input type='hidden' name='action' value='log_touchpoints'>
            <input type='hidden' name='user_id' value='{user['id']}'>
            <div class='grid grid-2'>
              <label>Platform
                <select name='platform'>
                  <option>Facebook</option>
                  <option>Messenger</option>
                  <option>Instagram</option>
                  <option>Other</option>
                </select>
              </label>
              <label>Date and Time<input type='datetime-local' name='date' value='{dt_local_input()}'></label>
            </div>
            <div class='field-grid'>
              {quick_form_html()}
            </div>
            <label>Notes / Proof Details<textarea name='notes' placeholder='What exactly did you do today for this client?'></textarea></label>
            <button type='submit'>Save Full Entry</button>
          </form>
        </div>

        <div class='card'>
          <h2>Recent Activity for {selected_name}</h2>
          <table>
            <tr><th>Date</th><th>Platform</th><th>Total</th><th>Notes</th></tr>
            {recent_rows_html}
          </table>
        </div>
        """

    body += f"""
    <div class='card'>
      <h2>Recent Activity Across All Clients</h2>
      <table>
        <tr><th>Date</th><th>Client</th><th>Platform</th><th>Notes</th></tr>
        {''.join([f"<tr><td>{r['date']}</td><td>{r['client']}</td><td>{r['platform']}</td><td>{r['notes'] or ''}</td></tr>" for r in recent]) or '<tr><td colspan="4">No touchpoints yet.</td></tr>'}
      </table>
    </div>
    """
    return base_html("Admin Dashboard", body, "Add clients, switch profiles fast, log daily work, and send reports")


@app.route("/client")
@login_required()
def client_dashboard():
    user_id = session["user_id"]
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    settings = ensure_client_settings(conn, user_id, user["email"] or "")
    rows = conn.execute(
        f"SELECT id, date, platform, notes, {', '.join(field for field, _ in TOUCHPOINT_FIELDS)} FROM touchpoints WHERE user_id = ? ORDER BY date DESC, id DESC LIMIT 100",
        (user_id,),
    ).fetchall()
    conn.close()

    daily_rows = get_period_rows(user_id, 1)
    weekly_rows = get_period_rows(user_id, 7)
    monthly_rows = get_period_rows(user_id, 30)
    _daily_totals, daily_total = totals_from_rows(daily_rows)
    _weekly_totals, weekly_total = totals_from_rows(weekly_rows)
    monthly_totals, monthly_total = totals_from_rows(monthly_rows)

    breakdown_html = "".join([f"<tr><td>{label}</td><td>{monthly_totals[field]}</td></tr>" for field, label in TOUCHPOINT_FIELDS])

    body = f"""
    <div class='grid grid-3'>
      <div class='stat'><div class='label'>Daily Touchpoints</div><div class='value'>{daily_total}</div></div>
      <div class='stat'><div class='label'>Weekly Touchpoints</div><div class='value'>{weekly_total}</div></div>
      <div class='stat'><div class='label'>Monthly Touchpoints</div><div class='value'>{monthly_total}</div></div>
    </div>

    <div class='grid grid-2'>
      <div class='card'>
        <h2>Report Settings</h2>
        <p><span class='pill'>Report Email</span> {settings['report_email'] or user['email'] or 'Not set'}</p>
        <p><span class='pill'>Daily</span> {'On' if settings['send_daily'] else 'Off'}</p>
        <p><span class='pill'>Weekly</span> {'On' if settings['send_weekly'] else 'Off'}</p>
        <p><span class='pill'>Monthly</span> {'On' if settings['send_monthly'] else 'Off'}</p>
        <div class='btnrow'>
          <a class='btn' href='/settings'>Update Settings</a>
          <a class='btn secondary' href='/my-reports'>View Report Log</a>
        </div>
      </div>
      <div class='card'>
        <h2>Send a Report Now</h2>
        <div class='btnrow'>
          <a class='btn green' href='/send-report/daily'>Send Daily</a>
          <a class='btn green' href='/send-report/weekly'>Send Weekly</a>
          <a class='btn green' href='/send-report/monthly'>Send Monthly</a>
          <a class='btn secondary' href='/export-csv'>Export CSV</a>
        </div>
      </div>
    </div>

    <div class='grid grid-2'>
      <div class='card'>
        <h2>30-Day Breakdown</h2>
        <table>
          <tr><th>Touchpoint</th><th>Total</th></tr>
          {breakdown_html}
        </table>
      </div>
      <div class='card'>
        <h2>Recent Activity</h2>
        <table>
          <tr><th>Date</th><th>Platform</th><th>Total</th><th>Notes</th></tr>
          {''.join([f"<tr><td>{r['date']}</td><td>{r['platform']}</td><td>{sum((r[field] or 0) for field, _ in TOUCHPOINT_FIELDS)}</td><td>{r['notes'] or ''}</td></tr>" for r in rows]) or '<tr><td colspan="4">No activity yet.</td></tr>'}
        </table>
      </div>
    </div>
    """
    return base_html("Client Dashboard", body, f"Welcome back, {user['display_name'] or user['username']}")


@app.route("/settings", methods=["GET", "POST"])
@login_required()
def settings():
    user_id = session["user_id"]
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    settings_row = ensure_client_settings(conn, user_id, user["email"] or "")
    notice = ""
    if request.method == "POST":
        company_name = request.form.get("company_name", "").strip()
        report_email = request.form.get("report_email", "").strip()
        cc_email = request.form.get("cc_email", "").strip()
        display_name = request.form.get("display_name", "").strip()
        email = request.form.get("email", "").strip()
        send_daily = 1 if request.form.get("send_daily") == "on" else 0
        send_weekly = 1 if request.form.get("send_weekly") == "on" else 0
        send_monthly = 1 if request.form.get("send_monthly") == "on" else 0
        now = utcnow()
        conn.execute("UPDATE users SET display_name = ?, email = ?, updated_at = ? WHERE id = ?", (display_name, email, now, user_id))
        conn.execute("""
            UPDATE client_settings
            SET company_name = ?, report_email = ?, cc_email = ?, send_daily = ?, send_weekly = ?, send_monthly = ?, updated_at = ?
            WHERE user_id = ?
        """, (company_name, report_email, cc_email, send_daily, send_weekly, send_monthly, now, user_id))
        conn.commit()
        notice = "Settings updated."
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        settings_row = conn.execute("SELECT * FROM client_settings WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()

    body = ""
    if notice:
        body += f"<div class='notice'>{notice}</div>"
    body += f"""
    <div class='card' style='max-width:760px;'>
      <h2>Client Settings</h2>
      <form method='POST'>
        <label>Display Name<input name='display_name' value='{user['display_name'] or ''}'></label>
        <label>Login Email<input name='email' type='email' value='{user['email'] or ''}'></label>
        <label>Company Name<input name='company_name' value='{settings_row['company_name'] or ''}'></label>
        <label>Report Email<input name='report_email' type='email' value='{settings_row['report_email'] or ''}'></label>
        <label>CC Email<input name='cc_email' type='email' value='{settings_row['cc_email'] or ''}'></label>
        <label><input type='checkbox' name='send_daily' {'checked' if settings_row['send_daily'] else ''}> Enable daily reports</label>
        <label><input type='checkbox' name='send_weekly' {'checked' if settings_row['send_weekly'] else ''}> Enable weekly reports</label>
        <label><input type='checkbox' name='send_monthly' {'checked' if settings_row['send_monthly'] else ''}> Enable monthly reports</label>
        <button type='submit'>Save Settings</button>
      </form>
    </div>
    """
    return base_html("Settings", body, "Manage your report destination and frequency")


@app.route("/send-report/<period>")
@login_required()
def send_report(period):
    if period not in PERIODS:
        return base_html("Invalid Report", "<div class='error'>Invalid report period.</div>")
    success, message = send_email_report(session["user_id"], period)
    klass = "notice" if success else "error"
    body = f"<div class='{klass}'>{message}</div><div class='btnrow'><a class='btn' href='/client'>Back to Dashboard</a></div>"
    return base_html("Send Report", body, "Manual report sending")


@app.route("/my-reports")
@login_required()
def my_reports():
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM report_log WHERE user_id = ? ORDER BY sent_at DESC LIMIT 100",
        (session["user_id"],),
    ).fetchall()
    conn.close()
    body = f"""
    <div class='card'>
      <h2>Report Log</h2>
      <table>
        <tr><th>Sent At</th><th>Period</th><th>Recipient</th><th>Status</th><th>Message</th></tr>
        {''.join([f"<tr><td>{r['sent_at']}</td><td>{r['period']}</td><td>{r['sent_to']}</td><td>{'Success' if r['success'] else 'Failed'}</td><td>{r['message'] or ''}</td></tr>" for r in logs]) or '<tr><td colspan="5">No reports sent yet.</td></tr>'}
      </table>
    </div>
    """
    return base_html("My Reports", body, "See every report that was sent for your account")


@app.route("/admin/clients")
@login_required(role="admin")
def admin_clients():
    conn = get_db()
    clients = conn.execute("""
        SELECT u.id, u.username, u.display_name, u.email, u.is_active, cs.report_email, cs.cc_email, cs.send_daily, cs.send_weekly, cs.send_monthly
        FROM users u
        LEFT JOIN client_settings cs ON cs.user_id = u.id
        WHERE u.role = 'client'
        ORDER BY COALESCE(u.display_name, u.username), u.username
    """).fetchall()
    conn.close()
    body = f"""
    <div class='card'>
      <h2>Clients</h2>
      <table>
        <tr><th>Name</th><th>Username</th><th>Email</th><th>Report Email</th><th>CC</th><th>Daily</th><th>Weekly</th><th>Monthly</th><th>Status</th></tr>
        {''.join([f"<tr><td>{c['display_name'] or ''}</td><td>{c['username']}</td><td>{c['email'] or ''}</td><td>{c['report_email'] or ''}</td><td>{c['cc_email'] or ''}</td><td>{'On' if c['send_daily'] else 'Off'}</td><td>{'On' if c['send_weekly'] else 'Off'}</td><td>{'On' if c['send_monthly'] else 'Off'}</td><td>{'Active' if c['is_active'] else 'Inactive'}</td></tr>" for c in clients]) or '<tr><td colspan="9">No clients yet.</td></tr>'}
      </table>
    </div>
    """
    return base_html("Clients", body, "View all client accounts and report settings")


@app.route("/admin/reports")
@login_required(role="admin")
def admin_reports():
    conn = get_db()
    logs = conn.execute("""
        SELECT rl.*, u.username, u.display_name
        FROM report_log rl
        JOIN users u ON u.id = rl.user_id
        ORDER BY rl.sent_at DESC
        LIMIT 200
    """).fetchall()
    conn.close()
    body = f"""
    <div class='card'>
      <h2>All Report Activity</h2>
      <table>
        <tr><th>Sent At</th><th>Client</th><th>Period</th><th>Recipient</th><th>Status</th><th>Message</th></tr>
        {''.join([f"<tr><td>{r['sent_at']}</td><td>{r['display_name'] or r['username']}</td><td>{r['period']}</td><td>{r['sent_to']}</td><td>{'Success' if r['success'] else 'Failed'}</td><td>{r['message'] or ''}</td></tr>" for r in logs]) or '<tr><td colspan="6">No reports yet.</td></tr>'}
      </table>
    </div>
    """
    return base_html("Report Activity", body, "Monitor every sent or failed client report")


@app.route("/admin/mail", methods=["GET", "POST"])
@login_required(role="admin")
def admin_mail():
    conn = get_db()
    settings = get_mail_settings(conn)
    notice = ""
    error = ""
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "save_mail":
            sender_name = request.form.get("sender_name", "").strip()
            sender_email = request.form.get("sender_email", "").strip()
            smtp_username = request.form.get("smtp_username", "").strip()
            smtp_password = request.form.get("smtp_password", "").strip()
            smtp_use_tls = 1 if request.form.get("smtp_use_tls") == "on" else 0
            now = utcnow()
            conn.execute("""
                UPDATE mail_settings
                SET sender_name = ?, sender_email = ?, smtp_host = 'smtp.gmail.com', smtp_port = 587,
                    smtp_username = ?, smtp_password = ?, smtp_use_tls = ?, updated_at = ?
                WHERE id = ?
            """, (sender_name, sender_email, smtp_username, smtp_password, smtp_use_tls, now, settings["id"]))
            conn.commit()
            settings = get_mail_settings(conn)
            notice = "Gmail settings saved."
        elif action == "test_mail":
            conn.close()
            success, msg = send_test_email_to_admin()
            notice = msg if success else ""
            error = "" if success else msg
            conn = get_db()
            settings = get_mail_settings(conn)

    conn.close()
    body = ""
    if notice:
        body += f"<div class='notice'>{notice}</div>"
    if error:
        body += f"<div class='error'>{error}</div>"

    body += f"""
    <div class='card' style='max-width:820px;'>
      <h2>Gmail Connection</h2>
      <p class='muted'>Use a Gmail address and a Google App Password. Regular Gmail passwords usually will not work.</p>
      <form method='POST'>
        <input type='hidden' name='action' value='save_mail'>
        <label>Sender Name<input name='sender_name' value='{settings['sender_name'] or ''}' placeholder='Your business name'></label>
        <label>Sender Gmail Address<input name='sender_email' type='email' value='{settings['sender_email'] or ''}' placeholder='you@gmail.com'></label>
        <label>SMTP Username<input name='smtp_username' value='{settings['smtp_username'] or ''}' placeholder='Usually the same Gmail address'></label>
        <label>Gmail App Password<input name='smtp_password' type='password' value='{settings['smtp_password'] or ''}' placeholder='16-character app password'></label>
        <label><input type='checkbox' name='smtp_use_tls' {'checked' if settings['smtp_use_tls'] else ''}> Use TLS</label>
        <div class='btnrow'>
          <button type='submit'>Save Gmail Settings</button>
        </div>
      </form>
    </div>
    <div class='card' style='max-width:820px;'>
      <h2>Send Test Email</h2>
      <form method='POST'>
        <input type='hidden' name='action' value='test_mail'>
        <button class='btn green' type='submit'>Send Test Email</button>
      </form>
      <p class='small'>The test email goes to the admin email from your account settings or the ADMIN_EMAIL environment variable if present.</p>
    </div>
    """
    return base_html("Gmail Settings", body, "Connect Gmail so daily, weekly, and monthly reports can actually send")


def send_test_email_to_admin():
    cfg = get_effective_mail_config()
    recipient = os.environ.get("ADMIN_EMAIL", "") or cfg["sender_email"]
    if not recipient:
        return False, "No admin email available for the test."
    if not cfg["smtp_username"] or not cfg["smtp_password"] or not cfg["sender_email"]:
        return False, "Save your Gmail address and app password first."
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Touchpoint Tracker Gmail Test"
        display_from = cfg["sender_email"] if not cfg["sender_name"] else f"{cfg['sender_name']} <{cfg['sender_email']}>"
        msg["From"] = display_from
        msg["To"] = recipient
        msg.attach(MIMEText("<html><body><h2>Gmail is connected.</h2><p>Your Touchpoint Tracker can send reports now.</p></body></html>", "html"))

        server = smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=20)
        if cfg["smtp_use_tls"]:
            server.starttls()
        server.login(cfg["smtp_username"], cfg["smtp_password"])
        server.sendmail(cfg["sender_email"], [recipient], msg.as_string())
        server.quit()
        return True, f"Test email sent to {recipient}"
    except Exception as exc:
        return False, str(exc)


@app.route("/export-csv")
@login_required()
def export_csv():
    user_id = session["user_id"]
    conn = get_db()
    rows = conn.execute(
        f"SELECT date, platform, notes, {', '.join(field for field, _ in TOUCHPOINT_FIELDS)} FROM touchpoints WHERE user_id = ? ORDER BY date DESC, id DESC",
        (user_id,),
    ).fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["date", "platform", *[field for field, _ in TOUCHPOINT_FIELDS], "notes"])
    for row in rows:
        writer.writerow([row["date"], row["platform"], *[row[field] for field, _ in TOUCHPOINT_FIELDS], row["notes"] or ""])
    csv_data = output.getvalue()
    filename = f"touchpoints_{session.get('username', 'client')}.csv"
    return Response(csv_data, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.route("/run-due-reports")
def run_due_reports():
    token = request.args.get("token", "")
    expected = os.environ.get("CRON_TOKEN", "")
    if expected and token != expected:
        return {"ok": False, "message": "Unauthorized"}, 401
    results = maybe_send_due_reports()
    return {"ok": True, "processed": len(results), "results": results}


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
