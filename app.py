from flask import Flask, request, redirect, session, url_for
import sqlite3
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "lucidmage_secret_change_this"

DB_NAME = "touchpoints.db"


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'client'
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS touchpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client TEXT NOT NULL,
        comments INTEGER NOT NULL DEFAULT 0,
        dms INTEGER NOT NULL DEFAULT 0,
        reactions INTEGER NOT NULL DEFAULT 0,
        friends INTEGER NOT NULL DEFAULT 0,
        posts INTEGER NOT NULL DEFAULT 0,
        notes TEXT DEFAULT '',
        date TEXT NOT NULL
    )
    """)

    conn.commit()

    existing_admin = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        ("jeff",)
    ).fetchone()

    if not existing_admin:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("jeff", "lucidmage", "admin")
        )
        conn.commit()

    # Upgrade old DBs if needed
    columns = [row["name"] for row in conn.execute("PRAGMA table_info(touchpoints)").fetchall()]
    if "posts" not in columns:
        conn.execute("ALTER TABLE touchpoints ADD COLUMN posts INTEGER NOT NULL DEFAULT 0")
    if "notes" not in columns:
        conn.execute("ALTER TABLE touchpoints ADD COLUMN notes TEXT DEFAULT ''")

    conn.commit()
    conn.close()


init_db()


def render_page(title, body_html):
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{title}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
            * {{
                box-sizing: border-box;
            }}

            :root {{
                --bg1: #050816;
                --bg2: #0f172a;
                --bg3: #1e1b4b;
                --card: rgba(255,255,255,0.07);
                --card-strong: rgba(255,255,255,0.10);
                --line: rgba(255,255,255,0.12);
                --text: #f8fafc;
                --muted: #cbd5e1;
                --purple: #a855f7;
                --violet: #7c3aed;
                --blue: #38bdf8;
                --pink: #ec4899;
                --green: #22c55e;
                --gold: #fbbf24;
                --danger: #ef4444;
            }}

            body {{
                margin: 0;
                font-family: Arial, sans-serif;
                color: var(--text);
                min-height: 100vh;
                background:
                    radial-gradient(circle at top left, rgba(168,85,247,0.22), transparent 25%),
                    radial-gradient(circle at top right, rgba(56,189,248,0.16), transparent 20%),
                    radial-gradient(circle at bottom center, rgba(236,72,153,0.12), transparent 22%),
                    linear-gradient(180deg, var(--bg3) 0%, var(--bg2) 35%, var(--bg1) 100%);
                padding: 20px;
            }}

            .wrap {{
                max-width: 1220px;
                margin: 0 auto;
            }}

            .topbar {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 14px;
                flex-wrap: wrap;
                margin-bottom: 20px;
            }}

            .brand-wrap {{
                display: flex;
                flex-direction: column;
                gap: 6px;
            }}

            .brand {{
                font-size: 34px;
                font-weight: 800;
                letter-spacing: 0.4px;
                background: linear-gradient(90deg, #ffffff, #c084fc, #7dd3fc);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}

            .sub {{
                color: var(--muted);
                font-size: 14px;
            }}

            .action-row {{
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
            }}

            .card {{
                background: var(--card);
                border: 1px solid var(--line);
                border-radius: 22px;
                padding: 22px;
                backdrop-filter: blur(12px);
                box-shadow:
                    0 10px 30px rgba(0,0,0,0.28),
                    inset 0 1px 0 rgba(255,255,255,0.05);
            }}

            .panel-title {{
                font-size: 22px;
                font-weight: 800;
                margin: 0 0 8px 0;
            }}

            .panel-sub {{
                color: var(--muted);
                margin-bottom: 18px;
                font-size: 14px;
            }}

            .login-card {{
                max-width: 540px;
                margin: 48px auto;
                position: relative;
                overflow: hidden;
            }}

            .login-card::before {{
                content: "";
                position: absolute;
                inset: -1px;
                background: linear-gradient(135deg, rgba(168,85,247,0.30), rgba(56,189,248,0.20), rgba(236,72,153,0.18));
                filter: blur(30px);
                z-index: 0;
            }}

            .login-content {{
                position: relative;
                z-index: 1;
            }}

            .grid {{
                display: grid;
                gap: 16px;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            }}

            .grid-2 {{
                display: grid;
                gap: 18px;
                grid-template-columns: 1.05fr 1.4fr;
                align-items: start;
            }}

            .stat {{
                background: var(--card-strong);
                border: 1px solid var(--line);
                border-radius: 20px;
                padding: 18px;
                min-height: 120px;
                position: relative;
                overflow: hidden;
            }}

            .stat::after {{
                content: "";
                position: absolute;
                top: -20px;
                right: -20px;
                width: 90px;
                height: 90px;
                border-radius: 999px;
                background: radial-gradient(circle, rgba(168,85,247,0.18), transparent 70%);
            }}

            .stat-label {{
                color: var(--muted);
                font-size: 13px;
                margin-bottom: 12px;
                text-transform: uppercase;
                letter-spacing: 0.7px;
            }}

            .stat-value {{
                font-size: 34px;
                font-weight: 900;
                line-height: 1;
                margin-bottom: 8px;
            }}

            .stat-hint {{
                color: #94a3b8;
                font-size: 13px;
            }}

            .accent-purple {{
                box-shadow: inset 0 0 0 1px rgba(168,85,247,0.14);
            }}

            .accent-blue {{
                box-shadow: inset 0 0 0 1px rgba(56,189,248,0.14);
            }}

            .accent-pink {{
                box-shadow: inset 0 0 0 1px rgba(236,72,153,0.14);
            }}

            .accent-green {{
                box-shadow: inset 0 0 0 1px rgba(34,197,94,0.14);
            }}

            .accent-gold {{
                box-shadow: inset 0 0 0 1px rgba(251,191,36,0.14);
            }}

            label {{
                display: block;
                margin-bottom: 6px;
                font-size: 14px;
                color: #e2e8f0;
                font-weight: 700;
            }}

            input, select, textarea {{
                width: 100%;
                padding: 13px 14px;
                margin: 0 0 14px 0;
                border-radius: 14px;
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.08);
                color: white;
                outline: none;
                font-size: 15px;
            }}

            textarea {{
                resize: vertical;
                min-height: 92px;
            }}

            input::placeholder, textarea::placeholder {{
                color: #94a3b8;
            }}

            .btn {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                padding: 12px 18px;
                border-radius: 14px;
                border: none;
                cursor: pointer;
                font-weight: 800;
                text-decoration: none;
                color: white;
                background: linear-gradient(135deg, var(--purple), var(--blue));
                box-shadow: 0 8px 24px rgba(124,58,237,0.32);
            }}

            .btn.secondary {{
                background: rgba(255,255,255,0.08);
                border: 1px solid var(--line);
                box-shadow: none;
            }}

            .btn.gold {{
                background: linear-gradient(135deg, #f59e0b, #fbbf24);
                color: #111827;
            }}

            .btn-row {{
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                margin-top: 8px;
            }}

            .alert {{
                padding: 13px 14px;
                border-radius: 14px;
                margin-bottom: 16px;
                font-weight: 700;
                font-size: 14px;
            }}

            .alert.error {{
                background: rgba(239,68,68,0.15);
                border: 1px solid rgba(239,68,68,0.30);
            }}

            .alert.success {{
                background: rgba(34,197,94,0.15);
                border: 1px solid rgba(34,197,94,0.30);
            }}

            .mini-grid {{
                display: grid;
                gap: 14px;
                grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 8px;
                overflow: hidden;
                border-radius: 16px;
            }}

            th, td {{
                padding: 12px 10px;
                border-bottom: 1px solid rgba(255,255,255,0.08);
                text-align: center;
                font-size: 14px;
            }}

            th {{
                color: var(--muted);
                text-transform: uppercase;
                letter-spacing: 0.5px;
                font-size: 12px;
            }}

            tr:hover td {{
                background: rgba(255,255,255,0.03);
            }}

            .section {{
                margin-top: 18px;
            }}

            .pill {{
                display: inline-block;
                padding: 7px 10px;
                border-radius: 999px;
                background: rgba(255,255,255,0.07);
                border: 1px solid var(--line);
                color: var(--muted);
                font-size: 12px;
                margin-right: 8px;
                margin-bottom: 8px;
            }}

            .note-box {{
                background: rgba(255,255,255,0.04);
                border: 1px solid rgba(255,255,255,0.08);
                padding: 14px;
                border-radius: 16px;
                color: #dbeafe;
                text-align: left;
                white-space: pre-wrap;
            }}

            .empty {{
                color: var(--muted);
                text-align: center;
                padding: 24px 10px;
            }}

            .footer-hint {{
                color: #94a3b8;
                font-size: 13px;
                margin-top: 14px;
            }}

            @media (max-width: 900px) {{
                .grid-2 {{
                    grid-template-columns: 1fr;
                }}
            }}

            @media (max-width: 640px) {{
                body {{
                    padding: 12px;
                }}

                .brand {{
                    font-size: 26px;
                }}

                .card {{
                    padding: 18px;
                    border-radius: 18px;
                }}

                .stat {{
                    min-height: 105px;
                }}

                .stat-value {{
                    font-size: 28px;
                }}

                th, td {{
                    font-size: 12px;
                    padding: 10px 6px;
                }}

                .btn {{
                    width: 100%;
                }}

                .action-row {{
                    width: 100%;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="wrap">
            {body_html}
        </div>
    </body>
    </html>
    """


def safe_int(value):
    try:
        return int(value or 0)
    except:
        return 0


def totals_from_rows(rows):
    total = 0
    comments = 0
    dms = 0
    reactions = 0
    friends = 0
    posts = 0

    for r in rows:
        comments += r["comments"]
        dms += r["dms"]
        reactions += r["reactions"]
        friends += r["friends"]
        posts += r["posts"]
        total += r["comments"] + r["dms"] + r["reactions"] + r["friends"] + r["posts"]

    return {
        "total": total,
        "comments": comments,
        "dms": dms,
        "reactions": reactions,
        "friends": friends,
        "posts": posts
    }


@app.route("/", methods=["GET", "POST"])
def login():
    message = ""
    success = request.args.get("success", "")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            message = '<div class="alert error">Please enter both username and password.</div>'
        else:
            conn = get_db()
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? AND password = ?",
                (username, password)
            ).fetchone()
            conn.close()

            if user:
                session["user"] = user["username"]
                session["role"] = user["role"]
                return redirect("/admin" if user["role"] == "admin" else "/client")
            else:
                message = '<div class="alert error">Invalid username or password.</div>'

    success_message = ""
    if success == "account_created":
        success_message = '<div class="alert success">Account created. You can log in now.</div>'

    body = f"""
    <div class="card login-card">
        <div class="login-content">
            <div class="brand-wrap" style="text-align:center;">
                <div class="brand">Lucid Mage Command Center</div>
                <div class="sub">Manual Facebook touchpoint tracking with a stronger client-facing visual dashboard.</div>
            </div>

            <div class="section">
                {success_message}
                {message}
            </div>

            <form method="POST">
                <label>Username</label>
                <input name="username" placeholder="Enter username" />

                <label>Password</label>
                <input name="password" type="password" placeholder="Enter password" />

                <div class="btn-row">
                    <button class="btn" type="submit">Login</button>
                    <a class="btn secondary" href="/create-account">Create Account</a>
                </div>
            </form>

            <div class="footer-hint">
                Default admin login: <strong>jeff</strong> / <strong>lucidmage</strong>
            </div>
        </div>
    </div>
    """
    return render_page("Login", body)


@app.route("/create-account", methods=["GET", "POST"])
def create_account():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not username or not password or not confirm_password:
            message = '<div class="alert error">Please fill out all fields.</div>'
        elif password != confirm_password:
            message = '<div class="alert error">Passwords do not match.</div>'
        else:
            conn = get_db()
            existing = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if existing:
                message = '<div class="alert error">That username already exists.</div>'
                conn.close()
            else:
                conn.execute(
                    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, password, "client")
                )
                conn.commit()
                conn.close()
                return redirect("/?success=account_created")

    body = f"""
    <div class="card login-card">
        <div class="login-content">
            <div class="brand-wrap" style="text-align:center;">
                <div class="brand">Create Client Account</div>
                <div class="sub">Add a client login for their private dashboard.</div>
            </div>

            <div class="section">
                {message}
            </div>

            <form method="POST">
                <label>Username</label>
                <input name="username" placeholder="Choose a username" />

                <label>Password</label>
                <input name="password" type="password" placeholder="Choose a password" />

                <label>Confirm Password</label>
                <input name="confirm_password" type="password" placeholder="Confirm password" />

                <div class="btn-row">
                    <button class="btn" type="submit">Create Account</button>
                    <a class="btn secondary" href="/">Back to Login</a>
                </div>
            </form>
        </div>
    </div>
    """
    return render_page("Create Account", body)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if session.get("role") != "admin":
        return redirect("/")

    message = ""

    if request.method == "POST":
        client = request.form.get("client", "").strip()
        comments = safe_int(request.form.get("comments"))
        dms = safe_int(request.form.get("dms"))
        reactions = safe_int(request.form.get("reactions"))
        friends = safe_int(request.form.get("friends"))
        posts = safe_int(request.form.get("posts"))
        notes = request.form.get("notes", "").strip()

        if not client:
            message = '<div class="alert error">Please select a client username.</div>'
        else:
            conn = get_db()
            client_user = conn.execute(
                "SELECT * FROM users WHERE username = ? AND role = 'client'",
                (client,)
            ).fetchone()

            if not client_user:
                message = '<div class="alert error">That client account does not exist yet. Create it first.</div>'
            else:
                conn.execute("""
                    INSERT INTO touchpoints (client, comments, dms, reactions, friends, posts, notes, date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    client,
                    comments,
                    dms,
                    reactions,
                    friends,
                    posts,
                    notes,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ))
                conn.commit()
                message = '<div class="alert success">Touchpoints added successfully.</div>'

            conn.close()

    conn = get_db()
    clients = conn.execute(
        "SELECT username FROM users WHERE role = 'client' ORDER BY username ASC"
    ).fetchall()

    recent_rows = conn.execute("""
        SELECT client, comments, dms, reactions, friends, posts, notes, date
        FROM touchpoints
        ORDER BY id DESC
        LIMIT 25
    """).fetchall()
    conn.close()

    metrics = totals_from_rows(recent_rows)

    rows_html = ""
    for row in recent_rows:
        row_total = row["comments"] + row["dms"] + row["reactions"] + row["friends"] + row["posts"]
        note_preview = (row["notes"][:40] + "...") if row["notes"] and len(row["notes"]) > 40 else (row["notes"] or "")
        rows_html += f"""
        <tr>
            <td>{row["client"]}</td>
            <td>{row["date"]}</td>
            <td>{row["comments"]}</td>
            <td>{row["dms"]}</td>
            <td>{row["reactions"]}</td>
            <td>{row["friends"]}</td>
            <td>{row["posts"]}</td>
            <td>{row_total}</td>
            <td>{note_preview}</td>
        </tr>
        """

    if not rows_html:
        rows_html = """
        <tr>
            <td colspan="9" class="empty">No touchpoints logged yet.</td>
        </tr>
        """

    client_options = "".join(
        [f'<option value="{c["username"]}">{c["username"]}</option>' for c in clients]
    )

    body = f"""
    <div class="topbar">
        <div class="brand-wrap">
            <div class="brand">Lucid Mage Command Center</div>
            <div class="sub">Operator panel for logging manual Facebook activity and showing compounding client momentum.</div>
        </div>
        <div class="action-row">
            <a class="btn secondary" href="/create-account">Create Client Account</a>
            <a class="btn secondary" href="/logout">Logout</a>
        </div>
    </div>

    <div class="grid">
        <div class="stat accent-purple">
            <div class="stat-label">Recent Total Touchpoints</div>
            <div class="stat-value">{metrics["total"]}</div>
            <div class="stat-hint">Sum of all recent logged activity</div>
        </div>
        <div class="stat accent-blue">
            <div class="stat-label">Comments</div>
            <div class="stat-value">{metrics["comments"]}</div>
            <div class="stat-hint">Visibility placements</div>
        </div>
        <div class="stat accent-pink">
            <div class="stat-label">DMs</div>
            <div class="stat-value">{metrics["dms"]}</div>
            <div class="stat-hint">Private conversations started</div>
        </div>
        <div class="stat accent-green">
            <div class="stat-label">Reactions</div>
            <div class="stat-value">{metrics["reactions"]}</div>
            <div class="stat-hint">Engagement signals sent</div>
        </div>
        <div class="stat accent-gold">
            <div class="stat-label">Friend Requests</div>
            <div class="stat-value">{metrics["friends"]}</div>
            <div class="stat-hint">Network expansion moves</div>
        </div>
    </div>

    <div class="section grid-2">
        <div class="card">
            <div class="panel-title">Log Touchpoints</div>
            <div class="panel-sub">Manually enter the work completed for a specific client.</div>
            {message}

            <form method="POST">
                <label>Client Username</label>
                <select name="client">
                    <option value="">Select a client</option>
                    {client_options}
                </select>

                <div class="mini-grid">
                    <div>
                        <label>Comments</label>
                        <input name="comments" type="number" min="0" value="0" />
                    </div>
                    <div>
                        <label>DMs</label>
                        <input name="dms" type="number" min="0" value="0" />
                    </div>
                    <div>
                        <label>Reactions</label>
                        <input name="reactions" type="number" min="0" value="0" />
                    </div>
                    <div>
                        <label>Friend Requests</label>
                        <input name="friends" type="number" min="0" value="0" />
                    </div>
                    <div>
                        <label>Posts</label>
                        <input name="posts" type="number" min="0" value="0" />
                    </div>
                </div>

                <label>Notes</label>
                <textarea name="notes" placeholder="Optional note about what was done, where it was done, or any results noticed..."></textarea>

                <div class="btn-row">
                    <button class="btn" type="submit">Save Activity</button>
                </div>
            </form>
        </div>

        <div class="card">
            <div class="panel-title">How the Numbers Read</div>
            <div class="panel-sub">Translate simple actions into stronger client-facing meaning.</div>

            <span class="pill">Comments = visibility placements</span>
            <span class="pill">DMs = direct conversations</span>
            <span class="pill">Reactions = engagement signals</span>
            <span class="pill">Friend Requests = network growth</span>
            <span class="pill">Posts = authority assets</span>

            <div class="section note-box">
This dashboard is designed to make manual work feel visible, measurable, and compounding.

You are not just logging random tasks.
You are showing daily momentum across:
- conversation creation
- visibility expansion
- network building
- content consistency

That is what makes the offer feel like a system instead of loose activity.
            </div>
        </div>
    </div>

    <div class="section card">
        <div class="panel-title">Recent Activity Log</div>
        <div class="panel-sub">Latest manually entered touchpoints across all clients.</div>
        <table>
            <tr>
                <th>Client</th>
                <th>Date</th>
                <th>Comments</th>
                <th>DMs</th>
                <th>Reactions</th>
                <th>Friends</th>
                <th>Posts</th>
                <th>Total</th>
                <th>Notes</th>
            </tr>
            {rows_html}
        </table>
    </div>
    """
    return render_page("Admin Dashboard", body)


@app.route("/client")
def client():
    if "user" not in session:
        return redirect("/")

    username = session.get("user")

    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM touchpoints WHERE client = ? ORDER BY id DESC",
        (username,)
    ).fetchall()
    conn.close()

    totals = totals_from_rows(rows)

    now = datetime.now()
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    today_total = 0
    week_total = 0
    month_total = 0

    table_rows = ""

    for r in rows:
        row_total = r["comments"] + r["dms"] + r["reactions"] + r["friends"] + r["posts"]
        row_date = datetime.strptime(r["date"], "%Y-%m-%d %H:%M:%S")

        if row_date.date() == now.date():
            today_total += row_total
        if row_date >= week_ago:
            week_total += row_total
        if row_date >= month_ago:
            month_total += row_total

        note_html = f'<div class="note-box" style="margin-top:8px;">{r["notes"]}</div>' if r["notes"] else ""

        table_rows += f"""
        <tr>
            <td>{r["date"]}</td>
            <td>{r["comments"]}</td>
            <td>{r["dms"]}</td>
            <td>{r["reactions"]}</td>
            <td>{r["friends"]}</td>
            <td>{r["posts"]}</td>
            <td>{row_total}</td>
        </tr>
        """

    if not table_rows:
        table_rows = """
        <tr>
            <td colspan="7" class="empty">No activity logged yet.</td>
        </tr>
        """

    body = f"""
    <div class="topbar">
        <div class="brand-wrap">
            <div class="brand">{username} Growth Dashboard</div>
            <div class="sub">Your Facebook touchpoint progress, tracked and updated manually.</div>
        </div>
        <div class="action-row">
            <a class="btn secondary" href="/logout">Logout</a>
        </div>
    </div>

    <div class="grid">
        <div class="stat accent-purple">
            <div class="stat-label">Today</div>
            <div class="stat-value">{today_total}</div>
            <div class="stat-hint">Today's total touchpoints</div>
        </div>
        <div class="stat accent-blue">
            <div class="stat-label">Last 7 Days</div>
            <div class="stat-value">{week_total}</div>
            <div class="stat-hint">Weekly momentum</div>
        </div>
        <div class="stat accent-pink">
            <div class="stat-label">Last 30 Days</div>
            <div class="stat-value">{month_total}</div>
            <div class="stat-hint">Monthly compounding activity</div>
        </div>
        <div class="stat accent-gold">
            <div class="stat-label">All-Time Total</div>
            <div class="stat-value">{totals["total"]}</div>
            <div class="stat-hint">Cumulative growth actions</div>
        </div>
    </div>

    <div class="section grid">
        <div class="stat accent-blue">
            <div class="stat-label">Comments</div>
            <div class="stat-value">{totals["comments"]}</div>
            <div class="stat-hint">Visibility placements</div>
        </div>
        <div class="stat accent-pink">
            <div class="stat-label">DMs</div>
            <div class="stat-value">{totals["dms"]}</div>
            <div class="stat-hint">Direct conversations</div>
        </div>
        <div class="stat accent-green">
            <div class="stat-label">Reactions</div>
            <div class="stat-value">{totals["reactions"]}</div>
            <div class="stat-hint">Engagement signals</div>
        </div>
        <div class="stat accent-gold">
            <div class="stat-label">Friend Requests</div>
            <div class="stat-value">{totals["friends"]}</div>
            <div class="stat-hint">Network expansion</div>
        </div>
        <div class="stat accent-purple">
            <div class="stat-label">Posts</div>
            <div class="stat-value">{totals["posts"]}</div>
            <div class="stat-hint">Authority assets published</div>
        </div>
    </div>

    <div class="section card">
        <div class="panel-title">Activity Log</div>
        <div class="panel-sub">Every manually entered session and touchpoint batch.</div>
        <table>
            <tr>
                <th>Date</th>
                <th>Comments</th>
                <th>DMs</th>
                <th>Reactions</th>
                <th>Friends</th>
                <th>Posts</th>
                <th>Total</th>
            </tr>
            {table_rows}
        </table>
    </div>
    """
    return render_page("Client Dashboard", body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
