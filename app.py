from flask import Flask, request, redirect, session
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

    columns = [row["name"] for row in conn.execute("PRAGMA table_info(touchpoints)").fetchall()]
    if "posts" not in columns:
        conn.execute("ALTER TABLE touchpoints ADD COLUMN posts INTEGER NOT NULL DEFAULT 0")
    if "notes" not in columns:
        conn.execute("ALTER TABLE touchpoints ADD COLUMN notes TEXT DEFAULT ''")

    conn.commit()
    conn.close()


init_db()


def totals_from_rows(rows):
    total = 0
    comments = 0
    dms = 0
    reactions = 0
    friends = 0
    posts = 0

    for r in rows:
        comments += int(r["comments"])
        dms += int(r["dms"])
        reactions += int(r["reactions"])
        friends += int(r["friends"])
        posts += int(r["posts"])
        total += int(r["comments"]) + int(r["dms"]) + int(r["reactions"]) + int(r["friends"]) + int(r["posts"])

    return {
        "total": total,
        "comments": comments,
        "dms": dms,
        "reactions": reactions,
        "friends": friends,
        "posts": posts
    }


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
                --blue: #38bdf8;
                --pink: #ec4899;
                --green: #22c55e;
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
                max-width: 1280px;
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

            .brand {{
                font-size: 34px;
                font-weight: 800;
                background: linear-gradient(90deg, #ffffff, #c084fc, #7dd3fc);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}

            .sub {{
                color: var(--muted);
                font-size: 14px;
                margin-top: 6px;
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

            .login-card {{
                max-width: 540px;
                margin: 48px auto;
            }}

            .grid {{
                display: grid;
                gap: 16px;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            }}

            .grid-2 {{
                display: grid;
                gap: 18px;
                grid-template-columns: 1.1fr 1fr;
            }}

            .stat {{
                background: var(--card-strong);
                border: 1px solid var(--line);
                border-radius: 20px;
                padding: 18px;
            }}

            .stat-label {{
                color: var(--muted);
                font-size: 13px;
                margin-bottom: 10px;
                text-transform: uppercase;
                letter-spacing: 0.7px;
            }}

            .stat-value {{
                font-size: 34px;
                font-weight: 900;
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
                min-height: 90px;
            }}

            .btn {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
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

            .btn.green {{
                background: linear-gradient(135deg, #16a34a, #22c55e);
            }}

            .btn-row {{
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
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

            .tracker-grid {{
                display: grid;
                gap: 14px;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            }}

            .tracker-box {{
                background: rgba(255,255,255,0.05);
                border: 1px solid rgba(255,255,255,0.10);
                border-radius: 18px;
                padding: 16px;
                text-align: center;
            }}

            .tracker-name {{
                color: var(--muted);
                font-size: 13px;
                margin-bottom: 10px;
                text-transform: uppercase;
                letter-spacing: 0.6px;
            }}

            .tracker-count {{
                font-size: 34px;
                font-weight: 900;
                margin-bottom: 12px;
            }}

            .counter-row {{
                display: flex;
                gap: 10px;
            }}

            .counter-btn {{
                flex: 1;
                padding: 12px;
                border: none;
                border-radius: 12px;
                cursor: pointer;
                font-weight: 900;
                font-size: 20px;
                color: white;
            }}

            .minus {{
                background: rgba(239,68,68,0.85);
            }}

            .plus {{
                background: rgba(34,197,94,0.85);
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 8px;
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

            .empty {{
                color: var(--muted);
                text-align: center;
                padding: 24px 10px;
            }}

            .section {{
                margin-top: 18px;
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

                .btn {{
                    width: 100%;
                }}

                .btn-row {{
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
        <div class="brand" style="text-align:center;">Lucid Mage Command Center</div>
        <div class="sub" style="text-align:center;">Manual Facebook touchpoint tracking dashboard</div>

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

        <div class="sub" style="margin-top:16px;">
            Default admin login: <strong>jeff</strong> / <strong>lucidmage</strong>
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
        <div class="brand" style="text-align:center;">Create Client Account</div>
        <div class="sub" style="text-align:center;">Add a client login for their private dashboard</div>

        <div class="section">{message}</div>

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
    """
    return render_page("Create Account", body)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if session.get("role") != "admin":
        return redirect("/")

    message = ""

    if "selected_client" not in session:
        session["selected_client"] = ""

    if request.method == "POST":
        action = request.form.get("action", "").strip()

        if action == "set_client":
            selected_client = request.form.get("selected_client", "").strip()
            session["selected_client"] = selected_client
            if selected_client:
                message = f'<div class="alert success">Loaded workspace for {selected_client}.</div>'
            else:
                message = '<div class="alert error">Please choose a client.</div>'

        elif action == "save_session":
            client = session.get("selected_client", "").strip()
            comments = int(request.form.get("comments", 0))
            dms = int(request.form.get("dms", 0))
            reactions = int(request.form.get("reactions", 0))
            friends = int(request.form.get("friends", 0))
            posts = int(request.form.get("posts", 0))
            notes = request.form.get("notes", "").strip()

            if not client:
                message = '<div class="alert error">Select a client first.</div>'
            else:
                total = comments + dms + reactions + friends + posts
                if total <= 0 and not notes:
                    message = '<div class="alert error">Add at least one task before saving.</div>'
                else:
                    conn = get_db()
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
                    conn.close()
                    message = f'<div class="alert success">Saved session for {client}.</div>'

    selected_client = session.get("selected_client", "").strip()

    conn = get_db()
    clients = conn.execute(
        "SELECT username FROM users WHERE role = 'client' ORDER BY username ASC"
    ).fetchall()

    recent_rows = conn.execute("""
        SELECT client, comments, dms, reactions, friends, posts, notes, date
        FROM touchpoints
        ORDER BY id DESC
        LIMIT 30
    """).fetchall()

    today_rows = []
    today_metrics = {"total": 0, "comments": 0, "dms": 0, "reactions": 0, "friends": 0, "posts": 0}

    if selected_client:
        today_prefix = datetime.now().strftime("%Y-%m-%d")
        today_rows = conn.execute("""
            SELECT * FROM touchpoints
            WHERE client = ? AND date LIKE ?
            ORDER BY id DESC
        """, (selected_client, f"{today_prefix}%")).fetchall()

    conn.close()

    recent_metrics = totals_from_rows(recent_rows)
    today_metrics = totals_from_rows(today_rows)

    client_options = "".join(
        [f'<option value="{c["username"]}" {"selected" if c["username"] == selected_client else ""}>{c["username"]}</option>' for c in clients]
    )

    recent_html = ""
    for row in recent_rows:
        row_total = row["comments"] + row["dms"] + row["reactions"] + row["friends"] + row["posts"]
        recent_html += f"""
        <tr>
            <td>{row["client"]}</td>
            <td>{row["date"]}</td>
            <td>{row["comments"]}</td>
            <td>{row["dms"]}</td>
            <td>{row["reactions"]}</td>
            <td>{row["friends"]}</td>
            <td>{row["posts"]}</td>
            <td>{row_total}</td>
        </tr>
        """
    if not recent_html:
        recent_html = '<tr><td colspan="8" class="empty">No activity logged yet.</td></tr>'

    today_html = ""
    for row in today_rows:
        row_total = row["comments"] + row["dms"] + row["reactions"] + row["friends"] + row["posts"]
        today_html += f"""
        <tr>
            <td>{row["date"]}</td>
            <td>{row["comments"]}</td>
            <td>{row["dms"]}</td>
            <td>{row["reactions"]}</td>
            <td>{row["friends"]}</td>
            <td>{row["posts"]}</td>
            <td>{row_total}</td>
        </tr>
        """
    if not today_html:
        today_html = '<tr><td colspan="7" class="empty">No activity logged today for this client.</td></tr>'

    body = f"""
    <div class="topbar">
        <div>
            <div class="brand">Lucid Mage Command Center</div>
            <div class="sub">Manual operator dashboard for Facebook touchpoint tracking</div>
        </div>
        <div class="btn-row">
            <a class="btn secondary" href="/create-account">Create Client Account</a>
            <a class="btn secondary" href="/logout">Logout</a>
        </div>
    </div>

    <div class="grid">
        <div class="stat">
            <div class="stat-label">Recent Total Touchpoints</div>
            <div class="stat-value">{recent_metrics["total"]}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Comments</div>
            <div class="stat-value">{recent_metrics["comments"]}</div>
        </div>
        <div class="stat">
            <div class="stat-label">DMs</div>
            <div class="stat-value">{recent_metrics["dms"]}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Reactions</div>
            <div class="stat-value">{recent_metrics["reactions"]}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Friend Requests</div>
            <div class="stat-value">{recent_metrics["friends"]}</div>
        </div>
    </div>

    <div class="section">{message}</div>

    <div class="section card">
        <div class="panel-title">Select Client Workspace</div>
        <div class="panel-sub">Choose the client you are working on. It stays selected until you change it.</div>
        <form method="POST">
            <input type="hidden" name="action" value="set_client" />
            <label>Client Username</label>
            <select name="selected_client">
                <option value="">Select a client</option>
                {client_options}
            </select>
            <div class="btn-row">
                <button class="btn" type="submit">Load Client Workspace</button>
            </div>
        </form>
        <div class="sub" style="margin-top:12px;">
            Current client: <strong>{selected_client if selected_client else "None selected"}</strong>
        </div>
    </div>

    <div class="section grid-2">
        <div class="card">
            <div class="panel-title">Manual Task Tracker</div>
            <div class="panel-sub">Use the plus and minus buttons, then save the session.</div>

            <form method="POST" id="sessionForm">
                <input type="hidden" name="action" value="save_session" />
                <input type="hidden" name="comments" id="comments_input" value="0" />
                <input type="hidden" name="dms" id="dms_input" value="0" />
                <input type="hidden" name="reactions" id="reactions_input" value="0" />
                <input type="hidden" name="friends" id="friends_input" value="0" />
                <input type="hidden" name="posts" id="posts_input" value="0" />

                <div class="tracker-grid">
                    <div class="tracker-box">
                        <div class="tracker-name">Comments</div>
                        <div class="tracker-count" id="comments_count">0</div>
                        <div class="counter-row">
                            <button type="button" class="counter-btn minus" onclick="changeCount('comments', -1)">-</button>
                            <button type="button" class="counter-btn plus" onclick="changeCount('comments', 1)">+</button>
                        </div>
                    </div>

                    <div class="tracker-box">
                        <div class="tracker-name">DMs</div>
                        <div class="tracker-count" id="dms_count">0</div>
                        <div class="counter-row">
                            <button type="button" class="counter-btn minus" onclick="changeCount('dms', -1)">-</button>
                            <button type="button" class="counter-btn plus" onclick="changeCount('dms', 1)">+</button>
                        </div>
                    </div>

                    <div class="tracker-box">
                        <div class="tracker-name">Reactions</div>
                        <div class="tracker-count" id="reactions_count">0</div>
                        <div class="counter-row">
                            <button type="button" class="counter-btn minus" onclick="changeCount('reactions', -1)">-</button>
                            <button type="button" class="counter-btn plus" onclick="changeCount('reactions', 1)">+</button>
                        </div>
                    </div>

                    <div class="tracker-box">
                        <div class="tracker-name">Friend Requests</div>
                        <div class="tracker-count" id="friends_count">0</div>
                        <div class="counter-row">
                            <button type="button" class="counter-btn minus" onclick="changeCount('friends', -1)">-</button>
                            <button type="button" class="counter-btn plus" onclick="changeCount('friends', 1)">+</button>
                        </div>
                    </div>

                    <div class="tracker-box">
                        <div class="tracker-name">Posts</div>
                        <div class="tracker-count" id="posts_count">0</div>
                        <div class="counter-row">
                            <button type="button" class="counter-btn minus" onclick="changeCount('posts', -1)">-</button>
                            <button type="button" class="counter-btn plus" onclick="changeCount('posts', 1)">+</button>
                        </div>
                    </div>
                </div>

                <div class="section">
                    <label>Notes</label>
                    <textarea name="notes" placeholder="Optional note about what you worked on"></textarea>
                </div>

                <div class="btn-row">
                    <button class="btn green" type="submit">Save Session</button>
                    <button class="btn secondary" type="button" onclick="resetCounts()">Reset</button>
                </div>
            </form>
        </div>

        <div class="card">
            <div class="panel-title">Today Summary</div>
            <div class="panel-sub">Live totals already saved today for the selected client.</div>

            <div class="grid">
                <div class="stat">
                    <div class="stat-label">Today Total</div>
                    <div class="stat-value">{today_metrics["total"]}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Comments</div>
                    <div class="stat-value">{today_metrics["comments"]}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">DMs</div>
                    <div class="stat-value">{today_metrics["dms"]}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Reactions</div>
                    <div class="stat-value">{today_metrics["reactions"]}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Friends</div>
                    <div class="stat-value">{today_metrics["friends"]}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Posts</div>
                    <div class="stat-value">{today_metrics["posts"]}</div>
                </div>
            </div>
        </div>
    </div>

    <div class="section grid-2">
        <div class="card">
            <div class="panel-title">Today's Activity Log</div>
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
                {today_html}
            </table>
        </div>

        <div class="card">
            <div class="panel-title">Recent Activity Across All Clients</div>
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
                </tr>
                {recent_html}
            </table>
        </div>
    </div>

    <script>
        const counts = {
            comments: 0,
            dms: 0,
            reactions: 0,
            friends: 0,
            posts: 0
        };

        function changeCount(name, amount) {
            counts[name] = Math.max(0, counts[name] + amount);
            document.getElementById(name + "_count").innerText = counts[name];
            document.getElementById(name + "_input").value = counts[name];
        }

        function resetCounts() {
            for (const key in counts) {
                counts[key] = 0;
                document.getElementById(key + "_count").innerText = 0;
                document.getElementById(key + "_input").value = 0;
            }
        }
    </script>
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
        <div>
            <div class="brand">{username} Growth Dashboard</div>
            <div class="sub">Your Facebook touchpoint progress, tracked manually</div>
        </div>
        <div class="btn-row">
            <a class="btn secondary" href="/logout">Logout</a>
        </div>
    </div>

    <div class="grid">
        <div class="stat">
            <div class="stat-label">Today</div>
            <div class="stat-value">{today_total}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Last 7 Days</div>
            <div class="stat-value">{week_total}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Last 30 Days</div>
            <div class="stat-value">{month_total}</div>
        </div>
        <div class="stat">
            <div class="stat-label">All-Time Total</div>
            <div class="stat-value">{totals["total"]}</div>
        </div>
    </div>

    <div class="section grid">
        <div class="stat">
            <div class="stat-label">Comments</div>
            <div class="stat-value">{totals["comments"]}</div>
        </div>
        <div class="stat">
            <div class="stat-label">DMs</div>
            <div class="stat-value">{totals["dms"]}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Reactions</div>
            <div class="stat-value">{totals["reactions"]}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Friend Requests</div>
            <div class="stat-value">{totals["friends"]}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Posts</div>
            <div class="stat-value">{totals["posts"]}</div>
        </div>
    </div>

    <div class="section card">
        <div class="panel-title">Activity Log</div>
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
