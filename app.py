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
        date TEXT NOT NULL
    )
    """)

    conn.commit()

    # Seed default admin if it doesn't exist
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

    conn.close()


init_db()


def render_page(title, body_html):
    return f"""
    <html>
    <head>
        <title>{title}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
            * {{
                box-sizing: border-box;
            }}

            body {{
                margin: 0;
                font-family: Arial, sans-serif;
                background:
                    radial-gradient(circle at top, #312e81 0%, #0f172a 35%, #020617 100%);
                color: white;
                min-height: 100vh;
                padding: 24px;
            }}

            .wrap {{
                max-width: 1000px;
                margin: 0 auto;
            }}

            .card {{
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 18px;
                padding: 24px;
                box-shadow: 0 12px 40px rgba(0,0,0,0.35);
                backdrop-filter: blur(10px);
            }}

            h1, h2, h3 {{
                margin-top: 0;
            }}

            .brand {{
                font-size: 32px;
                font-weight: 700;
                text-align: center;
                margin-bottom: 10px;
            }}

            .sub {{
                text-align: center;
                color: #cbd5e1;
                margin-bottom: 30px;
            }}

            form {{
                margin: 0;
            }}

            input, select {{
                width: 100%;
                padding: 12px 14px;
                margin: 8px 0 14px;
                border-radius: 12px;
                border: 1px solid rgba(255,255,255,0.15);
                background: rgba(255,255,255,0.08);
                color: white;
                outline: none;
            }}

            input::placeholder {{
                color: #cbd5e1;
            }}

            .btn {{
                display: inline-block;
                padding: 12px 18px;
                border-radius: 12px;
                border: none;
                cursor: pointer;
                font-weight: 700;
                background: linear-gradient(135deg, #9333ea, #6366f1);
                color: white;
                text-decoration: none;
                margin-right: 8px;
                margin-top: 6px;
            }}

            .btn.secondary {{
                background: rgba(255,255,255,0.10);
                border: 1px solid rgba(255,255,255,0.12);
            }}

            .grid {{
                display: grid;
                gap: 16px;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            }}

            .stat {{
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 16px;
                padding: 18px;
            }}

            .stat-label {{
                color: #cbd5e1;
                font-size: 14px;
                margin-bottom: 8px;
            }}

            .stat-value {{
                font-size: 30px;
                font-weight: 800;
            }}

            .alert {{
                padding: 12px 14px;
                border-radius: 12px;
                margin-bottom: 16px;
                font-weight: 600;
            }}

            .alert.error {{
                background: rgba(239, 68, 68, 0.18);
                border: 1px solid rgba(239, 68, 68, 0.35);
            }}

            .alert.success {{
                background: rgba(34, 197, 94, 0.18);
                border: 1px solid rgba(34, 197, 94, 0.35);
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 18px;
                overflow: hidden;
                border-radius: 14px;
            }}

            th, td {{
                padding: 12px;
                border-bottom: 1px solid rgba(255,255,255,0.10);
                text-align: center;
            }}

            th {{
                color: #cbd5e1;
                font-size: 14px;
            }}

            .topbar {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 12px;
                flex-wrap: wrap;
                margin-bottom: 24px;
            }}

            .small {{
                color: #cbd5e1;
                font-size: 14px;
            }}

            .section {{
                margin-top: 24px;
            }}

            @media (max-width: 640px) {{
                body {{
                    padding: 14px;
                }}

                .card {{
                    padding: 18px;
                }}

                .brand {{
                    font-size: 26px;
                }}

                .stat-value {{
                    font-size: 24px;
                }}

                th, td {{
                    padding: 10px 8px;
                    font-size: 13px;
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

                if user["role"] == "admin":
                    return redirect(url_for("admin"))
                return redirect(url_for("client"))
            else:
                message = '<div class="alert error">Invalid username or password.</div>'

    success_message = ""
    if success == "account_created":
        success_message = '<div class="alert success">Account created. You can log in now.</div>'

    body = f"""
    <div class="card" style="max-width:520px; margin:40px auto;">
        <div class="brand">Lucid Mage Touchpoint Dashboard</div>
        <div class="sub">Track comments, DMs, reactions, friend requests, and compounding Facebook activity.</div>
        {success_message}
        {message}
        <form method="POST">
            <label>Username</label>
            <input name="username" placeholder="Enter username" />

            <label>Password</label>
            <input name="password" type="password" placeholder="Enter password" />

            <button class="btn" type="submit">Login</button>
            <a class="btn secondary" href="/create-account">Create Account</a>
        </form>
        <div class="section small">
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
    <div class="card" style="max-width:520px; margin:40px auto;">
        <div class="brand">Create Client Account</div>
        <div class="sub">This creates a client login for the dashboard.</div>
        {message}
        <form method="POST">
            <label>Username</label>
            <input name="username" placeholder="Choose a username" />

            <label>Password</label>
            <input name="password" type="password" placeholder="Choose a password" />

            <label>Confirm Password</label>
            <input name="confirm_password" type="password" placeholder="Confirm password" />

            <button class="btn" type="submit">Create Account</button>
            <a class="btn secondary" href="/">Back to Login</a>
        </form>
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
        comments = request.form.get("comments", "0").strip()
        dms = request.form.get("dms", "0").strip()
        reactions = request.form.get("reactions", "0").strip()
        friends = request.form.get("friends", "0").strip()

        if not client:
            message = '<div class="alert error">Please enter a client username.</div>'
        else:
            try:
                comments = int(comments or 0)
                dms = int(dms or 0)
                reactions = int(reactions or 0)
                friends = int(friends or 0)

                conn = get_db()

                # Make sure client exists
                client_user = conn.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (client,)
                ).fetchone()

                if not client_user:
                    message = '<div class="alert error">That client username does not exist yet. Create the account first.</div>'
                else:
                    conn.execute("""
                        INSERT INTO touchpoints (client, comments, dms, reactions, friends, date)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        client,
                        comments,
                        dms,
                        reactions,
                        friends,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    ))
                    conn.commit()
                    message = '<div class="alert success">Touchpoints added successfully.</div>'

                conn.close()

            except ValueError:
                message = '<div class="alert error">Comments, DMs, reactions, and friend requests must be numbers.</div>'

    conn = get_db()
    clients = conn.execute(
        "SELECT username FROM users WHERE role = 'client' ORDER BY username"
    ).fetchall()

    recent_rows = conn.execute("""
        SELECT client, comments, dms, reactions, friends, date
        FROM touchpoints
        ORDER BY id DESC
        LIMIT 20
    """).fetchall()
    conn.close()

    total_touchpoints = 0
    total_comments = 0
    total_dms = 0
    total_reactions = 0
    total_friends = 0

    rows_html = ""
    for row in recent_rows:
        row_total = row["comments"] + row["dms"] + row["reactions"] + row["friends"]
        total_touchpoints += row_total
        total_comments += row["comments"]
        total_dms += row["dms"]
        total_reactions += row["reactions"]
        total_friends += row["friends"]

        rows_html += f"""
        <tr>
            <td>{row["client"]}</td>
            <td>{row["date"]}</td>
            <td>{row["comments"]}</td>
            <td>{row["dms"]}</td>
            <td>{row["reactions"]}</td>
            <td>{row["friends"]}</td>
            <td>{row_total}</td>
        </tr>
        """

    client_options = "".join(
        [f'<option value="{c["username"]}">{c["username"]}</option>' for c in clients]
    )

    body = f"""
    <div class="topbar">
        <div>
            <h1 style="margin-bottom:6px;">Admin Dashboard</h1>
            <div class="small">Logged in as {session.get("user")} | Operator Control Panel</div>
        </div>
        <div>
            <a class="btn secondary" href="/create-account">Create Client Account</a>
            <a class="btn secondary" href="/logout">Logout</a>
        </div>
    </div>

    <div class="grid">
        <div class="stat"><div class="stat-label">Recent Total Touchpoints</div><div class="stat-value">{total_touchpoints}</div></div>
        <div class="stat"><div class="stat-label">Comments</div><div class="stat-value">{total_comments}</div></div>
        <div class="stat"><div class="stat-label">DMs</div><div class="stat-value">{total_dms}</div></div>
        <div class="stat"><div class="stat-label">Reactions</div><div class="stat-value">{total_reactions}</div></div>
        <div class="stat"><div class="stat-label">Friend Requests</div><div class="stat-value">{total_friends}</div></div>
    </div>

    <div class="section card">
        <h2>Add Touchpoints</h2>
        <div class="small">Log daily work for a specific client.</div>
        {message}
        <form method="POST">
            <label>Client Username</label>
            <select name="client">
                <option value="">Select a client</option>
                {client_options}
            </select>

            <div class="grid">
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
            </div>

            <button class="btn" type="submit">Save Touchpoints</button>
        </form>
    </div>

    <div class="section card">
        <h2>Recent Logged Activity</h2>
        <table>
            <tr>
                <th>Client</th>
                <th>Date</th>
                <th>Comments</th>
                <th>DMs</th>
                <th>Reactions</th>
                <th>Friends</th>
                <th>Total</th>
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

    total = 0
    total_comments = 0
    total_dms = 0
    total_reactions = 0
    total_friends = 0

    today_total = 0
    week_total = 0
    month_total = 0

    now = datetime.now()
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    table_rows = ""

    for r in rows:
        row_total = r["comments"] + r["dms"] + r["reactions"] + r["friends"]

        total += row_total
        total_comments += r["comments"]
        total_dms += r["dms"]
        total_reactions += r["reactions"]
        total_friends += r["friends"]

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
            <td>{row_total}</td>
        </tr>
        """

    body = f"""
    <div class="topbar">
        <div>
            <h1 style="margin-bottom:6px;">{username} Dashboard</h1>
            <div class="small">Your Facebook touchpoint progress and compounding activity</div>
        </div>
        <div>
            <a class="btn secondary" href="/logout">Logout</a>
        </div>
    </div>

    <div class="grid">
        <div class="stat"><div class="stat-label">Today</div><div class="stat-value">{today_total}</div></div>
        <div class="stat"><div class="stat-label">Last 7 Days</div><div class="stat-value">{week_total}</div></div>
        <div class="stat"><div class="stat-label">Last 30 Days</div><div class="stat-value">{month_total}</div></div>
        <div class="stat"><div class="stat-label">All-Time Total</div><div class="stat-value">{total}</div></div>
    </div>

    <div class="section grid">
        <div class="stat"><div class="stat-label">Comments</div><div class="stat-value">{total_comments}</div></div>
        <div class="stat"><div class="stat-label">DMs</div><div class="stat-value">{total_dms}</div></div>
        <div class="stat"><div class="stat-label">Reactions</div><div class="stat-value">{total_reactions}</div></div>
        <div class="stat"><div class="stat-label">Friend Requests</div><div class="stat-value">{total_friends}</div></div>
    </div>

    <div class="section card">
        <h2>Activity Log</h2>
        <table>
            <tr>
                <th>Date</th>
                <th>Comments</th>
                <th>DMs</th>
                <th>Reactions</th>
                <th>Friends</th>
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
'''.encode('ascii').decode('ascii')  # validate ASCII-only text
reqs = 'Flask
gunicorn
'.encode('ascii').decode('ascii')

with open('/mnt/data/app_upgraded_exact.txt', 'w', encoding='ascii', newline='\n') as f:
    f.write(code)
with open('/mnt/data/requirements_upgraded_exact.txt', 'w', encoding='ascii', newline='\n') as f:
    f.write(reqs)

print('/mnt/data/app_upgraded_exact.txt')
print('/mnt/data/requirements_upgraded_exact.txt')
