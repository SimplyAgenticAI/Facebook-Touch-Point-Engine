from flask import Flask, request, redirect, session
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = "lucidmage_secret"

def get_db():
    conn = sqlite3.connect("touchpoints.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        role TEXT
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS touchpoints (
        id INTEGER PRIMARY KEY,
        client TEXT,
        comments INTEGER,
        dms INTEGER,
        reactions INTEGER,
        friends INTEGER,
        date TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

@app.route("/", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username,password)
        ).fetchone()

        if user:
            session["user"] = username
            session["role"] = user["role"]

            if user["role"] == "admin":
                return redirect("/admin")
            else:
                return redirect("/client")

    return """
    <html>
    <style>
    body{
        background:#020617;
        color:white;
        font-family:Arial;
        text-align:center;
        padding-top:100px;
    }
    input{
        padding:10px;
        margin:10px;
        width:200px;
    }
    button{
        padding:10px 20px;
        background:#9333ea;
        border:none;
        color:white;
    }
    </style>

    <h1>Facebook Touchpoint Dashboard</h1>

    <form method="POST">
    <input name="username" placeholder="username"><br>
    <input name="password" type="password" placeholder="password"><br>
    <button>Login</button>
    </form>
    </html>
    """

@app.route("/admin", methods=["GET","POST"])
def admin():

    if session.get("role") != "admin":
        return redirect("/")

    if request.method == "POST":

        client = request.form["client"]
        comments = request.form["comments"]
        dms = request.form["dms"]
        reactions = request.form["reactions"]
        friends = request.form["friends"]

        conn = get_db()
        conn.execute("""
        INSERT INTO touchpoints
        (client,comments,dms,reactions,friends,date)
        VALUES (?,?,?,?,?,?)
        """,(client,comments,dms,reactions,friends,datetime.now()))

        conn.commit()

    return """
    <html>
    <style>
    body{
        background:#020617;
        color:white;
        font-family:Arial;
        text-align:center;
    }
    input{
        padding:10px;
        margin:5px;
        width:150px;
    }
    button{
        padding:10px;
        background:#9333ea;
        color:white;
        border:none;
    }
    </style>

    <h1>Admin Panel</h1>

    <form method="POST">

    <input name="client" placeholder="client name"><br>

    <input name="comments" placeholder="comments"><br>

    <input name="dms" placeholder="dms"><br>

    <input name="reactions" placeholder="reactions"><br>

    <input name="friends" placeholder="friend requests"><br>

    <button>Add Touchpoints</button>

    </form>

    <br><br>

    <a href="/logout">Logout</a>

    </html>
    """

@app.route("/client")
def client():

    if "user" not in session:
        return redirect("/")

    client = session["user"]

    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM touchpoints WHERE client=?",
        (client,)
    ).fetchall()

    total = 0

    for r in rows:
        total += r["comments"] + r["dms"] + r["reactions"] + r["friends"]

    table = ""

    for r in rows:
        table += f"""
        <tr>
        <td>{r['date']}</td>
        <td>{r['comments']}</td>
        <td>{r['dms']}</td>
        <td>{r['reactions']}</td>
        <td>{r['friends']}</td>
        </tr>
        """

    return f"""

    <html>

    <style>

    body{{
        background:#020617;
        color:white;
        font-family:Arial;
        text-align:center;
    }}

    table{{
        margin:auto;
        margin-top:40px;
        border-collapse:collapse;
    }}

    td,th{{
        padding:10px;
        border:1px solid #444;
    }}

    </style>

    <h1>{client} Dashboard</h1>

    <h2>Total Touchpoints</h2>

    <h1>{total}</h1>

    <table>

    <tr>
    <th>Date</th>
    <th>Comments</th>
    <th>DMs</th>
    <th>Reactions</th>
    <th>Friends</th>
    </tr>

    {table}

    </table>

    <br>

    <a href="/logout">Logout</a>

    </html>

    """

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

app.run(host="0.0.0.0", port=10000)
