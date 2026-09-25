from flask import Flask, request, redirect, url_for, session, render_template_string
import sqlite3
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)

# Change this in production and keep it secret.
app.secret_key = "change-this-to-a-long-random-secret-key"

DATABASE = "users.db"
ph = PasswordHasher()

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login</title>
    <style>
        body {
            font-family: Arial;
            background: #f4f4f4;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .box {
            background: white;
            padding: 30px;
            width: 350px;
            border-radius: 10px;
            box-shadow: 0 0 15px #ccc;
        }
        input {
            width: 100%;
            padding: 10px;
            margin: 8px 0 15px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 10px;
            background: #2563eb;
            color: white;
            border: none;
            cursor: pointer;
        }
        a {
            color: #2563eb;
        }
        .message {
            color: #c00;
        }
    </style>
</head>
<body>
<div class="box">
    {{ content|safe }}
</div>
</body>
</html>
"""


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


@app.route("/")
def home():
    if "user_id" in session:
        content = f"""
        <h2>Welcome, {session['username']}!</h2>
        <p>You are successfully logged in.</p>
        <a href="/logout">Logout</a>
        """
    else:
        content = """
        <h2>Secure Login System</h2>
        <p><a href="/register">Register</a></p>
        <p><a href="/login">Login</a></p>
        """

    return render_template_string(HTML, content=content)


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Basic validation
        if len(username) < 3 or len(username) > 50:
            message = "Username must contain 3-50 characters."
            return render_template_string(
                HTML,
                content=f"<p class='message'>{message}</p>"
                        "<a href='/register'>Try again</a>"
            )

        if len(password) < 8:
            message = "Password must contain at least 8 characters."
            return render_template_string(
                HTML,
                content=f"<p class='message'>{message}</p>"
                        "<a href='/register'>Try again</a>"
            )

        # Hash password using Argon2
        password_hash = ph.hash(password)

        conn = get_db()

        try:
            # Parameterized query prevents SQL injection
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()

            return render_template_string(
                HTML,
                content="""
                <p class="message">Username already exists.</p>
                <a href="/register">Try again</a>
                """
            )

        conn.close()

        return redirect(url_for("login"))

    content = """
    <h2>Create Account</h2>

    <form method="POST">
        <label>Username</label>
        <input type="text" name="username" required>

        <label>Password</label>
        <input type="password" name="password" required>

        <button type="submit">Register</button>
    </form>

    <p><a href="/login">Already have an account?</a></p>
    """

    return render_template_string(HTML, content=content)


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()

        # Parameterized query
        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user is None:
            return render_template_string(
                HTML,
                content="""
                <p class="message">Invalid username or password.</p>
                <a href="/login">Try again</a>
                """
            )

        try:
            # Verify Argon2 password
            ph.verify(user["password_hash"], password)

        except VerifyMismatchError:
            return render_template_string(
                HTML,
                content="""
                <p class="message">Invalid username or password.</p>
                <a href="/login">Try again</a>
                """
            )

        # Create authenticated session
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]

        return redirect(url_for("home"))

    content = """
    <h2>Login</h2>

    <form method="POST">
        <label>Username</label>
        <input type="text" name="username" required>

        <label>Password</label>
        <input type="password" name="password" required>

        <button type="submit">Login</button>
    </form>

    <p><a href="/register">Create an account</a></p>
    """

    return render_template_string(HTML, content=content)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()

    app.run(
        debug=False,
        host="127.0.0.1",
        port=5000
    )
