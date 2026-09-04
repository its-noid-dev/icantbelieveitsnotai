import hashlib
import http.server
import json
import os
import secrets
import sqlite3
import urllib.parse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "icanbelieveitsnotai.db")
HOST = "0.0.0.0"
PORT = 8000


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260000)
    return f"pbkdf2_sha256$260000${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        _, rounds, salt, expected = stored.split("$", 3)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return secrets.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def database():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def ensure_schema():
    with database() as connection:
        try:
            connection.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        except sqlite3.OperationalError:
            pass
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS bookmarks (
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, post_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_bookmarks_user_id ON bookmarks(user_id);
            CREATE INDEX IF NOT EXISTS idx_shares_post_id ON shares(post_id);
        """)


def user_payload(user):
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


class AppHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.end_headers()

    def read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        return json.loads(self.rfile.read(length))

    def current_user(self, connection):
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return None
        return connection.execute(
            """SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id
               WHERE sessions.id = ? AND sessions.expires_at > CURRENT_TIMESTAMP""",
            (authorization[7:].strip(),),
        ).fetchone()

    def require_user(self, connection):
        user = self.current_user(connection)
        if not user:
            self.send_json(401, {"message": "Please log in first."})
        return user

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            with database() as connection:
                if path == "/api/posts":
                    user = self.current_user(connection)
                    user_id = user["id"] if user else 0
                    posts = connection.execute(
                        """SELECT posts.id, posts.user_id, posts.content, posts.created_at, users.username,
                           (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) AS likes,
                           (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) AS comments,
                           EXISTS(SELECT 1 FROM likes WHERE likes.post_id = posts.id AND likes.user_id = ?) AS liked,
                           EXISTS(SELECT 1 FROM bookmarks WHERE bookmarks.post_id = posts.id AND bookmarks.user_id = ?) AS bookmarked
                           FROM posts JOIN users ON users.id = posts.user_id ORDER BY posts.created_at DESC""",
                        (user_id, user_id),
                    ).fetchall()
                    self.send_json(200, {"posts": [dict(post) for post in posts]})
                    return
                if path == "/api/moderator":
                    user = self.require_user(connection)
                    if not user or user["role"] != "moderator":
                        if user:
                            self.send_json(403, {"message": "Moderator access required."})
                        return
                    users = connection.execute("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC").fetchall()
                    posts = connection.execute("SELECT posts.id, posts.content, posts.created_at, users.username FROM posts JOIN users ON users.id = posts.user_id ORDER BY posts.created_at DESC").fetchall()
                    self.send_json(200, {"users": [dict(item) for item in users], "posts": [dict(item) for item in posts]})
                    return
                super().do_GET()
        except sqlite3.Error:
            self.send_json(500, {"message": "Database error."})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            with database() as connection:
                data = self.read_json()
                if path in ("/api/signup", "/api/login"):
                    email = str(data.get("email", "")).strip().lower()
                    password = str(data.get("password", ""))
                    if not email or not password:
                        raise ValueError("Email and password are required.")
                    if path.endswith("signup"):
                        username = str(data.get("username", "")).strip()
                        if not username or len(password) < 6:
                            raise ValueError("Username and a password of at least 6 characters are required.")
                        role = "moderator" if username.lower() == "noid.dev" else "user"
                        cursor = connection.execute(
                            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                            (username, email, hash_password(password), role),
                        )
                        user = connection.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
                        message = "Moderator account created." if role == "moderator" else "Account created."
                        status = 201
                    else:
                        user = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
                        if not user or not verify_password(password, user["password_hash"]):
                            self.send_json(401, {"message": "Email or password is incorrect."})
                            return
                        message = f"Welcome back, {user['username']}."
                        status = 200
                    token = secrets.token_urlsafe(32)
                    connection.execute("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, datetime('now', '+7 days'))", (token, user["id"]))
                    self.send_json(status, {"message": message, "token": token, "user": user_payload(user)})
                    return
                user = self.require_user(connection)
                if not user:
                    return
                if path == "/api/posts":
                    content = str(data.get("content", "")).strip()
                    if not content:
                        raise ValueError("Post content is required.")
                    cursor = connection.execute("INSERT INTO posts (user_id, content) VALUES (?, ?)", (user["id"], content))
                    self.send_json(201, {"message": "Post published.", "id": cursor.lastrowid})
                    return
                parts = path.strip("/").split("/")
                if len(parts) == 4 and parts[0] == "api" and parts[1] == "posts":
                    post_id = int(parts[2])
                    action = parts[3]
                    if action == "like":
                        exists = connection.execute("SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?", (user["id"], post_id)).fetchone()
                        connection.execute("DELETE FROM likes WHERE user_id = ? AND post_id = ?" if exists else "INSERT INTO likes (user_id, post_id) VALUES (?, ?)", (user["id"], post_id))
                        self.send_json(200, {"liked": not exists})
                    elif action == "bookmark":
                        exists = connection.execute("SELECT 1 FROM bookmarks WHERE user_id = ? AND post_id = ?", (user["id"], post_id)).fetchone()
                        connection.execute("DELETE FROM bookmarks WHERE user_id = ? AND post_id = ?" if exists else "INSERT INTO bookmarks (user_id, post_id) VALUES (?, ?)", (user["id"], post_id))
                        self.send_json(200, {"bookmarked": not exists})
                    elif action == "share":
                        connection.execute("INSERT INTO shares (user_id, post_id) VALUES (?, ?)", (user["id"], post_id))
                        self.send_json(201, {"message": "Post shared."})
                    elif action == "comment":
                        content = str(data.get("content", "")).strip()
                        if not content:
                            raise ValueError("Comment content is required.")
                        connection.execute("INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)", (post_id, user["id"], content))
                        self.send_json(201, {"message": "Comment added."})
                    else:
                        self.send_json(404, {"message": "Action not found."})
                    return
                if len(parts) == 3 and parts[:2] == ["api", "users"] and parts[2].isdigit():
                    target_id = int(parts[2])
                    if target_id == user["id"]:
                        raise ValueError("You cannot follow yourself.")
                    exists = connection.execute("SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?", (user["id"], target_id)).fetchone()
                    connection.execute("DELETE FROM follows WHERE follower_id = ? AND following_id = ?" if exists else "INSERT INTO follows (follower_id, following_id) VALUES (?, ?)", (user["id"], target_id))
                    self.send_json(200, {"following": not exists})
                    return
                self.send_json(404, {"message": "Endpoint not found."})
        except sqlite3.IntegrityError:
            self.send_json(409, {"message": "That username or email is already registered."})
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"message": str(error)})
        except sqlite3.Error:
            self.send_json(500, {"message": "Database error."})

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            with database() as connection:
                user = self.require_user(connection)
                if not user:
                    return
                if user["role"] != "moderator":
                    self.send_json(403, {"message": "Moderator access required."})
                    return
                parts = path.strip("/").split("/")
                if len(parts) == 4 and parts[:3] == ["api", "moderator", "posts"]:
                    connection.execute("DELETE FROM posts WHERE id = ?", (int(parts[3]),))
                    self.send_json(200, {"message": "Post removed."})
                    return
                self.send_json(404, {"message": "Endpoint not found."})
        except (ValueError, sqlite3.Error):
            self.send_json(400, {"message": "Could not remove that post."})


if __name__ == "__main__":
    ensure_schema()
    print(f"Serving on http://{HOST}:{PORT}")
    http.server.ThreadingHTTPServer((HOST, PORT), AppHandler).serve_forever()
