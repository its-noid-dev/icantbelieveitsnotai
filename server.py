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


class AppHandler(http.server.SimpleHTTPRequestHandler):
	 def __init__(self, *args, **kwargs):
		 super().__init__(*args, directory=BASE_DIR, **kwargs)

	 def send_json(self, status, payload):
		 body = json.dumps(payload).encode()
		 self.send_response(status)
		 self.send_header("Content-Type", "application/json")
		 self.send_header("Content-Length", str(len(body)))
		 self.send_header("Access-Control-Allow-Origin", "*")
		 self.end_headers()
		 self.wfile.write(body)

	 def do_OPTIONS(self):
		 self.send_response(204)
		 self.send_header("Access-Control-Allow-Origin", "*")
		 self.send_header("Access-Control-Allow-Headers", "Content-Type")
		 self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
		 self.end_headers()

	 def do_POST(self):
		 if self.path not in ("/api/signup", "/api/login"):
			 self.send_json(404, {"message": "Endpoint not found."})
			 return
		 try:
			 length = int(self.headers.get("Content-Length", 0))
			 data = json.loads(self.rfile.read(length))
			 email = str(data.get("email", "")).strip().lower()
			 password = str(data.get("password", ""))
			 if not email or not password:
				 raise ValueError("Email and password are required.")
			 with database() as connection:
				 if self.path.endswith("signup"):
					 username = str(data.get("username", "")).strip()
					 if not username or len(password) < 6:
						 raise ValueError("Username and a password of at least 6 characters are required.")
					 connection.execute(
						 "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
						 (username, email, hash_password(password)),
					 )
					 message = "Account created. You can now log in."
				 else:
					 user = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
					 if not user or not verify_password(password, user["password_hash"]):
						 self.send_json(401, {"message": "Email or password is incorrect."})
						 return
					 message = f"Welcome back, {user['username']}."
			 self.send_json(201 if self.path.endswith("signup") else 200, {"message": message})
		 except sqlite3.IntegrityError:
			 self.send_json(409, {"message": "That username or email is already registered."})
		 except (ValueError, json.JSONDecodeError) as error:
			 self.send_json(400, {"message": str(error)})
		 except sqlite3.Error:
			 self.send_json(500, {"message": "Database error."})


if __name__ == "__main__":
	 print(f"Serving on http://{HOST}:{PORT}")
	 http.server.ThreadingHTTPServer((HOST, PORT), AppHandler).serve_forever()