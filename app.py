from flask import Flask, render_template, request, redirect, url_for, session, flash
import os, random, string
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------- Config ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "supersecretkey")

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

# ---------------- Helpers ----------------
def user_password_file(username):
    safe = secure_filename(username)
    return os.path.join(DATA_DIR, f"passwords_{safe}.txt")

def user_key_file(username):
    safe = secure_filename(username)
    return os.path.join(DATA_DIR, f"{safe}_key.key")

# ------------------- USER MANAGEMENT ------------------- #
def get_users():
    users_path = os.path.join(DATA_DIR, "users.txt")
    if not os.path.exists(users_path):
        return {}
    users = {}
    with open(users_path, "r") as f:
        for line in f:
            if "||" in line:
                u, e, p = line.strip().split("||")
                users[u] = {"email": e, "pin": p}
    return users

def save_user(username, email, hashed_pin):
    users_path = os.path.join(DATA_DIR, "users.txt")
    with open(users_path, "a") as f:
        f.write(f"{username}||{email}||{hashed_pin}\n")

def update_user_pin(username, new_hashed_pin):
    users = get_users()
    users[username]["pin"] = new_hashed_pin
    users_path = os.path.join(DATA_DIR, "users.txt")
    with open(users_path, "w") as f:
        for u, data in users.items():
            f.write(f"{u}||{data['email']}||{data['pin']}\n")

# ------------------- USER KEY (per-user Fernet) ------------------- #
def create_user_key(username):
    key = Fernet.generate_key()
    with open(user_key_file(username), "wb") as f:
        f.write(key)
    return key

def load_user_key(username):
    path = user_key_file(username)
    if not os.path.exists(path):
        return create_user_key(username)
    with open(path, "rb") as f:
        return f.read()

def encrypt_password(password, key):
    cipher = Fernet(key)
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(enc_password, key):
    cipher = Fernet(key)
    return cipher.decrypt(enc_password.encode()).decode()

# ------------------- PASSWORD GENERATOR ------------------- #
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# ------------------- ROUTES ------------------- #
@app.route("/")
def home():
    return render_template("base.html")

# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        pin = request.form["pin"].strip()
        users = get_users()
        if username in users:
            flash("⚠️ Username already exists!")
            return redirect(url_for("register"))
        hashed_pin = generate_password_hash(pin)
        save_user(username, email, hashed_pin)
        create_user_key(username)
        # Ensure user's password file exists
        open(user_password_file(username), "a").close()
        flash(f"✅ Account created for {username}. Please login.")
        return redirect(url_for("login"))
    return render_template("signup.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        pin = request.form["pin"].strip()
        users = get_users()
        if username in users and check_password_hash(users[username]["pin"], pin):
            session["username"] = username
            flash("✅ Logged in.")
            return redirect(url_for("dashboard"))
        flash("❌ Invalid username or PIN!")
    return render_template("login.html")

# Dashboard - view, add, search
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    key = load_user_key(username)
    fname = user_password_file(username)
    # ensure file exists
    if not os.path.exists(fname):
        open(fname, "a").close()

    passwords = []
    with open(fname, "r") as f:
        for line in f:
            if "||" in line:
                site, enc_pass = line.strip().split("||")
                try:
                    dec_pass = decrypt_password(enc_pass, key)
                except Exception as e:
                    dec_pass = "Error decrypting"
                passwords.append({"site": site, "password": dec_pass})
    return render_template("dashboard.html", username=username, passwords=passwords, generate_password=generate_password)

# Add password
@app.route("/add", methods=["POST"])
def add_password():
    if "username" not in session:
        return redirect(url_for("login"))
    username = session["username"]
    site = request.form["website"].strip()
    password = request.form["password"].strip()
    key = load_user_key(username)
    enc = encrypt_password(password, key)
    fname = user_password_file(username)
    with open(fname, "a") as f:
        f.write(f"{site}||{enc}\n")
    flash(f"Password added for {site} ✅")
    return redirect(url_for("dashboard"))

# Edit password (shows edit page + processes update)
@app.route("/edit/<site>", methods=["GET", "POST"])
def edit_password(site):
    if "username" not in session:
        return redirect(url_for("login"))
    username = session["username"]
    key = load_user_key(username)
    fname = user_password_file(username)
    if not os.path.exists(fname):
        open(fname, "a").close()
    with open(fname, "r") as f:
        lines = f.readlines()

    if request.method == "POST":
        new_pass = request.form["password"].strip()
        enc = encrypt_password(new_pass, key)
        with open(fname, "w") as f:
            for line in lines:
                s, _ = line.strip().split("||")
                if s == site:
                    f.write(f"{site}||{enc}\n")
                else:
                    f.write(line)
        flash(f"Password updated for {site} ✅")
        return redirect(url_for("dashboard"))

    current = ""
    for line in lines:
        if line.startswith(site + "||"):
            _, enc_pass = line.strip().split("||")
            try:
                current = decrypt_password(enc_pass, key)
            except:
                current = "Error decrypting"
    return render_template("edit.html", site=site, password=current)

# Delete password
@app.route("/delete/<site>", methods=["POST"])
def delete_password(site):
    if "username" not in session:
        return redirect(url_for("login"))
    username = session["username"]
    fname = user_password_file(username)
    if not os.path.exists(fname):
        open(fname, "a").close()
    with open(fname, "r") as f:
        lines = f.readlines()
    with open(fname, "w") as f:
        for line in lines:
            if not line.startswith(site + "||"):
                f.write(line)
    flash(f"Deleted password for {site} ✅")
    return redirect(url_for("dashboard"))

# Logout
@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("Logged out successfully.")
    return redirect(url_for("login"))

# Reset PIN
@app.route("/reset", methods=["GET", "POST"])
def reset_pin():
    if request.method == "POST":
        username = request.form["username"].strip()
        users = get_users()
        if username not in users:
            return render_template("reset.html", error="❌ Username not found!")
        new_pin = str(random.randint(1000, 9999))
        new_hashed = generate_password_hash(new_pin)
        update_user_pin(username, new_hashed)
        flash("✅ PIN reset. Please note the new PIN.")
        return render_template("reset.html", username=username, new_pin=new_pin)
    return render_template("reset.html")

# Password generator API (JS-friendly)
@app.route("/generate_password")
def generate_pass():
    return generate_password(16)

# ---------------- Run ----------------
if __name__ == "__main__":
    app.run(debug=True)
