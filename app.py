from flask import Flask, render_template, request, redirect, url_for, session, flash
import os, random, string
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ------------------- USER & KEY MANAGEMENT ------------------- #
def get_users():
    if not os.path.exists("users.txt"):
        return {}
    users = {}
    with open("users.txt", "r") as f:
        for line in f:
            if "||" in line:
                u, e, p = line.strip().split("||")
                users[u] = {"email": e, "pin": p}
    return users

def save_user(username, email, hashed_pin):
    with open("users.txt", "a") as f:
        f.write(f"{username}||{email}||{hashed_pin}\n")

def update_user_pin(username, new_hashed_pin):
    users = get_users()
    users[username]["pin"] = new_hashed_pin
    with open("users.txt", "w") as f:
        for u, data in users.items():
            f.write(f"{u}||{data['email']}||{data['pin']}\n")

def create_user_key(username):
    key = Fernet.generate_key()
    with open(f"{username}_key.key", "wb") as f:
        f.write(key)
    return key

def load_user_key(username):
    if not os.path.exists(f"{username}_key.key"):
        return create_user_key(username)
    with open(f"{username}_key.key", "rb") as f:
        return f.read()

def encrypt_password(password, key):
    cipher = Fernet(key)
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(enc_password, key):
    cipher = Fernet(key)
    return cipher.decrypt(enc_password.encode()).decode()

# ------------------- PASSWORD GENERATOR ------------------- #
def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# ------------------- ROUTES ------------------- #
@app.route("/")
def home():
    return render_template("base.html")

# ---------- REGISTER ----------
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
        flash(f"✅ Account created for {username}. Please login.")
        return redirect(url_for("login"))
    return render_template("signup.html")

# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        pin = request.form["pin"].strip()
        users = get_users()
        if username in users and check_password_hash(users[username]["pin"], pin):
            session["username"] = username
            return redirect(url_for("dashboard"))
        flash("❌ Invalid username or PIN!")
    return render_template("login.html")

# ---------- DASHBOARD ----------
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    
    username = session["username"]
    key = load_user_key(username)
    filename = f"passwords_{username}.txt"
    passwords = []

    # Ensure file exists
    if not os.path.exists(filename):
        open(filename, "w").close()

    with open(filename, "r") as f:
        for line in f:
            if "||" in line:
                site, enc_pass = line.strip().split("||")
                try:
                    dec_pass = decrypt_password(enc_pass, key)
                except:
                    dec_pass = "Error decrypting"
                passwords.append({"site": site, "password": dec_pass})

    return render_template("dashboard.html", username=username, passwords=passwords)

# ---------- ADD PASSWORD ----------
@app.route("/add", methods=["POST"])
def add_password():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    site = request.form["website"]
    password = request.form["password"]
    key = load_user_key(username)
    enc_pass = encrypt_password(password, key)
    filename = f"passwords_{username}.txt"

    with open(filename, "a") as f:
        f.write(f"{site}||{enc_pass}\n")

    flash(f"Password added for {site} ✅")
    return redirect(url_for("dashboard"))

# ---------- EDIT PASSWORD ----------
@app.route("/edit/<site>", methods=["GET", "POST"])
def edit_password(site):
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    key = load_user_key(username)
    filename = f"passwords_{username}.txt"

    if not os.path.exists(filename):
        open(filename, "w").close()

    with open(filename, "r") as f:
        lines = f.readlines()

    if request.method == "POST":
        new_pass = request.form["password"]
        enc_pass = encrypt_password(new_pass, key)
        with open(filename, "w") as f:
            for line in lines:
                s, _ = line.strip().split("||")
                if s == site:
                    f.write(f"{site}||{enc_pass}\n")
                else:
                    f.write(line)
        flash(f"Password updated for {site} ✅")
        return redirect(url_for("dashboard"))

    current_pass = ""
    for line in lines:
        if line.startswith(site + "||"):
            _, enc_pass = line.strip().split("||")
            try:
                current_pass = decrypt_password(enc_pass, key)
            except:
                current_pass = "Error decrypting"
    return render_template("edit.html", site=site, password=current_pass)

# ---------- DELETE PASSWORD ----------
@app.route("/delete/<site>", methods=["POST"])
def delete_password(site):
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    filename = f"passwords_{username}.txt"

    if not os.path.exists(filename):
        open(filename, "w").close()

    with open(filename, "r") as f:
        lines = f.readlines()
    with open(filename, "w") as f:
        for line in lines:
            if not line.startswith(site + "||"):
                f.write(line)
    flash(f"Deleted password for {site} ✅")
    return redirect(url_for("dashboard"))

# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("Logged out successfully.")
    return redirect(url_for("login"))

# ---------- RESET PIN ----------
@app.route("/reset", methods=["GET", "POST"])
def reset_pin():
    if request.method == "POST":
        username = request.form["username"].strip()
        users = get_users()
        if username not in users:
            return render_template("reset.html", error="❌ Username not found!")
        new_pin = str(random.randint(1000, 9999))
        new_hashed_pin = generate_password_hash(new_pin)
        update_user_pin(username, new_hashed_pin)
        return render_template("reset.html", username=username, new_pin=new_pin)
    return render_template("reset.html")

# ---------- PASSWORD GENERATOR API ----------
@app.route("/generate_password")
def generate_pass():
    return generate_password(16)

if __name__ == "__main__":
    app.run(debug=True)
