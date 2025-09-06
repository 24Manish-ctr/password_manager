from flask import Flask, render_template, request, redirect, url_for, session
import os, random
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "supersecretkey"

def load_key():
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as f:
            f.write(key)
    with open("key.key", "rb") as f:
        return f.read()

def encrypt_password(password, key):
    cipher = Fernet(key)
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(enc_password, key):
    cipher = Fernet(key)
    return cipher.decrypt(enc_password.encode()).decode()

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

def save_user(username, email, pin):
    with open("users.txt", "a") as f:
        f.write(f"{username}||{email}||{pin}\n")

def update_user_pin(username, new_pin):
    users = get_users()
    users[username]["pin"] = new_pin
    with open("users.txt", "w") as f:
        for u, data in users.items():
            f.write(f"{u}||{data['email']}||{data['pin']}\n")

@app.route("/")
def home():
    return render_template("base.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        pin = request.form["pin"].strip()
        users = get_users()
        if username in users:
            return "⚠️ Username already exists!"
        save_user(username, email, pin)
        return f"✅ Account created for {username}. <a href='/login'>Login</a>"
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        pin = request.form["pin"].strip()
        users = get_users()
        if username in users and users[username]["pin"] == pin:
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            return "❌ Invalid username or PIN!"
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    key = load_key()
    filename = f"passwords_{session['username']}.txt"
    passwords = []
    if os.path.exists(filename):
        with open(filename, "r") as f:
            for line in f:
                if "||" in line:
                    site, enc_pass = line.strip().split("||")
                    dec_pass = decrypt_password(enc_pass, key)
                    passwords.append((site, dec_pass))
    return render_template("dashboard.html", username=session["username"], passwords=passwords)

@app.route("/add", methods=["POST"])
def add_password():
    if "username" not in session:
        return redirect(url_for("login"))
    key = load_key()
    filename = f"passwords_{session['username']}.txt"
    site = request.form["website"]
    password = request.form["password"]
    enc_pass = encrypt_password(password, key)
    with open(filename, "a") as f:
        f.write(f"{site}||{enc_pass}\n")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

@app.route("/reset", methods=["GET", "POST"])
def reset_pin():
    if request.method == "POST":
        username = request.form["username"].strip()
        users = get_users()
        if username not in users:
            return render_template("reset.html", error="❌ Username not found!")
        new_pin = str(random.randint(1000, 9999))
        update_user_pin(username, new_pin)
        return render_template("reset.html", username=username, new_pin=new_pin)
    return render_template("reset.html")

if __name__ == "__main__":
    app.run(debug=True)
