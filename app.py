from flask import Flask, render_template, request, redirect, url_for, session, Response, flash
import os, random, hashlib, csv
from cryptography.fernet import Fernet
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ------------------------
# UTILITIES
# ------------------------
def get_users():
    if not os.path.exists("users.txt"):
        return {}
    users = {}
    with open("users.txt", "r") as f:
        for line in f:
            if "||" in line:
                u, e, pin_hash, key = line.strip().split("||")
                users[u] = {"email": e, "pin_hash": pin_hash, "key": key}
    return users

def save_user(username, email, pin, key):
    pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    with open("users.txt", "a") as f:
        f.write(f"{username}||{email}||{pin_hash}||{key}\n")

def update_user_pin(username, new_pin):
    users = get_users()
    key = users[username]["key"]
    users[username]["pin_hash"] = hashlib.sha256(new_pin.encode()).hexdigest()
    with open("users.txt", "w") as f:
        for u, data in users.items():
            f.write(f"{u}||{data['email']}||{data['pin_hash']}||{data['key']}\n")

def generate_key():
    return Fernet.generate_key().decode()

def encrypt_password(password, key):
    cipher = Fernet(key.encode())
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(enc_password, key):
    cipher = Fernet(key.encode())
    return cipher.decrypt(enc_password.encode()).decode()

def generate_password(length=12):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    return "".join(random.choice(chars) for _ in range(length))

# ------------------------
# ROUTES
# ------------------------
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
        key = generate_key()
        save_user(username, email, pin, key)
        return f"✅ Account created for {username}. <a href='/login'>Login</a>"
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        pin = request.form["pin"].strip()
        users = get_users()
        if username in users and hashlib.sha256(pin.encode()).hexdigest() == users[username]["pin_hash"]:
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            return "❌ Invalid username or PIN!"
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    users = get_users()
    key = users[username]["key"]

    filename = f"passwords_{username}.txt"
    passwords = []
    if os.path.exists(filename):
        with open(filename, "r") as f:
            for line in f:
                if "||" in line:
                    site, enc_pass = line.strip().split("||")
                    try:
                        dec_pass = decrypt_password(enc_pass, key)
                    except:
                        dec_pass = "ERROR"
                    passwords.append({"site": site, "password": dec_pass})
    return render_template("dashboard.html", username=username, passwords=passwords)

@app.route("/add", methods=["POST"])
def add_password():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    users = get_users()
    key = users[username]["key"]

    site = request.form["website"]
    password = request.form["password"]
    enc_pass = encrypt_password(password, key)

    filename = f"passwords_{username}.txt"
    with open(filename, "a") as f:
        f.write(f"{site}||{enc_pass}\n")

    return redirect(url_for("dashboard"))

@app.route("/delete/<site>")
def delete_password(site):
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    filename = f"passwords_{username}.txt"
    if os.path.exists(filename):
        lines = []
        with open(filename, "r") as f:
            lines = f.readlines()
        with open(filename, "w") as f:
            for line in lines:
                if not line.startswith(site + "||"):
                    f.write(line)
    return redirect(url_for("dashboard"))

@app.route("/edit/<site>", methods=["GET", "POST"])
def edit_password(site):
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    users = get_users()
    key = users[username]["key"]
    filename = f"passwords_{username}.txt"

    if request.method == "POST":
        new_password = request.form["password"]
        enc_pass = encrypt_password(new_password, key)
        lines = []
        with open(filename, "r") as f:
            lines = f.readlines()
        with open(filename, "w") as f:
            for line in lines:
                if line.startswith(site + "||"):
                    f.write(f"{site}||{enc_pass}\n")
                else:
                    f.write(line)
        return redirect(url_for("dashboard"))

    # GET method
    current_password = ""
    if os.path.exists(filename):
        with open(filename, "r") as f:
            for line in f:
                if line.startswith(site + "||"):
                    enc_pass = line.strip().split("||")[1]
                    current_password = decrypt_password(enc_pass, key)
    return render_template("edit.html", site=site, password=current_password)

@app.route("/export_csv")
def export_csv():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    users = get_users()
    key = users[username]["key"]
    filename = f"passwords_{username}.txt"

    output = []
    if os.path.exists(filename):
        with open(filename, "r") as f:
            for line in f:
                if "||" in line:
                    site, enc_pass = line.strip().split("||")
                    try:
                        dec_pass = decrypt_password(enc_pass, key)
                    except:
                        dec_pass = "ERROR"
                    output.append([site, dec_pass])

    def generate():
        yield "Website,Password\n"
        for row in output:
            yield f"{row[0]},{row[1]}\n"

    return Response(generate(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={username}_passwords.csv"})

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
        # Here you can add email sending logic for OTP
        return render_template("reset.html", username=username, new_pin=new_pin)
    return render_template("reset.html")

if __name__ == "__main__":
    app.run(debug=True)
