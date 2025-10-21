import csv
from flask import Response

app.route("/export_csv")
def export_csv():
    if "username" not in session:
        return redirect(url_for("login"))
    username = session["username"]
    filename = f"passwords_{username}.txt"
    key = load_key()

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

    # Create CSV response
    def generate():
        yield "Website,Password\n"
        for row in output:
            yield f"{row[0]},{row[1]}\n"

    return Response(generate(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={username}_passwords.csv"})
