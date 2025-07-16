from flask import Flask, render_template
import sqlite3

app = Flask(__name__)
DB_FILE = 'alerts.db'

@app.route("/")
def home():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM alerts WHERE threshold > 0")
    alerts = c.fetchall()
    conn.close()
    return render_template("admin.html", alerts=alerts)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
