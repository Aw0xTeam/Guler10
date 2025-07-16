from flask import Flask, render_template
from models import Session, Alert, Log

app = Flask(__name__)
session = Session()

@app.route("/")
def index():
    alerts = session.query(Alert).filter(Alert.threshold > 0).all()
    return render_template("admin.html", alerts=alerts)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
