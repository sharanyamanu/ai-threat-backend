from flask import Flask, render_template, request, send_file, jsonify
import joblib
import pandas as pd
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Load model
model = joblib.load("threat_detection_model.pkl")

latest_data = None


# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("index.html", chart_data=[0,0,0])


# ---------------- API (SMART VERSION) ----------------
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    try:
        file = request.files["file"]
        data = pd.read_csv(file)

        print("Uploaded Columns:", data.columns)

        # 🔥 SMART COLUMN MAPPING
        col_map = {}

        for col in data.columns:
            c = col.lower()

            if "hour" in c:
                col_map["login_hour"] = col
            elif "fail" in c:
                col_map["failed_attempts"] = col
            elif "file" in c:
                col_map["files_accessed"] = col

        # ❌ If required columns not found
        if len(col_map) < 3:
            return jsonify({
                "error": "Invalid file format. Required columns like login_hour, failed_attempts, files_accessed not found."
            }), 400

        # 🔥 CREATE STANDARDIZED COLUMNS
        data['login_hour'] = data[col_map["login_hour"]]
        data['failed_attempts'] = data[col_map["failed_attempts"]]
        data['files_accessed'] = data[col_map["files_accessed"]]

        # -------- FEATURE ENGINEERING --------
        data['late_login'] = data['login_hour'].apply(lambda x: 1 if x < 6 else 0)
        data['high_failed'] = data['failed_attempts'].apply(lambda x: 1 if x > 3 else 0)
        data['high_file_access'] = data['files_accessed'].apply(lambda x: 1 if x > 100 else 0)

        features = data[['late_login','high_failed','high_file_access']]

        # -------- PREDICTION --------
        data['anomaly'] = model.predict(features)

        # -------- RISK SCORE --------
        data['risk_score'] = (
            data['late_login'] * 30 +
            data['high_failed'] * 40 +
            data['high_file_access'] * 30
        )

        # -------- RISK LEVEL --------
        def get_risk_level(score):
            if score >= 70:
                return "CRITICAL"
            elif score >= 50:
                return "HIGH"
            elif score >= 30:
                return "MEDIUM"
            else:
                return "LOW"

        data['risk_level'] = data['risk_score'].apply(get_risk_level)

        # -------- EXPLANATION --------
        def explain(row):
            reasons = []
            if row['late_login']:
                reasons.append("Unusual login time")
            if row['high_failed']:
                reasons.append("Multiple failed attempts")
            if row['high_file_access']:
                reasons.append("Excessive file access")
            return ", ".join(reasons) if reasons else "Normal behavior"

        data['explanation'] = data.apply(explain, axis=1)

        return jsonify(data.to_dict(orient="records"))

    except Exception as e:
        print("ERROR:", e)
        return jsonify({"error": str(e)}), 500


# ---------------- UPLOAD (OLD UI SUPPORT) ----------------
@app.route("/upload", methods=["POST"])
def upload():
    global latest_data

    file = request.files["file"]
    data = pd.read_csv(file)

    # Basic processing
    data['late_login'] = data['login_hour'].apply(lambda x: 1 if x < 6 else 0)
    data['high_failed'] = data['failed_attempts'].apply(lambda x: 1 if x > 3 else 0)
    data['high_file_access'] = data['files_accessed'].apply(lambda x: 1 if x > 100 else 0)

    features = data[['late_login','high_failed','high_file_access']]
    data['anomaly'] = model.predict(features)

    latest_data = data

    return render_template("index.html")


# ---------------- DOWNLOAD ----------------
@app.route("/download")
def download():
    global latest_data

    if latest_data is None:
        return "No data to download"

    latest_data.to_csv("report.csv", index=False)
    return send_file("report.csv", as_attachment=True)


# ---------------- RUN ----------------
if __name__ == "__main__":
   app.run(host="0.0.0.0", port=10000)