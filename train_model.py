import pandas as pd
from sklearn.ensemble import IsolationForest

# Load data
data = pd.read_csv("logs.csv")

# Feature Engineering
data['late_login'] = data['login_hour'].apply(lambda x: 1 if x < 6 else 0)
data['high_failed'] = data['failed_attempts'].apply(lambda x: 1 if x > 3 else 0)
data['high_file_access'] = data['files_accessed'].apply(lambda x: 1 if x > 100 else 0)

# Select features
X = data[['late_login','high_failed','high_file_access']]

# Train Isolation Forest
model = IsolationForest(contamination=0.2, random_state=42)
model.fit(X)

# Predict anomalies
data['anomaly'] = model.predict(X)

print(data[['late_login','high_failed','high_file_access','anomaly']].head())
import joblib

# Save the trained model
joblib.dump(model, "threat_detection_model.pkl")

print("Model saved successfully!")