import joblib
import pandas as pd

# Load trained model
model = joblib.load("threat_detection_model.pkl")

print("AI Threat Detection System")

# User input
login_hour = int(input("Enter login hour (0-23): "))
failed_attempts = int(input("Failed login attempts: "))
files_accessed = int(input("Files accessed: "))

# Feature engineering
late_login = 1 if login_hour < 6 else 0
high_failed = 1 if failed_attempts > 3 else 0
high_file_access = 1 if files_accessed > 100 else 0

# Create dataframe with correct feature names
features = pd.DataFrame([[late_login, high_failed, high_file_access]],
columns=['late_login','high_failed','high_file_access'])

prediction = model.predict(features)

if prediction[0] == -1:
    print("⚠ Suspicious Login Detected")
else:
    print("✔ Normal Login")