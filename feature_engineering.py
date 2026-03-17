import pandas as pd

# Load dataset
data = pd.read_csv("logs.csv")

# Create Late Login feature
data['late_login'] = data['login_hour'].apply(lambda x: 1 if x < 6 else 0)

# Create High Failed Attempts feature
data['high_failed'] = data['failed_attempts'].apply(lambda x: 1 if x > 3 else 0)

# Create High File Access feature
data['high_file_access'] = data['files_accessed'].apply(lambda x: 1 if x > 100 else 0)

# Select only ML features
features = data[['late_login','high_failed','high_file_access']]

print(features.head())