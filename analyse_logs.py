import pandas as pd

# Load dataset
data = pd.read_csv("logs.csv")

# Show first 5 rows
print("First 5 rows:")
print(data.head())

# Show dataset info
print("\nDataset Info:")
print(data.info())

# Show basic statistics
print("\nStatistics:")
print(data.describe())