from faker import Faker
import pandas as pd
import random

fake = Faker()

data = []

for i in range(1200):

    user = f"user_{random.randint(1,100)}"
    login_hour = random.randint(0,23)
    location = fake.country()
    device = random.choice(["Laptop","Mobile","Desktop"])
    failed_attempts = random.randint(0,5)
    files_accessed = random.randint(1,200)

    data.append([user,login_hour,location,
                 device,failed_attempts,files_accessed])

df = pd.DataFrame(data, columns=[
"user_id","login_hour","location",
"device","failed_attempts","files_accessed"
])

df.to_csv("logs.csv", index=False)

print("Dataset Generated Successfully!")
