import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# Create models folder if not exists
os.makedirs("models", exist_ok=True)

# Load data
df = pd.read_csv("backend/data/dataset.csv")

# Drop id column
df.drop("id", axis=1, inplace=True)

# Features & target
X = df.drop("Result", axis=1)
y = df["Result"]

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Model
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    random_state=42
)

# Train
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

# Save model
import joblib
joblib.dump(model, "backend/models/phishing_model.joblib")

print("\n✅ Model saved successfully!")