import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load dataset
df = pd.read_csv("data/dataset.csv")

# Drop id column
df.drop("id", axis=1, inplace=True)

print("Shape:", df.shape)
print("\nClass Distribution:\n", df["Result"].value_counts())
print("\nMissing Values:\n", df.isnull().sum())

# Correlation Heatmap
plt.figure(figsize=(15,12))
sns.heatmap(df.corr(), cmap="coolwarm")
plt.title("Feature Correlation Heatmap")
plt.show()

# Class distribution plot
sns.countplot(x="Result", data=df)
plt.title("Phishing vs Legitimate Distribution")
plt.show()