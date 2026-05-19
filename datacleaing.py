import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split

data_dir = "path/to/dataset_folder"
fname = "your_file.csv"

df = pd.read_csv(os.path.join(data_dir, fname))
print("Initial shape:", df.shape)
print(df.head())
print(df.info())
print(df.describe(include='all'))

print("Columns:", df.columns.tolist())
print("Missing values per column:")
print(df.isna().sum().sort_values(ascending=False).head(20))

label_col = "Label"
if label_col in df.columns:
    print("Class counts:")
    print(df[label_col].value_counts())

before = df.shape[0]
df = df.drop_duplicates()
after = df.shape[0]
print(f"Dropped {before-after} duplicate rows")

threshold = 0.5
na_frac = df.isna().mean()
cols_to_drop = na_frac[na_frac > threshold].index.tolist()
print("Dropping columns with >50% missing:", cols_to_drop)
df = df.drop(columns=cols_to_drop)

if label_col in df.columns:
    df = df[~df[label_col].isna()]

numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
categorical_cols = df.select_dtypes(include=['object', 'category']).columns.tolist()

print("Numeric cols:", numeric_cols[:10], "…")
print("Categorical cols:", categorical_cols[:10], "…")

for col in numeric_cols:
    if df[col].isna().any():
        df[col].fillna(df[col].mean(), inplace=True)

for col in categorical_cols:
    if df[col].isna().any():
        df[col].fillna(df[col].mode()[0], inplace=True)

print("Missing values after imputation:")
print(df.isna().sum().sum())

label_encoders = {}
for col in categorical_cols:
    if col == label_col:
        continue
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    label_encoders[col] = le

scaler = StandardScaler()
df[numeric_cols] = scaler.fit_transform(df[numeric_cols])

if label_col in df.columns:
    X = df.drop(columns=[label_col])
    y = df[label_col]
else:
    X = df.copy()
    y = None

if y is not None:
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    print("Train shape:", X_train.shape, y_train.shape)
    print("Test shape :", X_test.shape, y_test.shape)
else:
    X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)
    print("Train shape:", X_train.shape)
    print("Test shape :", X_test.shape)

plt.figure(figsize=(10,6))
if label_col in df.columns:
    sns.countplot(data=df, x=label_col)
    plt.title("Class distribution")
    plt.show()

plt.figure(figsize=(12,10))
corr = df[numeric_cols].corr()
sns.heatmap(corr, cmap="coolwarm", vmax=0.8, square=True)
plt.title("Correlation matrix")
plt.show()

cleaned_path = os.path.join(data_dir, "cleaned_iot_dataset.csv")
df.to_csv(cleaned_path, index=False)
print(f"Cleaned dataset saved to {cleaned_path}")
