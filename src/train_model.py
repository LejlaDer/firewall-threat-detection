import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

print("Loading dataset...")
df = pd.read_csv('data/firewall_data.csv')

print(f"Dataset shape: {df.shape}")
print(f"Classes: {df['Action'].unique()}")

X = df.drop('Action', axis=1)
y = df['Action'].apply(lambda x: 0 if x == 'allow' else 1)

print(f"Threat distribution:\n{y.value_counts()}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("Training model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

print("Evaluating model...")
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

joblib.dump(model, 'model/model.pkl')
print("Model saved to model/model.pkl")