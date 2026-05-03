import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

print("Loading dataset...")
df = pd.read_csv('data/firewall_data.csv')
print(f"Dataset shape: {df.shape}")
print(f"Columns: {list(df.columns)}")

# ── Data Analysis ──────────────────────────────────────────────
print("\n── Class Distribution (before encoding) ──")
print(df['Action'].value_counts())

print("\n── Missing Values ──")
print(df.isnull().sum())

# ── Feature Selection ──────────────────────────────────────────
# UFW logs only record individual packets, not full sessions.
# Session-level features (Bytes, Packets, Elapsed Time...)
# are not available in UFW log format and are excluded.
# Only Source Port and Destination Port are consistently present
# in every UFW log entry and are retained for model training.

SELECTED_FEATURES = ['Source Port', 'Destination Port']

print(f"\n── Feature Selection ──")
print(f"Total features in dataset : {len(df.columns) - 1}")
print(f"Features retained         : {SELECTED_FEATURES}")
print(f"Features dropped          : {[c for c in df.columns if c not in SELECTED_FEATURES + ['Action']]}")
print(f"Reason                    : Session-level metrics unavailable in UFW packet-level logs")

X = df[SELECTED_FEATURES]
y = df['Action'].apply(lambda x: 0 if x == 'allow' else 1)

print(f"\n── Label Encoding ──")
print(f"  0 = benign  (allow)")
print(f"  1 = threat  (drop / deny / reset-both)")
print(f"\n── Threat Distribution After Encoding ──")
print(y.value_counts())
print(f"  Threat ratio: {y.mean():.2%}")

print(f"\n── Port Range Analysis ──")
print(f"Source Port  — min: {X['Source Port'].min()}, max: {X['Source Port'].max()}, mean: {X['Source Port'].mean():.1f}")
print(f"Dest Port    — min: {X['Destination Port'].min()}, max: {X['Destination Port'].max()}, mean: {X['Destination Port'].mean():.1f}")

# ── Train / Test Split ─────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
print(f"\n── Train/Test Split ──")
print(f"  Training samples : {len(X_train)}")
print(f"  Test samples     : {len(X_test)}")

# ── Model Training ─────────────────────────────────────────────
print("\nTraining Random Forest model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ── Evaluation ─────────────────────────────────────────────────
print("\n── Classification Report ──")
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred, target_names=['benign', 'threat']))

print("\n── Confusion Matrix ──")
cm = confusion_matrix(y_test, y_pred)
print(f"  TN={cm[0,0]}  FP={cm[0,1]}")
print(f"  FN={cm[1,0]}  TP={cm[1,1]}")

# Feature importance
print("\n── Feature Importance ──")
importance = pd.DataFrame({
    'feature': SELECTED_FEATURES,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)
print(importance)

# Save model
joblib.dump(model, 'model/model.pkl')
print("\n✅ Model saved to model/model.pkl")