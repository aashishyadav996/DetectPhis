"""
Baseline phishing-URL classifier training pipeline.

Usage:
    python -m app.ml_pipeline.train --data path/to/dataset.csv

Expects a CSV with columns: url, label (1 = phishing, 0 = legitimate).

Pipeline: load -> feature extraction -> train/test split -> train
(Logistic Regression baseline + Random Forest comparison) -> evaluate ->
serialize the better-performing model to app/modules/ml/model.joblib.

Logistic Regression and Random Forest were chosen over deep learning or
gradient boosting because: the expected dataset size for a BCA project
(hundreds to low tens-of-thousands of rows) does not benefit from a deep
model, both remain interpretable (coefficients / feature importances feed
directly into the explainability requirement), and both train in seconds
on ordinary hardware. This choice should be justified the same way in
the project report — not asserted without reasoning.

IMPORTANT: whatever CSV you pass in, the printed metrics ARE the real
results of that run — nothing here fabricates numbers. If you run this
on the mock dataset (generate_mock_dataset.py), the results reflect that
mock data's easy/artificial patterns and are NOT valid experimental
results for your report.
"""
import argparse
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Allow running as `python -m app.ml_pipeline.train` from the backend/ dir.
sys.path.append(str(Path(__file__).resolve().parents[2]))

from app.core.url_safety import normalize_url, InvalidURLError
from app.modules.url_features.extractor import extract_features

MODEL_OUTPUT_PATH = Path(__file__).resolve().parents[1] / "modules" / "ml" / "model.joblib"

NUMERIC_FEATURE_COLUMNS = [
    "url_length", "num_dots", "num_hyphens", "num_digits", "num_subdomains",
    "has_at_symbol", "has_ip_address_host", "is_https", "uses_url_shortener",
    "suspicious_keyword_count",
]


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    dropped = 0
    for url in df["url"]:
        try:
            normalized = normalize_url(url)
            feats = extract_features(normalized).to_dict()
            rows.append({col: feats[col] for col in NUMERIC_FEATURE_COLUMNS})
        except InvalidURLError:
            dropped += 1
            rows.append({col: None for col in NUMERIC_FEATURE_COLUMNS})

    if dropped:
        print(f"Warning: {dropped} row(s) had invalid URLs and were excluded.")

    feature_df = pd.DataFrame(rows)
    for col in ["has_at_symbol", "has_ip_address_host", "is_https", "uses_url_shortener"]:
        feature_df[col] = feature_df[col].astype(float)
    return feature_df


def evaluate(name: str, model, X_test, y_test) -> dict:
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None

    metrics = {
        "model": name,
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "f1": f1_score(y_test, y_pred, zero_division=0),
    }
    if y_proba is not None and len(set(y_test)) > 1:
        metrics["roc_auc"] = roc_auc_score(y_test, y_proba)

    print(f"\n--- {name} ---")
    for k, v in metrics.items():
        if k != "model":
            print(f"  {k}: {v:.4f}")
    print("  Confusion matrix:\n", confusion_matrix(y_test, y_pred))
    print("  Classification report:\n", classification_report(y_test, y_pred, zero_division=0))

    return metrics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="Path to CSV with columns: url,label")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    df = pd.read_csv(args.data)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset CSV must have 'url' and 'label' columns.")

    print(f"Loaded {len(df)} rows from {args.data}")
    print(f"Label distribution:\n{df['label'].value_counts()}")

    X = build_feature_matrix(df)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    log_reg = LogisticRegression(max_iter=1000, random_state=args.random_state)
    log_reg.fit(X_train_scaled, y_train)
    log_reg_metrics = evaluate("Logistic Regression", log_reg, X_test_scaled, y_test)

    rf = RandomForestClassifier(n_estimators=200, random_state=args.random_state)
    rf.fit(X_train, y_train)  # tree-based models don't need scaling
    rf_metrics = evaluate("Random Forest", rf, X_test, y_test)

    # Select by F1 (balances precision/recall, appropriate for a security
    # detection task where both false positives and false negatives matter).
    if rf_metrics["f1"] >= log_reg_metrics["f1"]:
        chosen_model, chosen_name, needs_scaler = rf, "Random Forest", False
    else:
        chosen_model, chosen_name, needs_scaler = log_reg, "Logistic Regression", True

    print(f"\nSelected model: {chosen_name} (higher F1 on this run's test split)")

    MODEL_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": chosen_model,
        "model_name": chosen_name,
        "needs_scaler": needs_scaler,
        "scaler": scaler if needs_scaler else None,
        "feature_columns": NUMERIC_FEATURE_COLUMNS,
    }, MODEL_OUTPUT_PATH)

    print(f"Model serialized to {MODEL_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
