"""
MOCK / SYNTHETIC DEMO DATA — NOT A REAL TRAINING DATASET.

This script generates a small, clearly-labeled synthetic set of URLs so the
ML pipeline (feature extraction -> training -> evaluation -> serialization)
can be run and verified end-to-end in this development environment, which
does not have network access to download PhishTank/UCI/Mendeley data.

DO NOT use this synthetic data to report real accuracy/precision/recall
figures in the project report or viva — those numbers must come from
training on an actual downloaded dataset (see
docs/dataset_setup.md / the requirements specification for sources).

Run this only to sanity-check that the pipeline code works, then replace
its output with real downloaded data before running real experiments.
"""
import csv
import random
from pathlib import Path

OUTPUT_PATH = Path(__file__).parent / "sample_mock_dataset.csv"

LEGIT_DOMAINS = [
    "google.com", "wikipedia.org", "github.com", "amazon.com", "apple.com",
    "microsoft.com", "nytimes.com", "bbc.co.uk", "stackoverflow.com", "reddit.com",
    "linkedin.com", "netflix.com", "spotify.com", "dropbox.com", "adobe.com",
]

PHISHING_PATTERNS = [
    "paypa1-login-security.com/verify",
    "micr0soft-account-update.net/signin",
    "amaz0n-security-alert.com/confirm",
    "faceb00k-authentication.info/login",
    "apple-id-verify-account.com/secure",
    "netflix-billing-update.net/account",
    "chase-secure-login.info/verify?user=1",
    "linkedin-account-security.net/confirm",
    "wellsfargo-alert-verify.com/login",
    "outlook-account-update.info/signin",
]

random.seed(42)  # reproducibility, per project requirements


def generate_mock_row(is_phishing: bool) -> dict:
    if is_phishing:
        base = random.choice(PHISHING_PATTERNS)
        url = f"http://{base}"
        label = 1
    else:
        base = random.choice(LEGIT_DOMAINS)
        path = random.choice(["", "/about", "/products", "/help", "/search?q=test"])
        url = f"https://www.{base}{path}"
        label = 0
    return {"url": url, "label": label}


def main():
    rows = [generate_mock_row(is_phishing=bool(i % 2)) for i in range(200)]
    random.shuffle(rows)

    with open(OUTPUT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} MOCK rows to {OUTPUT_PATH}")
    print("Reminder: this is synthetic demo data only. Replace with a real")
    print("dataset before running actual experiments for your report.")


if __name__ == "__main__":
    main()
