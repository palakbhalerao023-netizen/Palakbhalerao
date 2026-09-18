import pandas as pd
import re
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, ConfusionMatrixDisplay


# Load dataset
data = pd.read_csv("emails.csv")

# Remove empty values
data = data.dropna(subset=["text", "label"])

# Convert labels
data["label"] = data["label"].map({
    "safe": 0,
    "legitimate": 0,
    "phishing": 1,
    "spam": 1
})

data = data.dropna(subset=["label"])

# --------------------------------------------------
# URL feature extraction
# --------------------------------------------------

def url_features(text):
    text = str(text)

    urls = re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        text.lower()
    )

    url_count = len(urls)

    ip_urls = sum(
        bool(re.search(
            r"https?://(?:\d{1,3}\.){3}\d{1,3}",
            url
        ))
        for url in urls
    )

    suspicious_words = [
        "urgent",
        "verify",
        "password",
        "login",
        "account",
        "suspended",
        "bank",
        "click",
        "security"
    ]

    suspicious_count = sum(
        word in text.lower()
        for word in suspicious_words
    )

    return url_count, ip_urls, suspicious_count


# Extract URL features
features = data["text"].apply(url_features)

data["url_count"] = features.apply(lambda x: x[0])
data["ip_url_count"] = features.apply(lambda x: x[1])
data["suspicious_words"] = features.apply(lambda x: x[2])


# --------------------------------------------------
# Split data
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    data["text"],
    data["label"],
    test_size=0.2,
    random_state=42,
    stratify=data["label"]
)


# --------------------------------------------------
# TF-IDF text processing
# --------------------------------------------------

vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    ngram_range=(1, 2),
    max_features=10000
)

X_train = vectorizer.fit_transform(X_train)
X_test = vectorizer.transform(X_test)


# --------------------------------------------------
# Train model
# --------------------------------------------------

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced"
)

model.fit(X_train, y_train)


# --------------------------------------------------
# Test model
# --------------------------------------------------

prediction = model.predict(X_test)

accuracy = accuracy_score(y_test, prediction)

print("\n===== PHISHING EMAIL DETECTOR =====")
print(f"Accuracy: {accuracy * 100:.2f}%")

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, prediction)
print(cm)


# Display confusion matrix
disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["Safe", "Phishing"]
)

disp.plot(cmap="Blues")
plt.title("Phishing Email Detection")
plt.show()


# --------------------------------------------------
# Predict a new email
# --------------------------------------------------

def check_email(email):
    email_vector = vectorizer.transform([email])

    result = model.predict(email_vector)[0]
    probability = model.predict_proba(email_vector)[0][1]

    print("\n===== EMAIL RESULT =====")

    if result == 1:
        print("Prediction: PHISHING")
    else:
        print("Prediction: SAFE")

    print(f"Phishing Probability: {probability * 100:.2f}%")


# Example email
email = """
URGENT! Your bank account has been suspended.
Click https://example.com/login to verify your password.
"""

check_email(email)
