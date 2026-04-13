"""
Script to train and save both Decision Tree and Random Forest models
Run this script to generate the model files needed for the Flask API
"""

import pandas as pd
import numpy as np
import re
import pickle
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from urllib.parse import urlparse

def extract_features_advanced(url):
    """Extract 31 advanced features from a URL"""
    feature_lst = []

    # ============ EXISTING 11 FEATURES ============

    # 1. URL Length
    feature_lst.append(len(url))

    # 2. Count of '.'
    feature_lst.append(url.count('.'))

    # 3. Count of '/'
    feature_lst.append(url.count('/'))

    # 4. Count of '-'
    feature_lst.append(url.count('-'))

    # 5. HTTPS protocol
    feature_lst.append(1 if url.startswith('https') else 0)

    # 6. IP Address present
    ip_pattern = re.compile(r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}')
    feature_lst.append(1 if ip_pattern.search(url) else 0)

    # 7-11. Suspicious keywords
    suspicious_words = ['login', 'verify', 'update', 'secure', 'account']
    for word in suspicious_words:
        feature_lst.append(1 if word in url.lower() else 0)

    # ============ NEW 20 FEATURES ============

    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path

        # 12. Subdomain Count (parts before main domain)
        subdomain_count = domain.count('.') - 1 if '.' in domain else 0
        feature_lst.append(min(subdomain_count, 5))  # Cap at 5

        # 13. Domain Length
        feature_lst.append(len(domain))

        # 14. TLD Length (com, co.uk, etc)
        tld = domain.split('.')[-1] if '.' in domain else domain
        feature_lst.append(len(tld))

        # 15. @ Symbol present (obfuscation)
        feature_lst.append(1 if '@' in url else 0)

        # 16. Double slash position check (//)
        double_slash_pos = url.find('//')
        after_protocol = url.find('//', 6) if double_slash_pos != -1 else -1
        feature_lst.append(1 if after_protocol != -1 else 0)

        # 17. Consecutive digits (more than 3 in a row)
        consecutive_digits = 1 if re.search(r'\d{4,}', url) else 0
        feature_lst.append(consecutive_digits)

        # 18. Special characters count (&, %, $, =, etc)
        special_chars = len(re.findall(r'[&%$=]', url))
        feature_lst.append(min(special_chars, 5))  # Cap at 5

        # 19. Port number present
        feature_lst.append(1 if ':' in domain else 0)

        # 20. Redirect indicators in URL
        redirect_keywords = ['redirect', '/go/', '/go?', 'goto', 'redirecturl']
        feature_lst.append(1 if any(kw in url.lower() for kw in redirect_keywords) else 0)

        # 21. Query parameters count (? marks)
        query_param_count = url.count('?')
        feature_lst.append(min(query_param_count, 3))  # Cap at 3

        # 22. External form action (form submits elsewhere)
        form_suspicious = 1 if any(kw in url.lower() for kw in ['action=', 'formsubmit']) else 0
        feature_lst.append(form_suspicious)

        # 23. External links indicators
        external_links = url.count('http') - 1  # More than one http = redirects
        feature_lst.append(min(external_links, 3))  # Cap at 3

        # 24. Embedded object count (src=, files from different domains)
        embedded = len(re.findall(r'(src|href)=', url.lower()))
        feature_lst.append(min(embedded, 3))  # Cap at 3

        # 25. JavaScript indicators
        js_indicators = 1 if any(kw in url.lower() for kw in ['.js', 'javascript:', 'onclick']) else 0
        feature_lst.append(js_indicators)

        # 26. Suspicious TLDs (.tk, .ml, .ga, .cf - commonly abused)
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'top', 'download']
        feature_lst.append(1 if tld in suspicious_tlds else 0)

        # 27. Punycode present (internationalized domains abuse)
        feature_lst.append(1 if 'xn--' in url else 0)

        # 28. Extra slashes (more than 3)
        feature_lst.append(1 if url.count('/') > 7 else 0)

        # 29. Very long domain (phishing often uses long confusing domains)
        feature_lst.append(1 if len(domain) > 50 else 0)

        # 30. Percent encoding (%2e, %3a, etc - obfuscation)
        feature_lst.append(1 if '%' in url else 0)

        # 31. URL contains both http and https
        feature_lst.append(1 if url.count('http') > 1 else 0)

    except Exception as e:
        # If parsing fails, add zeros for all new features
        for _ in range(20):
            feature_lst.append(0)

    return feature_lst

def train_and_save_models():
    """Train both Decision Tree and Random Forest models"""

    print("Loading dataset...")
    try:
        # Load the dataset
        dataset = pd.read_csv('phishing_features.csv')
        print(f"Dataset loaded with {len(dataset)} samples")

        # Prepare X and y
        x = dataset.iloc[:, :-1].values
        y = dataset.iloc[:, -1].values

        print(f"Features shape: {x.shape}")
        print(f"Labels shape: {y.shape}")
        print(f"Number of features: {x.shape[1]}")

        # Split the data
        print("\nSplitting data (80% train, 20% test)...")
        x_train, x_test, y_train, y_test = train_test_split(
            x, y, test_size=0.2, random_state=1
        )

        # Scale the features
        print("Scaling features...")
        scaler = StandardScaler()
        x_train_scaled = scaler.fit_transform(x_train)
        x_test_scaled = scaler.transform(x_test)

        print("\n" + "="*60)
        print("TRAINING BOTH MODELS FOR COMPARISON")
        print("="*60)

        # Train Decision Tree model
        print("\n[1] Training Decision Tree Classifier...")
        dt_model = DecisionTreeClassifier(
            criterion='gini',
            max_depth=15,
            class_weight={0: 1, 1: 1.5},
            random_state=42
        )
        dt_model.fit(x_train_scaled, y_train)
        dt_pred = dt_model.predict(x_test_scaled)
        dt_accuracy = accuracy_score(y_test, dt_pred)

        print(f"\n{'='*60}")
        print(f"DECISION TREE MODEL PERFORMANCE")
        print(f"{'='*60}")
        print(f"Accuracy: {dt_accuracy:.4f} ({dt_accuracy*100:.2f}%)")
        print(f"\nClassification Report:")
        print(classification_report(y_test, dt_pred))
        print(f"Confusion Matrix:")
        print(confusion_matrix(y_test, dt_pred))

        # Train Random Forest model
        print(f"\n[2] Training Random Forest Classifier...")
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            class_weight={0: 1, 1: 1.5},
            random_state=42,
            n_jobs=-1
        )
        rf_model.fit(x_train_scaled, y_train)
        rf_pred = rf_model.predict(x_test_scaled)
        rf_accuracy = accuracy_score(y_test, rf_pred)

        print(f"\n{'='*60}")
        print(f"RANDOM FOREST MODEL PERFORMANCE")
        print(f"{'='*60}")
        print(f"Accuracy: {rf_accuracy:.4f} ({rf_accuracy*100:.2f}%)")
        print(f"\nClassification Report:")
        print(classification_report(y_test, rf_pred))
        print(f"Confusion Matrix:")
        print(confusion_matrix(y_test, rf_pred))

        # Model Comparison
        print(f"\n" + "="*60)
        print("MODEL COMPARISON")
        print("="*60)
        print(f"Decision Tree Accuracy: {dt_accuracy*100:.2f}%")
        print(f"Random Forest Accuracy: {rf_accuracy*100:.2f}%")

        if rf_accuracy > dt_accuracy:
            print(f"\n[WINNER] Random Forest is BETTER by {(rf_accuracy-dt_accuracy)*100:.2f}%")
            best_model = rf_model
            best_name = "Random Forest"
        else:
            print(f"\n[WINNER] Decision Tree is BETTER by {(dt_accuracy-rf_accuracy)*100:.2f}%")
            best_model = dt_model
            best_name = "Decision Tree"

        # Save both models
        print(f"\n" + "="*60)
        print("SAVING MODELS")
        print("="*60)

        with open('phishing_model.pkl', 'wb') as f:
            pickle.dump(best_model, f)
        print(f"SAVED: Best model ({best_name}) as 'phishing_model.pkl'")

        with open('scaler.pkl', 'wb') as f:
            pickle.dump(scaler, f)
        print("SAVED: Scaler as 'scaler.pkl'")

        # Save both for comparison
        with open('decision_tree_model.pkl', 'wb') as f:
            pickle.dump(dt_model, f)
        print("SAVED: Decision Tree (backup) as 'decision_tree_model.pkl'")

        with open('random_forest_model.pkl', 'wb') as f:
            pickle.dump(rf_model, f)
        print("SAVED: Random Forest (backup) as 'random_forest_model.pkl'")

        print(f"\n{'='*60}")
        print("MODEL TRAINING COMPLETED!")
        print(f"{'='*60}")
        print(f"\nSummary:")
        print(f"  - Features: {x.shape[1]}")
        print(f"  - Samples: {len(dataset)}")
        print(f"  - Best Model: {best_name} ({best_model.__class__.__name__})")
        print(f"  - Best Accuracy: {max(dt_accuracy, rf_accuracy)*100:.2f}%")
        print(f"\nYou can now run the Flask API with: python app.py")

    except FileNotFoundError:
        print("Error: phishing_features.csv not found!")
        print("Please make sure the dataset file exists.")
    except Exception as e:
        print(f"Error during training: {e}")
        raise

if __name__ == '__main__':
    train_and_save_models()
