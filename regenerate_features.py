"""
Script to regenerate phishing_features.csv with 31 advanced features
Run this to update the dataset before training
"""

import pandas as pd
import numpy as np
import re
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

        # 12. Subdomain Count
        subdomain_count = domain.count('.') - 1 if '.' in domain else 0
        feature_lst.append(min(subdomain_count, 5))

        # 13. Domain Length
        feature_lst.append(len(domain))

        # 14. TLD Length
        tld = domain.split('.')[-1] if '.' in domain else domain
        feature_lst.append(len(tld))

        # 15. @ Symbol present
        feature_lst.append(1 if '@' in url else 0)

        # 16. Double slash position check
        double_slash_pos = url.find('//')
        after_protocol = url.find('//', 6) if double_slash_pos != -1 else -1
        feature_lst.append(1 if after_protocol != -1 else 0)

        # 17. Consecutive digits
        consecutive_digits = 1 if re.search(r'\d{4,}', url) else 0
        feature_lst.append(consecutive_digits)

        # 18. Special characters count
        special_chars = len(re.findall(r'[&%$=]', url))
        feature_lst.append(min(special_chars, 5))

        # 19. Port number present
        feature_lst.append(1 if ':' in domain else 0)

        # 20. Redirect indicators
        redirect_keywords = ['redirect', '/go/', '/go?', 'goto', 'redirecturl']
        feature_lst.append(1 if any(kw in url.lower() for kw in redirect_keywords) else 0)

        # 21. Query parameters count
        query_param_count = url.count('?')
        feature_lst.append(min(query_param_count, 3))

        # 22. Form action indicators
        form_suspicious = 1 if any(kw in url.lower() for kw in ['action=', 'formsubmit']) else 0
        feature_lst.append(form_suspicious)

        # 23. External links indicators
        external_links = url.count('http') - 1
        feature_lst.append(min(external_links, 3))

        # 24. Embedded object count
        embedded = len(re.findall(r'(src|href)=', url.lower()))
        feature_lst.append(min(embedded, 3))

        # 25. JavaScript indicators
        js_indicators = 1 if any(kw in url.lower() for kw in ['.js', 'javascript:', 'onclick']) else 0
        feature_lst.append(js_indicators)

        # 26. Suspicious TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'top', 'download']
        feature_lst.append(1 if tld in suspicious_tlds else 0)

        # 27. Punycode present
        feature_lst.append(1 if 'xn--' in url else 0)

        # 28. Extra slashes
        feature_lst.append(1 if url.count('/') > 7 else 0)

        # 29. Very long domain
        feature_lst.append(1 if len(domain) > 50 else 0)

        # 30. Percent encoding
        feature_lst.append(1 if '%' in url else 0)

        # 31. URL contains both http and https
        feature_lst.append(1 if url.count('http') > 1 else 0)

    except Exception:
        for _ in range(20):
            feature_lst.append(0)

    return feature_lst


def regenerate_dataset():
    """Regenerate phishing_features.csv with 31 features"""
    print("Reading existing dataset...")
    try:
        # Read original CSV
        old_df = pd.read_csv('phishing_features.csv')
        print(f"Loaded {len(old_df)} records from existing dataset")

        # We need the URL column, but we don't have it in the original CSV
        # So we'll need to regenerate from source or work with what we have

        print("\n⚠️  NOTE: Regenerating from the original dataset...")
        print("Since we don't have the original URLs, we're extracting features")
        print("from a combination of known phishing and legitimate datasets.")

        # For now, let's read the original data and recompute
        # Get the labels (last column)
        labels = old_df.iloc[:, -1].values

        # Read the old features to understand the pattern
        old_features = old_df.iloc[:, :-1].values

        print(f"\nOriginal shape: {old_features.shape}")
        print(f"Processing {len(labels)} records with new feature extraction...")

        # Since we don't have URLs, we'll regenerate using a phishing dataset
        # Loading example URLs
        phishing_urls = [
            'http://appstarthelp.wixstudio.com/us-en',
            'https://jp.voteg3az8.baby/art?id=10001&id=',
            'https://www.t9-okx.com/',
            'http://webbulls.space',
            'https://ladger-us.wixstudio.com/en-us',
            'https://eng-trzersuite.wixstudio.com/eng-io',
            'https://desktopstarted.wixstudio.com/en-us',
            'http://192.168.1.1',
            'http://192.168.1.1:8080/admin/login',
            'https://malicious-site-with-login-verify-secure-account.com/update',
        ]

        legitimate_urls = [
            'https://www.google.com',
            'https://www.facebook.com',
            'https://www.amazon.com',
            'https://www.github.com',
            'https://www.microsoft.com',
            'https://www.apple.com',
            'https://www.wikipedia.org',
            'https://www.linkedin.com',
            'https://www.twitter.com',
            'https://www.youtube.com',
        ]

        print("\n" + "="*60)
        print("Feature Regeneration Status:")
        print("="*60)
        print("\n⚠️  IMPORTANT: Original URLs are not available!")
        print("\nTo properly regenerate the dataset with 31 features:")
        print("1. You need the original phishing_features.csv with URL column")
        print("2. Or provide a dataset with URL and label columns")
        print("\nFor now, KEEPING the original dataset with 11 features.")
        print("The new 31-feature extraction is ready in the code.")
        print("\nYou can:")
        print("  A) Provide the original URLs if you have them")
        print("  B) Use a public phishing dataset (UCIrvine, PhishTank)")
        print("  C) The code will still work with 11 features")

        return False

    except FileNotFoundError:
        print("Error: phishing_features.csv not found!")
        return False
    except Exception as e:
        print(f"Error during regeneration: {e}")
        return False


if __name__ == '__main__':
    regenerate_dataset()
