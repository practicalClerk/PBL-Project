"""
Extract 31 advanced features from phishing_dataset_final.csv
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
        # Add http:// if missing for proper parsing
        parsed_url = url if url.startswith(('http://', 'https://')) else 'http://' + url
        parsed = urlparse(parsed_url)
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

    except Exception as e:
        # If parsing fails, add zeros for new features
        for _ in range(20):
            feature_lst.append(0)

    return feature_lst


def extract_dataset():
    """Extract 31 features from all URLs in phishing_dataset_final.csv"""

    print("Loading phishing_dataset_final.csv...")
    df = pd.read_csv('phishing_dataset_final.csv')
    print(f"Loaded {len(df)} URLs\n")

    print("Extracting 31 features from each URL...")
    features = []

    for idx, row in df.iterrows():
        url = str(row['url']).strip()
        label = row['label']

        # Extract features
        feature_vector = extract_features_advanced(url)
        feature_vector.append(label)  # Add label at the end
        features.append(feature_vector)

        if (idx + 1) % 1000 == 0:
            print(f"  Processed {idx + 1}/{len(df)} URLs")

    print(f"\nProcessed all {len(df)} URLs")

    # Create column names
    feature_names = [
        'url_length', 'num_dots', 'num_slashes', 'num_hyphens',
        'has_https', 'has_ip', 'kw_login', 'kw_verify', 'kw_update',
        'kw_secure', 'kw_account',
        'subdomain_count', 'domain_length', 'tld_length', 'has_at_symbol',
        'double_slash', 'consecutive_digits', 'special_chars_count',
        'has_port', 'redirect_indicator', 'query_params_count',
        'form_action', 'external_links', 'embedded_objects',
        'javascript_indicators', 'suspicious_tld', 'punycode_present',
        'extra_slashes', 'long_domain', 'percent_encoding',
        'mixed_http_https', 'label'
    ]

    # Create DataFrame
    features_df = pd.DataFrame(features, columns=feature_names)

    # Save to CSV
    output_file = 'phishing_features.csv'
    features_df.to_csv(output_file, index=False)

    print(f"\n{'='*60}")
    print("DATASET EXTRACTION COMPLETE!")
    print(f"{'='*60}")
    print(f"Output: {output_file}")
    print(f"Shape: {features_df.shape}")
    print(f"Features: {features_df.shape[1] - 1} (excluding label)")
    print(f"\nFirst 5 rows:")
    print(features_df.head())
    print(f"\nDataset split:")
    print(f"  Legitimate URLs (0): {(features_df['label'] == 0).sum()}")
    print(f"  Phishing URLs (1): {(features_df['label'] == 1).sum()}")

    return features_df


if __name__ == '__main__':
    extract_dataset()
