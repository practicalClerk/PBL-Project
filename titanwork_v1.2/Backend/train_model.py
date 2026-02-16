"""
Script to train and save the Decision Tree model
Run this script to generate the model files needed for the Flask API
"""

import pandas as pd
import numpy as np
import re
import pickle
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

def extract_features(url):
    """Extract features from a URL"""
    feature_lst = []
    
    # 1. URL Length
    feature_lst.append(len(url))
    
    # 2. Count of '.'
    feature_lst.append(url.count('.'))
    
    # 3. Count of '/'
    feature_lst.append(url.count('/'))
    
    # 4. Count of '-'
    feature_lst.append(url.count('-'))
    
    # 5. Check whether 'https' is present
    feature_lst.append(1 if url.startswith('https') else 0)
    
    # 6. Check whether IP Address is present
    ip_pattern = re.compile(
        r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}'
    )
    feature_lst.append(1 if ip_pattern.search(url) else 0)
    
    # 7-11. Check suspicious keywords
    suspicious_words = ['login', 'verify', 'update', 'secure', 'account']
    for word in suspicious_words:
        feature_lst.append(1 if word in url.lower() else 0)
    
    return feature_lst

def train_and_save_model():
    """Train the Decision Tree model and save it along with the scaler"""
    
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
        
        # Train Decision Tree model
        print("Training Decision Tree model...")
        dt_model = DecisionTreeClassifier(
            criterion='gini',
            max_depth=10,
            class_weight={0: 1, 1: 1.5},
            random_state=42
        )
        dt_model.fit(x_train_scaled, y_train)
        
        # Make predictions
        y_pred = dt_model.predict(x_test_scaled)
        
        # Evaluate model
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\n{'='*50}")
        print(f"Decision Tree Model Performance")
        print(f"{'='*50}")
        print(f"Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"\nClassification Report:")
        print(classification_report(y_test, y_pred))
        print(f"Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        
        # Save the model
        print(f"\nSaving model and scaler...")
        with open('phishing_model.pkl', 'wb') as f:
            pickle.dump(dt_model, f)
        print("✓ Model saved as 'phishing_model.pkl'")
        
        # Save the scaler
        with open('scaler.pkl', 'wb') as f:
            pickle.dump(scaler, f)
        print("✓ Scaler saved as 'scaler.pkl'")
        
        print(f"\n{'='*50}")
        print("Model training and saving completed successfully!")
        print(f"{'='*50}")
        print("\nYou can now run the Flask API with: python app.py")
        
    except FileNotFoundError:
        print("Error: phishing_features.csv not found!")
        print("Please make sure to run the feature extraction from the notebook first.")
    except Exception as e:
        print(f"Error during training: {e}")
        raise

if __name__ == '__main__':
    train_and_save_model()
