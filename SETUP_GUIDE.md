# Phishing Detection System - Setup Guide

This guide will help you connect your ML model to the frontend interface.

## Architecture Overview

```
Frontend (PHISHING.HTML) 
    ↓
Flask API (app.py) on port 5000
    ↓
Decision Tree ML Model (phishing_model.pkl)
```

## Step 1: Prepare the Dataset Features

First, you need to extract features from the URLs in your dataset using the Jupyter notebook:

1. Open `phishing_ml_training.ipynb`
2. Run all cells from the beginning up to the **Feature Extraction** section
3. This will generate `phishing_features.csv` in the Backend folder

## Step 2: Install Backend Dependencies

Open a terminal in the `Backend` folder and run:

```bash
pip install -r requirements.txt
```

This installs:
- Flask (web framework)
- Flask-CORS (for frontend-backend communication)
- pandas & numpy (data processing)
- scikit-learn (ML models)

## Step 3: Train and Save the Model

Run the training script to create the Decision Tree model:

```bash
python train_model.py
```

This will:
- Load the features from `phishing_features.csv`
- Train the Decision Tree model
- Show performance metrics
- Save `phishing_model.pkl` and `scaler.pkl`

**Output files created:**
- `phishing_model.pkl` - The trained Decision Tree model
- `scaler.pkl` - Feature scaler for preprocessing

## Step 4: Start the Flask Backend Server

```bash
python app.py
```

You should see:
```
WARNING in app.run() * Running on http://localhost:5000
 * Debug mode: on
```

Keep this terminal open while testing.

## Step 5: Test the Frontend

1. Open a web browser
2. Navigate to `Frontend/public/index.html`
3. Click on "Phishing Detection" button
4. Enter a URL and click "Check"

## API Endpoints

### Check Phishing
**Endpoint:** `POST http://localhost:5000/api/check-phishing`

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response (Safe):**
```json
{
  "success": true,
  "url": "https://example.com",
  "is_phishing": false,
  "confidence": 92.45,
  "phishing_probability": 7.55,
  "legitimate_probability": 92.45,
  "message": "Website appears to be safe."
}
```

**Response (Phishing):**
```json
{
  "success": true,
  "url": "https://phishing-site.com",
  "is_phishing": true,
  "confidence": 88.90,
  "phishing_probability": 88.90,
  "legitimate_probability": 11.10,
  "message": "Phishing detected! Be cautious."
}
```

### Health Check
**Endpoint:** `GET http://localhost:5000/api/health`

Check if the API and model are loaded:
```json
{
  "status": "running",
  "model_status": "loaded",
  "scaler_status": "loaded"
}
```

## Troubleshooting

### "Connection Error" on Frontend
- Make sure Flask server is running: `python app.py`
- Check that port 5000 is not in use
- Ensure CORS is enabled (it's in the Flask app)

### "phishing_features.csv not found"
- Run the feature extraction cells in the Jupyter notebook first
- Make sure you're in the Backend folder when running `train_model.py`

### Model "not loaded" error
- Check that `phishing_model.pkl` and `scaler.pkl` exist in Backend folder
- Run `python train_model.py` to regenerate them

### Port 5000 already in use
Change the port in `app.py`:
```python
app.run(debug=True, host='localhost', port=8000)  # Use 8000 instead
```
Then update the frontend URL in PHISHING.html:
```javascript
const API_BASE_URL = 'http://localhost:8000';
```

## File Structure

```
Backend/
  ├── app.py                          # Flask API server
  ├── train_model.py                  # Model training script
  ├── requirements.txt                # Python dependencies
  ├── phishing_ml_training.ipynb      # Training notebook
  ├── phishing_features.csv           # Feature data (generated)
  ├── phishing_model.pkl              # Trained model (generated)
  ├── scaler.pkl                      # Feature scaler (generated)
  └── dataset/
      ├── final_dataset.csv
      └── ...

Frontend/
  └── public/
      ├── index.html                  # Home page
      ├── PHISHING.HTML               # Detection page
      └── ...
```

## Quick Start (One-time Setup)

```bash
# 1. Install dependencies
pip install -r Backend/requirements.txt

# 2. Extract features from notebook (run notebook cells)
# Then train the model
cd Backend
python train_model.py

# 3. Start the server
python app.py

# 4. Open frontend in browser
# Navigate to Frontend/public/index.html
```

## Features Extracted from URLs

1. **url_length** - Total length of the URL
2. **num_dots** - Count of '.' characters
3. **num_slashes** - Count of '/' characters  
4. **num_hyphens** - Count of '-' characters
5. **has_https** - 1 if URL starts with 'https', 0 otherwise
6. **has_ip** - 1 if IP address detected in URL, 0 otherwise
7. **kw_login** - 1 if 'login' keyword found, 0 otherwise
8. **kw_verify** - 1 if 'verify' keyword found, 0 otherwise
9. **kw_update** - 1 if 'update' keyword found, 0 otherwise
10. **kw_secure** - 1 if 'secure' keyword found, 0 otherwise
11. **kw_account** - 1 if 'account' keyword found, 0 otherwise

## Next Steps

- Test with various URLs
- Monitor API logs for requests
- Improve model accuracy by adding more training data
- Deploy to production using Gunicorn or similar
