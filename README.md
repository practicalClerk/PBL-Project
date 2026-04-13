# PBL Project Backend - Phishing Detection Web App

This repository contains a Flask-based phishing detection system that combines:
- Machine learning (Decision Tree / Random Forest trained on URL features)
- Rule-based phishing heuristics (domain squatting, suspicious TLDs, URL patterns)
- Optional LLM analysis via Ollama for human-readable security assessment
- Web UI pages served directly by Flask

The app serves both frontend pages and JSON APIs from one service.

## What This Project Does

Given a URL, the backend computes 31 engineered features and evaluates risk using a weighted ensemble:
- ML model contribution: 40%
- Rule engine contribution: 10%
- LLM contribution: 50% (if unavailable, neutral fallback is used)

It returns:
- Final phishing verdict
- Confidence score
- Model-level details
- Rule-based flags
- LLM assessment, findings, and recommendations (when enabled)

## Tech Stack

- Python 3.10+
- Flask, Flask-CORS
- pandas, numpy
- scikit-learn
- requests
- gunicorn (production)

## Repository Structure

```
Backend/
├── app.py                         # Main Flask app (pages + API)
├── train_model.py                 # Train and save models + scaler
├── combine_and_extract.py         # Build balanced feature dataset from legit+phishing URLs
├── extract_features_from_urls.py  # Extract 31 features (phishing dataset workflow)
├── regenerate_features.py         # Legacy/experimental feature regeneration helper
├── requirements.txt               # Python dependencies
├── Dockerfile                     # Docker image build and runtime
├── run.bat                        # Windows quick-run script (checks model files, starts app)
├── start.bat                      # Alternate Windows startup flow
├── phishing_features.csv          # Feature dataset used for training
├── legitimate_dataset_final.csv   # Legitimate URL dataset
├── phishing_dataset_final.csv     # Phishing URL dataset
├── phishing_model.pkl             # Best selected trained model artifact
├── scaler.pkl                     # Trained StandardScaler artifact
├── decision_tree_model.pkl        # Saved DT model (comparison)
├── random_forest_model.pkl        # Saved RF model (comparison)
├── templates/                     # Jinja templates
│   ├── index.html
│   ├── PHISHING.HTML
│   ├── knowmore.html
│   ├── contact.html
│   └── phishing_dataset.json
└── static/
    ├── css/
    └── js/
```

## Core Detection Flow

1. Input URL is received at `POST /api/check-phishing`.
2. URL is normalized (adds `https://` if protocol missing).
3. 31 numerical features are extracted.
4. Features are scaled using `scaler.pkl`.
5. ML probability is produced by `phishing_model.pkl`.
6. Rule-based detector adds domain and pattern risk signals.
7. Optional LLM analysis is requested from Ollama.
8. Weighted ensemble combines all sources into final verdict.

## Setup and Run (Local)

### 1) Create and activate virtual environment

Windows PowerShell:
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies

```bash
pip install -r requirements.txt
```

### 3) Train model artifacts (if missing or retraining)

```bash
python train_model.py
```

This generates:
- `phishing_model.pkl`
- `scaler.pkl`
- `decision_tree_model.pkl`
- `random_forest_model.pkl`

### 4) Start the Flask app

```bash
python app.py
```

App URLs:
- Home: `http://localhost:5000/`
- Phishing page: `http://localhost:5000/phishing`
- Health: `http://localhost:5000/api/health`

## Windows Convenience Scripts

From project root (`Backend/`):

```bat
run.bat
```

`run.bat` checks for model files and starts Flask.

`start.bat` is an alternate scripted startup flow (installs deps, trains, runs app).

## Optional LLM Analysis (Ollama)

The backend can call Ollama at:
- default: `http://127.0.0.1:11434`
- override via `OLLAMA_HOST` env var

The code requests model name:
- `gemma4:31b-cloud`

If Ollama is not reachable, the API still works and falls back to neutral LLM contribution.

Example (PowerShell):
```powershell
$env:OLLAMA_HOST="http://127.0.0.1:11434"
python app.py
```

## API Reference

### GET /api/health

Returns service and model loading status.

Example response:
```json
{
  "status": "running",
  "model_status": "loaded",
  "scaler_status": "loaded"
}
```

### POST /api/check-phishing

Request body:
```json
{
  "url": "https://example.com"
}
```

Response fields include:
- `is_phishing`, `confidence`, `message`
- `ensemble_analysis`
- `model_analysis`
- `rule_analysis`
- `llm_analysis`

### POST /api/llm-analysis

Runs LLM analysis for a provided URL + phishing_data payload.

## Feature Engineering (31 Features)

The extractor includes URL lexical and structural indicators such as:
- URL length, dots, slashes, hyphens
- HTTPS presence, IP-in-URL, suspicious keywords
- subdomain count, domain length, TLD length
- `@` symbol, extra slashes, percent encoding
- suspicious TLDs, punycode, redirect/query patterns

## Data and Training Workflow

### Build balanced dataset from raw URL sets

```bash
python combine_and_extract.py
```

Input:
- `legitimate_dataset_final.csv`
- `phishing_dataset_final.csv`

Output:
- `phishing_features.csv`

### Train models

```bash
python train_model.py
```

Training behavior:
- 80/20 train-test split
- Standard scaling
- Trains both Decision Tree and Random Forest
- Compares accuracy and saves best as `phishing_model.pkl`

## Docker

### Build image

```bash
docker build -t phishing-detector .
```

### Run container

```bash
docker run -d -p 5000:5000 --name phishing-app phishing-detector
```

### Check logs

```bash
docker logs phishing-app
```

### Stop/remove

```bash
docker stop phishing-app
docker rm phishing-app
```

## Production Notes

- Use gunicorn for production serving:
```bash
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```
- Keep Flask debug mode off in production.
- Put the app behind HTTPS reverse proxy (Nginx/Caddy) for internet exposure.

## Common Troubleshooting

1. Model not loading on startup:
- Run `python train_model.py`.
- Ensure `phishing_model.pkl` and `scaler.pkl` exist in `Backend/`.

2. Port 5000 already in use:
- Stop the conflicting process or switch app port.

3. Ollama errors in response:
- Start Ollama service.
- Verify `OLLAMA_HOST` and model availability.

4. Missing dependencies:
- Re-run `pip install -r requirements.txt` in the active environment.

## Branching and Collaboration (Suggested)

- Keep `main` protected/stable.
- Create feature branches for changes.
- Open PR from your branch to `main` after validation.

## License

No explicit license file is present in this repository. Add one if you plan public/open reuse.
