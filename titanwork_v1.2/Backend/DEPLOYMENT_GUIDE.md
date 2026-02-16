# Phishing Detection System - Deployment Guide

## ✅ Deployment Readiness Checklist

### Project Structure ✓
```
Backend/
├── app.py                      # Flask application (serves frontend + API)
├── train_model.py              # Model training script
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker configuration
├── .dockerignore              # Docker ignore patterns
├── phishing_features.csv       # Training data
│
├── templates/                  # HTML templates
│   ├── index.html             # Home page (uses url_for)
│   ├── PHISHING.HTML          # Detection page (uses url_for)
│   ├── contact.html           # Contact page
│   └── knowmore.html          # About page
│
└── static/                     # Static assets
    ├── css/
    │   ├── style.css          # Main stylesheet
    │   ├── contact.css        # Contact page styles
    │   ├── knowmore.css       # About page styles
    │   └── phi.css            # Additional styles
    └── js/
        └── script.js          # (if any custom scripts)
```

---

## 🚀 Quick Start

### Option 1: Local Development

```bash
# 1. Navigate to Backend directory
cd Backend

# 2. Install dependencies
pip install -r requirements.txt

# 3. Train the model (one-time)
python train_model.py

# 4. Start the server
python app.py

# 5. Open browser
# Visit: http://localhost:5000
```

### Option 2: Docker Deployment

```bash
# 1. Build the Docker image
cd Backend
docker build -t phishing-detector .

# 2. Run the container
docker run -d -p 5000:5000 --name phishing-app phishing-detector

# 3. Access the application
# Visit: http://localhost:5000

# 4. Check logs
docker logs phishing-app

# 5. Stop container
docker stop phishing-app

# 6. Remove container
docker rm phishing-app
```

---

## 🐳 Docker Details

### Build Arguments
```bash
docker build -t phishing-detector:v1.0 .
```

### Run with Environment Variables
```bash
docker run -d \
  -p 5000:5000 \
  -e FLASK_ENV=production \
  --name phishing-app \
  phishing-detector:v1.0
```

### Docker Compose (Optional)
Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  phishing-detector:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import requests; requests.get('http://localhost:5000/api/health')"]
      interval: 30s
      timeout: 3s
      retries: 3
```

Then run:
```bash
docker-compose up -d
```

---

## 🔍 Verification Tests

### 1. Check Server Status
```bash
curl http://localhost:5000/api/health
```
Expected response:
```json
{
  "status": "running",
  "model_status": "loaded",
  "scaler_status": "loaded"
}
```

### 2. Test Phishing Detection API
```bash
curl -X POST http://localhost:5000/api/check-phishing \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

Expected response:
```json
{
  "success": true,
  "url": "https://google.com",
  "is_phishing": false,
  "confidence": 92.45,
  "phishing_probability": 7.55,
  "legitimate_probability": 92.45,
  "message": "Website appears to be safe."
}
```

### 3. Test Frontend Access
- Home: http://localhost:5000/
- Detection: http://localhost:5000/phishing
- About: http://localhost:5000/knowmore
- Contact: http://localhost:5000/contact

### 4. Verify Static Files
Check that CSS loads properly:
```bash
curl http://localhost:5000/static/css/style.css
```

---

## 📝 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | `development` | Flask environment (production/development) |
| `FLASK_APP` | `app.py` | Main Flask application file |
| `PORT` | `5000` | Server port |

### Production Settings

For production deployment, modify `app.py`:
```python
if __name__ == '__main__':
    if load_model():
        # Use gunicorn in production
        app.run(debug=False, host='0.0.0.0', port=5000)
```

Or use Gunicorn:
```bash
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

---

## 🔒 Security Considerations

1. **Remove debug mode in production**
   - Set `debug=False` in app.run()
   - Use environment variables for sensitive data

2. **Use HTTPS** in production
   - Configure SSL/TLS certificates
   - Use a reverse proxy (Nginx, Caddy)

3. **Rate Limiting**
   - Consider adding Flask-Limiter for API rate limiting

4. **Input Validation**
   - Already implemented in API endpoints
   - Validates URL format before processing

---

## 🐛 Troubleshooting

### Issue: Model files not found
**Solution:**
```bash
python train_model.py
```

### Issue: Port 5000 already in use
**Solution:**
```bash
# Find process using port 5000
netstat -ano | findstr :5000  # Windows
lsof -i :5000                 # Mac/Linux

# Kill the process or use different port
# app.py: change port=5000 to port=8000
```

### Issue: CSS not loading
**Solution:**
- Check that files are in `static/css/`
- Verify HTML uses `{{ url_for('static', filename='css/style.css') }}`
- Clear browser cache

### Issue: API returns 500 error
**Solution:**
- Check model and scaler files exist
- Verify Flask server logs
- Ensure phishing_features.csv is present

---

## 📊 Performance

### Expected Response Times
- Homepage: < 100ms
- Phishing Detection: 200-500ms
- API Health Check: < 50ms

### Resource Requirements
- RAM: 512MB minimum
- CPU: 1 core minimum
- Disk: 100MB

---

## 🔄 Updates and Maintenance

### Updating the Model
1. Add new training data to `phishing_features.csv`
2. Run `python train_model.py`
3. Restart the server or rebuild Docker image

### Updating Dependencies
```bash
pip install --upgrade -r requirements.txt
pip freeze > requirements.txt
```

---

## 🌐 Cloud Deployment Options

### Deploy to Heroku
```bash
# Install Heroku CLI
heroku create phishing-detector-app
heroku container:push web
heroku container:release web
heroku open
```

### Deploy to AWS (EC2)
1. Launch EC2 instance (t2.micro or higher)
2. Install Docker
3. Clone repository
4. Build and run Docker container
5. Configure security group (port 5000)

### Deploy to Google Cloud Run
```bash
gcloud builds submit --tag gcr.io/PROJECT-ID/phishing-detector
gcloud run deploy --image gcr.io/PROJECT-ID/phishing-detector --platform managed
```

---

## ✅ Final Verification Before Production

- [ ] Model trained and .pkl files exist
- [ ] requirements.txt includes all dependencies
- [ ] templates/ contains all HTML files
- [ ] static/ contains all CSS/JS files
- [ ] HTML files use Flask url_for()
- [ ] API uses relative URLs (no hardcoded localhost)
- [ ] app.py runs on 0.0.0.0:5000
- [ ] Docker builds successfully
- [ ] Frontend loads at http://localhost:5000/
- [ ] API responds at /api/check-phishing
- [ ] Health check works at /api/health
- [ ] No hardcoded localhost URLs in frontend
- [ ] Debug mode disabled for production

---

## 📞 Support

For issues or questions:
1. Check logs: `docker logs phishing-app`
2. Test API endpoints individually
3. Verify file structure matches guide
4. Ensure all dependencies installed

---

**Status:** ✅ Ready for Docker Deployment
**Last Updated:** February 16, 2026
