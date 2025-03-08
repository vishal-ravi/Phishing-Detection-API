# AI-Powered Phishing Detection System

A sophisticated phishing detection system that uses machine learning and natural language processing to analyze URLs and emails for potential phishing threats. The system provides a user-friendly API interface and a browser extension for real-time protection.

## Features

### 1. URL Analysis
- Real-time URL scanning and risk assessment
- Multiple feature extraction including:
  - Domain analysis
  - TLD verification
  - Path and query analysis
  - Special character detection
  - Suspicious word identification
- Detailed security indicators and risk scoring

### 2. Email Analysis
- Comprehensive email content analysis
- Detection of:
  - Phishing language patterns
  - Suspicious formatting
  - Urgency indicators
  - Security-related keywords
  - Personal information requests

### 3. User Interface
- Clean, modern web interface
- Interactive API documentation
- Real-time analysis results
- Visual risk indicators
- Detailed threat analysis reports

## Technology Stack

- **Backend**: Python, Flask
- **Machine Learning**: TensorFlow, spaCy
- **Feature Engineering**: NumPy, tldextract
- **Frontend**: HTML, CSS, JavaScript
- **API**: RESTful endpoints with CORS support

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd phishing-detection
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

4. Download the spaCy model:
```bash
python -m spacy download en_core_web_sm
```

## Configuration

1. Ensure all model files are present in the `models/` directory:
- `url_model/` - TensorFlow model for URL analysis
- `email_model/` - TensorFlow model for email analysis
- `url_vectorizer.pkl` - Feature vectorizer for URLs
- `text_vectorizer.pkl` - Feature vectorizer for email content

2. Configure environment variables (if needed):
```bash
export FLASK_APP=app.py
export FLASK_ENV=development
```

## Usage

1. Start the Flask server:
```bash
python app.py
```

2. Access the web interface at `http://localhost:5000`

### API Endpoints

#### 1. Analyze URL
```http
POST /api/analyze_url
Content-Type: application/json

{
    "url": "https://example.com"
}
```

#### 2. Analyze Email
```http
POST /api/analyze_email
Content-Type: application/json

{
    "email_content": "Email text content..."
}
```

#### 3. Submit Feedback
```http
POST /api/report_feedback
Content-Type: application/json

{
    "url": "https://example.com",
    "is_phishing": true,
    "content_type": "url"
}
```

## Feature Details

### URL Analysis Features
- Length and character composition
- Domain structure analysis
- TLD verification
- Special character detection
- Path and query analysis
- Security protocol verification
- Suspicious word detection

### Email Analysis Features
- Text content analysis
- Formatting patterns
- Link extraction
- Header analysis
- Urgency indicators
- Security term detection
- Personal information request detection

## Model Training

The system uses two main machine learning models:

1. **URL Model**: Trained on a dataset of legitimate and phishing URLs
   - Features: 26 URL characteristics
   - Architecture: Neural network with multiple dense layers
   - Performance metrics: Accuracy, precision, recall, F1-score

2. **Email Model**: Trained on email content
   - Features: Text characteristics and patterns
   - NLP processing: spaCy for text analysis
   - Custom feature extraction for email-specific indicators

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Security Considerations

- The system is designed for detection only and should not be used as the sole security measure
- Regular updates to the models are recommended to maintain effectiveness
- False positives and negatives are possible; human verification is recommended for critical decisions

## License

[Your chosen license]

## Acknowledgments

- TensorFlow team for the machine learning framework
- spaCy for NLP capabilities
- Flask team for the web framework
- All contributors and maintainers

## Support

For support, please open an issue in the repository or contact [your contact information]. 