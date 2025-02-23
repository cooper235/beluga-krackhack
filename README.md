# Static Malware Analysis Web Application

## Overview
This web application allows users to perform **static malware analysis** on uploaded files (e.g., `.exe`, `.docx`, `.pdf`). The system scans files using pattern-matching techniques like **YARA rules** and **PE analysis** to detect potential threats. It provides a quick and user-friendly way to check for malicious indicators without requiring deep technical expertise.

## Features
- **Fast and Accurate Static Analysis** (No sandboxing or dynamic execution)
- **File Upload via Web Interface** (Simple and intuitive UI)
- **Concise Verdicts**: `Malicious` or `Clean`
- **Risk Factor Report** (Highlights suspicious components in files)
- **Security Measures**: File validation, size limits, and protection against malicious uploads
- **Scalability**: Supports multiple concurrent scans

## Technology Stack
### Front-End
- simple HTML/CSS/JavaScript for basic UI

### Back-End
- FastAPI (Python) for handling file uploads and scan requests

### File Analysis
- **YARA**: Pattern-matching for malware signatures
- **pefile**: Windows PE file analysis
- **Custom Heuristics**: Suspicious string detection, high entropy analysis, etc.

### Database (Optional)
- PostgreSQL / SQLite for storing scan logs and reference signatures

## Installation & Setup
### Prerequisites
- Python 3.8+
- Node.js (if using a React/Angular front-end)
- Docker (optional, for containerized deployment)

### Clone the Repository
```sh
git clone https://github.com/yourusername/static-malware-scanner.git
cd static-malware-scanner
```

### Backend Setup
1. Create and activate a virtual environment:
```sh
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```
2. Install dependencies:
```sh
pip install -r requirements.txt
```
3. Run the backend server:
```sh
uvicorn main:app --reload
```

### Frontend Setup (If Using React)
1. Navigate to the frontend directory:
```sh
cd frontend
```
2. Install dependencies:
```sh
npm install
```
3. Start the development server:
```sh
npm start
```

## Usage
1. Open the web application in a browser.
2. Upload a suspicious file (`.exe`, `.pdf`, `.docx`, etc.).
3. The system will analyze the file and return a verdict:
   - **Clean**: "No malicious indicators found."
   - **Malicious**: "High entropy and suspicious macro code detected."
4. (Optional) View a risk factor report highlighting specific threats.

## Security Measures
- **Input Validation**: Ensures only valid file types and sizes are processed.
- **File Sanitization**: Prevents malicious filenames from being executed.
- **Rate Limiting**: Protects against abuse and denial-of-service attacks.

## Evaluation Metrics
- **Detection Accuracy**: Correctly identifying malicious/clean files.
- **False Positives/Negatives**: Reducing misclassification rates.
- **User Experience**: Ensuring an intuitive and seamless UI.
- **Security & Reliability**: Preventing system exploitation.
- **Performance & Scalability**: Efficiently handling multiple file uploads.

## Contribution Guidelines
1. Fork the repository and create a feature branch.
2. Commit your changes with clear messages.
3. Submit a pull request for review.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact & Support
For questions, issues, or suggestions, please open an issue in the repository or contact kripakanodia@gmail.com].


