# Ransomware Detection System

A web-based ransomware detection system that analyzes files for potential ransomware indicators using multiple detection methods.

## Live Demo
Access the public deployment here:
🔗 https://ransomware-detection-system-1.onrender.com/

## Features

- **Extension Analysis**: Detects known ransomware file extensions
- **Signature Detection**: Scans for known ransomware signatures and patterns
- **Filename Pattern Matching**: Identifies suspicious filename patterns commonly used by ransomware
- **Entropy Analysis**: Calculates file entropy to detect potential encryption
- **Real-time Scanning**: Upload and analyze files instantly
- **Detailed Reports**: Comprehensive scan results with confidence scores

## Detection Methods

1. **File Extension Check**: Identifies files with extensions commonly associated with ransomware
2. **Signature Scanning**: Searches for known ransomware signatures in file contents
3. **Filename Pattern Analysis**: Detects suspicious patterns in filenames (e.g., "DECRYPT.txt", "HOW_TO_DECRYPT")
4. **Entropy Calculation**: High entropy values may indicate encrypted content

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/brookme1/Ranosmware_detection_system-.git
cd Ranosmware_detection_system-
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to:
```
http://localhost:5000
```

## Usage

1. Navigate to the home page
2. Click "Browse Files" or drag and drop a file onto the upload area
3. Wait for the analysis to complete
4. Review the scan results including:
   - Detection status (Safe/Suspicious/Ransomware)
   - Confidence score
   - File details (hash, type, entropy)
   - List of detected threats with severity levels

## Technology Stack

- **Backend**: Python Flask
- **Frontend**: HTML, CSS, JavaScript
- **File Analysis**: python-magic, hashlib
- **Detection**: Custom rule-based engine with entropy analysis

## Security Notes

⚠️ **Important**: 
- This tool is for educational and detection purposes only
- Always maintain regular backups of important files
- Use comprehensive antivirus software for complete protection
- Files uploaded are analyzed and immediately deleted from the server
- Do not rely solely on this tool for ransomware protection

## API Endpoints

- `GET /` - Main scanning interface
- `POST /scan` - Upload and scan a file
- `GET /about` - About page with project information
- `GET /health` - Health check endpoint

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is provided "as is" without warranty of any kind. The developers are not responsible for any damage or data loss that may occur from using this tool. Always exercise caution when handling potentially malicious files.