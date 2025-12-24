import os
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from werkzeug.utils import secure_filename
import hashlib
import re

# Try to import magic, but make it optional
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Known ransomware file extensions
RANSOMWARE_EXTENSIONS = [
    '.encrypted', '.locked', '.crypto', '.crypt', '.cryptolocker', '.cryptowall',
    '.cerber', '.locky', '.zepto', '.odin', '.thor', '.aesir', '.zzzzz',
    '.micro', '.mp3', '.xxx', '.ttt', '.vvv', '.ecc', '.ezz', '.exx',
    '.xyz', '.aaa', '.abc', '.ccc', '.vvv', '.xxx', '.zzz', '.vault',
    '.wallet', '.onion', '.wncry', '.wcry', '.WNCRY', '.wnry', '.cobra',
    '.evillock', '.ha3', '.toxcrypt', '.pec', '.good', '.LOL!', '.OMG!',
    '.RDM', '.RRK', '.encryptedRSA', '.crjoker', '.EnCiPhErEd', '.LeChiffre',
    '.keybtc@inbox_com', '.0x0', '.bleep', '.1999', '.nuclear', '.cryp1'
]

# Known ransomware file signatures (magic bytes)
RANSOMWARE_SIGNATURES = {
    'WANACRY': b'WANACRY',
    'PEYTA': b'PEYTA',
    'CERBER': b'CERBER',
}

# Suspicious file name patterns
SUSPICIOUS_PATTERNS = [
    r'DECRYPT.*\.txt',
    r'HELP.*DECRYPT',
    r'HOW.*TO.*DECRYPT',
    r'README.*\.txt',
    r'RECOVERY.*\.txt',
    r'YOUR.*FILES.*ENCRYPTED',
    r'ATTENTION.*\.txt',
    r'RESTORE.*FILES.*\.txt',
]

def calculate_file_hash(filepath):
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_file_extension(filename):
    """Check if file has a suspicious extension"""
    _, ext = os.path.splitext(filename.lower())
    return ext in RANSOMWARE_EXTENSIONS

def check_file_signature(filepath):
    """Check file for known ransomware signatures"""
    try:
        with open(filepath, 'rb') as f:
            content = f.read(1024)  # Read first 1KB
            for name, signature in RANSOMWARE_SIGNATURES.items():
                if signature in content:
                    return True, name
    except Exception:
        pass
    return False, None

def check_filename_pattern(filename):
    """Check if filename matches suspicious patterns"""
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, filename, re.IGNORECASE):
            return True, pattern
    return False, None

def analyze_file_entropy(filepath):
    """Calculate file entropy (high entropy can indicate encryption)"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            if len(data) == 0:
                return 0.0
            
            # Calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
    except Exception:
        return 0.0

def detect_ransomware(filepath, filename):
    """Main detection function"""
    results = {
        'filename': filename,
        'is_ransomware': False,
        'confidence': 0,
        'threats_detected': [],
        'file_hash': '',
        'file_type': '',
        'entropy': 0.0
    }
    
    try:
        # Calculate file hash
        results['file_hash'] = calculate_file_hash(filepath)
        
        # Get file type
        try:
            if MAGIC_AVAILABLE:
                mime = magic.Magic(mime=True)
                results['file_type'] = mime.from_file(filepath)
            else:
                # Fallback to extension-based detection
                _, ext = os.path.splitext(filename)
                results['file_type'] = ext if ext else 'unknown'
        except Exception:
            results['file_type'] = 'unknown'
        
        # Check file extension
        if check_file_extension(filename):
            results['threats_detected'].append({
                'type': 'Suspicious Extension',
                'severity': 'High',
                'description': f'File has a ransomware-associated extension'
            })
            results['confidence'] += 40
        
        # Check file signature
        has_signature, sig_name = check_file_signature(filepath)
        if has_signature:
            results['threats_detected'].append({
                'type': 'Ransomware Signature',
                'severity': 'Critical',
                'description': f'Known ransomware signature detected: {sig_name}'
            })
            results['confidence'] += 50
        
        # Check filename pattern
        has_pattern, pattern = check_filename_pattern(filename)
        if has_pattern:
            results['threats_detected'].append({
                'type': 'Suspicious Filename',
                'severity': 'Medium',
                'description': f'Filename matches ransomware pattern: {pattern}'
            })
            results['confidence'] += 30
        
        # Calculate entropy
        entropy = analyze_file_entropy(filepath)
        results['entropy'] = round(entropy, 2)
        
        # High entropy can indicate encryption
        if entropy > 7.5:
            results['threats_detected'].append({
                'type': 'High Entropy',
                'severity': 'Medium',
                'description': f'File has high entropy ({entropy:.2f}), possibly encrypted'
            })
            results['confidence'] += 20
        
        # Determine if ransomware based on confidence
        results['confidence'] = min(results['confidence'], 100)
        results['is_ransomware'] = results['confidence'] >= 50
        
    except Exception as e:
        results['error'] = str(e)
    
    return results

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Handle file upload and scanning"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Analyze the file
            results = detect_ransomware(filepath, filename)
            
            # Clean up uploaded file
            os.remove(filepath)
            
            return jsonify(results)
        except Exception as e:
            # Clean up on error
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'error': str(e)}), 500
    
    return jsonify({'error': 'Invalid request'}), 400

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
