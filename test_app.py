#!/usr/bin/env python3
"""
Simple test script for the Ransomware Detection System
"""

import requests
import json
import os
import tempfile

BASE_URL = "http://127.0.0.1:5000"

def test_health_check():
    """Test the health check endpoint"""
    print("Testing health check endpoint...")
    response = requests.get(f"{BASE_URL}/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    print("✓ Health check passed")

def test_scan_safe_file():
    """Test scanning a safe file"""
    print("\nTesting scan with safe file...")
    
    # Create a temporary safe file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("This is a safe test file")
        temp_file = f.name
    
    try:
        with open(temp_file, 'rb') as f:
            files = {'file': ('test.txt', f, 'text/plain')}
            response = requests.post(f"{BASE_URL}/scan", files=files)
        
        assert response.status_code == 200
        data = response.json()
        
        print(f"Filename: {data['filename']}")
        print(f"Is Ransomware: {data['is_ransomware']}")
        print(f"Confidence: {data['confidence']}%")
        print(f"File Hash: {data['file_hash'][:16]}...")
        print(f"Threats Detected: {len(data['threats_detected'])}")
        
        assert data['is_ransomware'] == False
        print("✓ Safe file test passed")
    finally:
        os.unlink(temp_file)

def test_scan_suspicious_filename():
    """Test scanning a file with suspicious filename"""
    print("\nTesting scan with suspicious filename...")
    
    # Create a temporary file with suspicious name
    with tempfile.NamedTemporaryFile(mode='w', suffix='_DECRYPT.txt', delete=False) as f:
        f.write("Your files have been encrypted")
        temp_file = f.name
    
    try:
        with open(temp_file, 'rb') as f:
            files = {'file': ('HOW_TO_DECRYPT.txt', f, 'text/plain')}
            response = requests.post(f"{BASE_URL}/scan", files=files)
        
        assert response.status_code == 200
        data = response.json()
        
        print(f"Filename: {data['filename']}")
        print(f"Is Ransomware: {data['is_ransomware']}")
        print(f"Confidence: {data['confidence']}%")
        print(f"Threats Detected: {len(data['threats_detected'])}")
        
        if data['threats_detected']:
            print("\nDetected Threats:")
            for threat in data['threats_detected']:
                print(f"  - {threat['type']}: {threat['description']} (Severity: {threat['severity']})")
        
        assert len(data['threats_detected']) > 0
        print("✓ Suspicious filename test passed")
    finally:
        os.unlink(temp_file)

def test_scan_suspicious_extension():
    """Test scanning a file with ransomware extension"""
    print("\nTesting scan with suspicious extension...")
    
    # Create a temporary file with ransomware extension
    with tempfile.NamedTemporaryFile(mode='w', suffix='.encrypted', delete=False) as f:
        f.write("Encrypted data")
        temp_file = f.name
    
    try:
        filename = os.path.basename(temp_file)
        with open(temp_file, 'rb') as f:
            files = {'file': (filename, f, 'application/octet-stream')}
            response = requests.post(f"{BASE_URL}/scan", files=files)
        
        assert response.status_code == 200
        data = response.json()
        
        print(f"Filename: {data['filename']}")
        print(f"Is Ransomware: {data['is_ransomware']}")
        print(f"Confidence: {data['confidence']}%")
        print(f"Threats Detected: {len(data['threats_detected'])}")
        
        if data['threats_detected']:
            print("\nDetected Threats:")
            for threat in data['threats_detected']:
                print(f"  - {threat['type']}: {threat['description']} (Severity: {threat['severity']})")
        
        assert len(data['threats_detected']) > 0
        print("✓ Suspicious extension test passed")
    finally:
        os.unlink(temp_file)

if __name__ == "__main__":
    print("=" * 60)
    print("Ransomware Detection System - Test Suite")
    print("=" * 60)
    
    try:
        test_health_check()
        test_scan_safe_file()
        test_scan_suspicious_filename()
        test_scan_suspicious_extension()
        
        print("\n" + "=" * 60)
        print("All tests passed! ✓")
        print("=" * 60)
    except Exception as e:
        print(f"\n✗ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        exit(1)
