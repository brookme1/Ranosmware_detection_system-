document.addEventListener('DOMContentLoaded', function() {
    const uploadBox = document.getElementById('uploadBox');
    const fileInput = document.getElementById('fileInput');
    const browseBtn = document.getElementById('browseBtn');
    const resultsDiv = document.getElementById('results');
    const resultsContent = document.getElementById('resultsContent');
    const loadingDiv = document.getElementById('loading');
    const scanAgainBtn = document.getElementById('scanAgainBtn');

    // Browse button click
    if (browseBtn) {
        browseBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            fileInput.click();
        });
    }

    // Upload box click
    if (uploadBox) {
        uploadBox.addEventListener('click', function() {
            fileInput.click();
        });
    }

    // File input change
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                handleFile(this.files[0]);
            }
        });
    }

    // Drag and drop
    if (uploadBox) {
        uploadBox.addEventListener('dragover', function(e) {
            e.preventDefault();
            this.classList.add('drag-over');
        });

        uploadBox.addEventListener('dragleave', function(e) {
            e.preventDefault();
            this.classList.remove('drag-over');
        });

        uploadBox.addEventListener('drop', function(e) {
            e.preventDefault();
            this.classList.remove('drag-over');
            if (e.dataTransfer.files.length > 0) {
                handleFile(e.dataTransfer.files[0]);
            }
        });
    }

    // Scan again button
    if (scanAgainBtn) {
        scanAgainBtn.addEventListener('click', function() {
            resultsDiv.style.display = 'none';
            document.querySelector('.upload-section').style.display = 'block';
            fileInput.value = '';
        });
    }

    function handleFile(file) {
        // Hide upload section and show loading
        document.querySelector('.upload-section').style.display = 'none';
        loadingDiv.style.display = 'block';
        resultsDiv.style.display = 'none';

        // Create form data
        const formData = new FormData();
        formData.append('file', file);

        // Send to server
        fetch('/scan', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            loadingDiv.style.display = 'none';
            displayResults(data);
        })
        .catch(error => {
            loadingDiv.style.display = 'none';
            displayError(error.message);
        });
    }

    function displayResults(data) {
        resultsDiv.style.display = 'block';
        
        if (data.error) {
            resultsContent.innerHTML = `
                <div class="result-card danger">
                    <div class="result-status">
                        <div class="status-icon">❌</div>
                        <div class="status-text">
                            <h4>Error</h4>
                            <p>${data.error}</p>
                        </div>
                    </div>
                </div>
            `;
            return;
        }

        let cardClass = 'safe';
        let statusIcon = '✅';
        let statusTitle = 'File Appears Safe';
        let statusMessage = 'No significant ransomware indicators detected.';

        if (data.is_ransomware) {
            if (data.confidence >= 80) {
                cardClass = 'danger';
                statusIcon = '🚨';
                statusTitle = 'RANSOMWARE DETECTED';
                statusMessage = 'This file shows strong indicators of ransomware!';
            } else if (data.confidence >= 50) {
                cardClass = 'warning';
                statusIcon = '⚠️';
                statusTitle = 'Suspicious File';
                statusMessage = 'This file shows some ransomware indicators.';
            }
        }

        let html = `
            <div class="result-card ${cardClass}">
                <div class="result-status">
                    <div class="status-icon">${statusIcon}</div>
                    <div class="status-text">
                        <h4>${statusTitle}</h4>
                        <p>${statusMessage}</p>
                    </div>
                </div>

                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: ${data.confidence}%">
                        ${data.confidence}% Confidence
                    </div>
                </div>

                <div class="result-details">
                    <div class="detail-item">
                        <span class="detail-label">Filename:</span>
                        <span class="detail-value">${data.filename}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">File Type:</span>
                        <span class="detail-value">${data.file_type}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">File Hash (SHA256):</span>
                        <span class="detail-value">${data.file_hash.substring(0, 32)}...</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Entropy:</span>
                        <span class="detail-value">${data.entropy}</span>
                    </div>
                </div>
            </div>
        `;

        if (data.threats_detected && data.threats_detected.length > 0) {
            html += `
                <div class="result-card">
                    <h4 style="margin-bottom: 1rem;">Threats Detected</h4>
                    <div class="threats-list">
            `;

            data.threats_detected.forEach(threat => {
                const severityClass = threat.severity.toLowerCase();
                html += `
                    <div class="threat-item ${severityClass}">
                        <div class="threat-header">
                            <span class="threat-type">${threat.type}</span>
                            <span class="threat-severity ${severityClass}">${threat.severity}</span>
                        </div>
                        <div class="threat-description">${threat.description}</div>
                    </div>
                `;
            });

            html += `
                    </div>
                </div>
            `;
        }

        resultsContent.innerHTML = html;
    }

    function displayError(message) {
        resultsDiv.style.display = 'block';
        resultsContent.innerHTML = `
            <div class="result-card danger">
                <div class="result-status">
                    <div class="status-icon">❌</div>
                    <div class="status-text">
                        <h4>Error</h4>
                        <p>${message}</p>
                    </div>
                </div>
            </div>
        `;
    }
});
