/**
 * QR Code Scanner JavaScript
 * Handles camera-based QR scanning and image upload scanning
 */

let html5QrCode = null;
let scannerActive = false;
let availableCameras = [];
let selectedCameraId = null;
let currentStreamTrack = null;
let lastDecoded = { text: null, ts: 0 };

// DOM elements
const startBtn = document.getElementById('startScanBtn');
const stopBtn = document.getElementById('stopScanBtn');
const qrFileInput = document.getElementById('qrFile');
const scannerStatus = document.getElementById('scannerStatus');
const scanResults = document.getElementById('scanResults');
const documentInfo = document.getElementById('documentInfo');
const cameraSelect = document.getElementById('cameraSelect');
const torchBtn = document.getElementById('torchBtn');

// Initialize scanner when page loads
document.addEventListener('DOMContentLoaded', function() {
    initializeScanner();
    setupEventListeners();
});

function initializeScanner() {
    // Initialize HTML5 QR Code scanner
    html5QrCode = new Html5Qrcode("reader");

    // Enumerate and populate camera list
    Html5Qrcode.getCameras().then(devices => {
        availableCameras = devices || [];
        if (availableCameras.length === 0) {
            updateStatus('No camera detected. Use file upload to scan QR codes.', 'warning');
            startBtn.disabled = true;
            return;
        }

        // Prefer back/rear camera when available
        const preferIdx = availableCameras.findIndex(d => /back|rear|environment/i.test(d.label));
        selectedCameraId = (preferIdx >= 0 ? availableCameras[preferIdx].id : availableCameras[0].id);

        if (cameraSelect) {
            cameraSelect.innerHTML = '';
            availableCameras.forEach((d, i) => {
                const opt = document.createElement('option');
                opt.value = d.id;
                opt.textContent = d.label || `Camera ${i+1}`;
                if (d.id === selectedCameraId) opt.selected = true;
                cameraSelect.appendChild(opt);
            });
            cameraSelect.disabled = false;
        }

        updateStatus('Camera detected. Ready to scan QR codes.', 'info');
    }).catch(err => {
        console.warn('Camera detection error:', err);
        updateStatus('Camera access unavailable. Use file upload to scan QR codes.', 'warning');
    });
}

function setupEventListeners() {
    // Start scanning button
    startBtn.addEventListener('click', startScanning);
    
    // Stop scanning button
    stopBtn.addEventListener('click', stopScanning);
    
    // File upload for QR codes
    qrFileInput.addEventListener('change', handleFileUpload);

    // Camera selection change
    if (cameraSelect) {
        cameraSelect.addEventListener('change', function() {
            selectedCameraId = this.value;
            if (scannerActive) {
                stopScanning();
                setTimeout(startScanning, 200);
            }
        });
    }

    // Torch toggle
    if (torchBtn) {
        let torchOn = false;
        torchBtn.addEventListener('click', function() {
            torchOn = !torchOn;
            const ok = setTorch(torchOn);
            if (ok) {
                torchBtn.classList.toggle('btn-warning', torchOn);
                torchBtn.classList.toggle('btn-secondary', !torchOn);
                torchBtn.innerHTML = torchOn ? '<i class="fas fa-lightbulb me-1"></i>Torch On' : '<i class="fas fa-lightbulb me-1"></i>Torch Off';
            } else {
                updateStatus('Torch not supported on this device/browser.', 'warning');
                torchOn = false;
            }
        });
    }
}

function startScanning() {
    if (scannerActive) return;

    updateStatus('Starting camera...', 'info');
    startBtn.disabled = true;

    // Responsive QR box based on viewport
    const qrboxFunc = function(viewfinderWidth, viewfinderHeight) {
        const minEdge = Math.min(viewfinderWidth, viewfinderHeight);
        const size = Math.floor(minEdge * 0.75); // 75% of smaller edge
        return { width: size, height: size };
    };

    const readerEl = document.getElementById('reader');
    const rect = readerEl ? readerEl.getBoundingClientRect() : { width: 640, height: 360 };
    const aspect = rect.width > 0 && rect.height > 0 ? (rect.width / rect.height) : 1.7778;

    // Camera configuration tuned for responsiveness
    const config = {
        fps: 15,
        qrbox: qrboxFunc,
        aspectRatio: aspect,
        // Limit to QR format for performance (library default is QR)
        // formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE]
    };

    const cameraOrConstraints = selectedCameraId ? selectedCameraId : { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } };

    html5QrCode.start(
        cameraOrConstraints,
        config,
        onScanSuccess,
        onScanError
    ).then(() => {
        scannerActive = true;
        startBtn.disabled = true;
        stopBtn.disabled = false;
        updateStatus('Camera active. Point camera at QR code to scan.', 'success');

        // Try to capture the underlying video track for torch/autofocus
        setTimeout(() => {
            try {
                const video = document.querySelector('#reader video');
                if (video && video.srcObject) {
                    const tracks = video.srcObject.getVideoTracks();
                    if (tracks && tracks.length) {
                        currentStreamTrack = tracks[0];
                        // Enable continuous autofocus if supported
                        const caps = currentStreamTrack.getCapabilities?.();
                        if (caps && caps.focusMode && caps.focusMode.includes('continuous')) {
                            currentStreamTrack.applyConstraints({ advanced: [{ focusMode: 'continuous' }] }).catch(() => {});
                        }
                    }
                }
            } catch (e) {
                // ignore
            }
        }, 300);
    }).catch(err => {
        console.error('Camera start error:', err);
        updateStatus('Failed to start camera. Please check permissions.', 'danger');
        startBtn.disabled = false;
    });
}

function stopScanning() {
    if (!scannerActive) return;
    
    html5QrCode.stop().then(() => {
        scannerActive = false;
        startBtn.disabled = false;
        stopBtn.disabled = true;
        updateStatus('Camera stopped. Click "Start Camera" to scan again.', 'info');
    }).catch(err => {
        console.error('Camera stop error:', err);
        updateStatus('Error stopping camera.', 'danger');
    });
}

function onScanSuccess(decodedText, decodedResult) {
    // Debounce duplicate results within 1.5s
    const now = Date.now();
    if (lastDecoded.text === decodedText && (now - lastDecoded.ts) < 1500) {
        return;
    }
    lastDecoded = { text: decodedText, ts: now };

    // Haptic feedback if supported
    if (navigator.vibrate) {
        navigator.vibrate(100);
    }

    // Stop scanning after successful detection
    stopScanning();

    updateStatus('QR code detected! Processing...', 'success');

    // Process the QR code data
    processQRCode(decodedText);
}

function onScanError(error) {
    // Ignore frequent scan errors - they're normal when no QR code is visible
    // console.log('Scan error:', error);
}

function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    updateStatus('Processing uploaded image...', 'info');
    
    // Scan QR code from uploaded file
    html5QrCode.scanFile(file, true)
        .then(decodedText => {
            updateStatus('QR code found in image!', 'success');
            processQRCode(decodedText);
        })
        .catch(err => {
            console.error('File scan error:', err);
            updateStatus('No QR code found in the uploaded image.', 'danger');
        });
}

function processQRCode(qrData) {
    // Normalize and split into lines to catch our payload structure
    const text = String(qrData || '');
    const lines = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const joined = lines.join(' ');

    // 1) Try to extract code from "Document Number: DOCxxxxx"
    let m = joined.match(/Document\s*Number\s*:\s*(DOC\d{4,})/i);
    if (m) {
        return fetchDocumentInfoByCode(m[1].toUpperCase());
    }

    // 2) Try to extract code pattern anywhere
    m = joined.match(/\b(DOC\d{4,})\b/i);
    if (m) {
        return fetchDocumentInfoByCode(m[1].toUpperCase());
    }

    // 3) Try to extract IDs or codes from known URL paths
    // /qr/code/<code> or /qr/<id> or /document/<id>
    m = joined.match(/\/qr\/code\/([A-Za-z0-9_-]+)/i);
    if (m) {
        return fetchDocumentInfoByCode(m[1]);
    }
    m = joined.match(/\/qr\/(\d+)/i);
    if (m) {
        return fetchDocumentInfo(m[1]);
    }
    m = joined.match(/\/document\/(\d+)/i);
    if (m) {
        return fetchDocumentInfo(m[1]);
    }

    // 4) Fallback: find first http(s) URL and try to parse
    m = joined.match(/https?:\/\/[\w\-\.:%#/?&=+@~]+/i);
    if (m) {
        try {
            const url = new URL(m[0]);
            const parts = url.pathname.split('/').filter(Boolean);
            // try patterns
            const idxQr = parts.indexOf('qr');
            if (idxQr >= 0 && parts[idxQr+1] && /^\d+$/.test(parts[idxQr+1])) {
                return fetchDocumentInfo(parts[idxQr+1]);
            }
            const idxQrCode = parts.indexOf('code');
            if (idxQrCode >= 0 && parts[idxQrCode+1]) {
                return fetchDocumentInfoByCode(parts[idxQrCode+1]);
            }
            const idxDoc = parts.indexOf('document');
            if (idxDoc >= 0 && parts[idxDoc+1] && /^\d+$/.test(parts[idxDoc+1])) {
                return fetchDocumentInfo(parts[idxDoc+1]);
            }
        } catch (e) {
            // ignore
        }
    }

    updateStatus('QR code detected, but could not extract a document reference.', 'warning');
    showGenericQRResult(qrData);
}

function setTorch(on) {
    try {
        if (!currentStreamTrack) return false;
        const caps = currentStreamTrack.getCapabilities?.();
        if (caps && 'torch' in caps) {
            currentStreamTrack.applyConstraints({ advanced: [{ torch: !!on }] }).catch(() => {});
            return true;
        }
    } catch (e) {
        // ignore
    }
    return false;
}

function fetchDocumentInfo(documentId) {
    updateStatus('Fetching document information...', 'info');
    
    // Make API call to get document information
    fetch(`/qr_lookup/${documentId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            displayDocumentInfo(data);
            updateStatus('Document information loaded successfully!', 'success');
        })
        .catch(error => {
            console.error('Document fetch error:', error);
            if (error.message.includes('403')) {
                updateStatus('Access denied. You do not have permission to view this document.', 'danger');
            } else if (error.message.includes('404')) {
                updateStatus('Document not found. The QR code may be invalid or outdated.', 'warning');
            } else {
                updateStatus('Error loading document information. Please try again.', 'danger');
            }
        });
}

function fetchDocumentInfoByCode(code) {
    updateStatus('Fetching document information by code...', 'info');
    fetch(`/qr_lookup/code/${encodeURIComponent(code)}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            displayDocumentInfo(data);
            updateStatus('Document information loaded successfully!', 'success');
        })
        .catch(error => {
            console.error('Document fetch error:', error);
            if (error.message.includes('403')) {
                updateStatus('Access denied. You do not have permission to view this document.', 'danger');
            } else if (error.message.includes('404')) {
                updateStatus('Document not found. The QR code may be invalid or outdated.', 'warning');
            } else {
                updateStatus('Error loading document information. Please try again.', 'danger');
            }
        });
}

function displayDocumentInfo(document) {
    documentInfo.innerHTML = `
        <div class="row">
            <div class="col-md-8">
                <h6 class="mb-1">${escapeHtml(document.title)}</h6>
                <div class="mb-2 text-muted">Document ID: <strong>${escapeHtml(document.document_number || ('#' + document.id))}</strong></div>
                <dl class="row">
                    <dt class="col-sm-3">Type:</dt>
                    <dd class="col-sm-9"><span class="badge bg-secondary">${escapeHtml(document.type)}</span></dd>
                    
                    <dt class="col-sm-3">Owner:</dt>
                    <dd class="col-sm-9">${escapeHtml(document.owner)}</dd>
                    
                    <dt class="col-sm-3">Date:</dt>
                    <dd class="col-sm-9">${escapeHtml(document.created_at)}</dd>
                </dl>
            </div>
            <div class="col-md-4 text-end">
                <div class="btn-group-vertical w-100" role="group">
                    <a href="${escapeHtml(document.view_url)}" class="btn btn-primary">
                        <i class="fas fa-eye me-1"></i>View Details
                    </a>
                    <a href="${escapeHtml(document.download_url)}" class="btn btn-success">
                        <i class="fas fa-download me-1"></i>Download
                    </a>
                </div>
            </div>
        </div>
    `;
    
    scanResults.classList.remove('d-none');
    
    // Add animation
    scanResults.style.opacity = '0';
    scanResults.style.transform = 'translateY(20px)';
    
    setTimeout(() => {
        scanResults.style.transition = 'all 0.3s ease';
        scanResults.style.opacity = '1';
        scanResults.style.transform = 'translateY(0)';
    }, 100);
}

function showGenericQRResult(qrData) {
    documentInfo.innerHTML = `
        <div class="alert alert-info">
            <h6><i class="fas fa-qrcode me-2"></i>QR Code Detected</h6>
            <p class="mb-0">Content: <code>${escapeHtml(qrData)}</code></p>
            <small class="text-muted">This QR code does not appear to be a document QR code from this system.</small>
        </div>
    `;
    
    scanResults.classList.remove('d-none');
}

function updateStatus(message, type = 'info') {
    const iconMap = {
        'info': 'fas fa-info-circle',
        'success': 'fas fa-check-circle',
        'warning': 'fas fa-exclamation-triangle',
        'danger': 'fas fa-times-circle'
    };
    
    scannerStatus.className = `alert alert-${type}`;
    scannerStatus.innerHTML = `
        <i class="${iconMap[type]} me-1"></i>
        ${escapeHtml(message)}
    `;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Cleanup when page unloads
window.addEventListener('beforeunload', function() {
    if (scannerActive && html5QrCode) {
        html5QrCode.stop().catch(console.error);
    }
});

// Handle visibility change (tab switching)
document.addEventListener('visibilitychange', function() {
    if (document.hidden && scannerActive) {
        // Pause scanning when tab is not visible
        stopScanning();
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', function(event) {
    // Space bar to start/stop scanning
    if (event.code === 'Space' && !event.target.matches('input, textarea')) {
        event.preventDefault();
        if (scannerActive) {
            stopScanning();
        } else {
            startScanning();
        }
    }
    
    // Escape to stop scanning
    if (event.code === 'Escape' && scannerActive) {
        stopScanning();
    }
});

// Auto-focus file input when clicking upload area
document.addEventListener('click', function(event) {
    if (event.target.closest('.file-upload-trigger')) {
        qrFileInput.click();
    }
});
