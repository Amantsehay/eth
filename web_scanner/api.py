"""
FastAPI Web Interface for Web Security Scanner
"""

import asyncio
import uuid
from datetime import datetime
from typing import Dict, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl

from .scanner import WebSecurityScanner


app = FastAPI(title="Web Security Scanner", version="1.0.0")

# In-memory storage for scan results (use Redis/DB in production)
scan_results: Dict[str, Dict] = {}


class ScanRequest(BaseModel):
    url: str
    scan_headers: bool = True
    scan_endpoints: bool = True
    scan_xss: bool = True
    scan_redirect: bool = True
    scan_sqli: bool = True
    timeout: int = 10
    verify_ssl: bool = False


class ScanStatus(BaseModel):
    scan_id: str
    status: str  # 'pending', 'running', 'completed', 'error'
    progress: str
    created_at: str
    completed_at: Optional[str] = None


def run_scan(scan_id: str, url: str, scan_headers: bool, scan_endpoints: bool,
             scan_xss: bool, scan_redirect: bool, scan_sqli: bool,
             timeout: int, verify_ssl: bool):
    """Run scan in background thread."""
    try:
        scan_results[scan_id]['status'] = 'running'
        scan_results[scan_id]['progress'] = 'Initializing scanner...'
        
        scanner = WebSecurityScanner(
            timeout=timeout,
            verify_ssl=verify_ssl,
            verbose=False,
            silent=True  # Suppress console output in API mode
        )
        
        scan_results[scan_id]['progress'] = 'Starting scan...'
        success = scanner.scan(
            url=url,
            scan_headers=scan_headers,
            scan_endpoints=scan_endpoints,
            scan_xss=scan_xss,
            scan_redirect=scan_redirect,
            scan_sqli=scan_sqli,
        )
        
        if success:
            results = scanner.get_results()
            scan_results[scan_id]['status'] = 'completed'
            scan_results[scan_id]['results'] = results
            scan_results[scan_id]['progress'] = 'Scan completed'
            scan_results[scan_id]['completed_at'] = datetime.now().isoformat()
        else:
            scan_results[scan_id]['status'] = 'error'
            scan_results[scan_id]['progress'] = 'Scan failed'
            scan_results[scan_id]['error'] = 'Scan execution failed'
            
    except Exception as e:
        scan_results[scan_id]['status'] = 'error'
        scan_results[scan_id]['progress'] = f'Error: {str(e)}'
        scan_results[scan_id]['error'] = str(e)


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main HTML interface."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Security Scanner</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: white;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border: 1px solid #ddd;
            overflow: hidden;
        }
        
        .header {
            background: white;
            color: #333;
            padding: 30px;
            text-align: center;
            border-bottom: 1px solid #ddd;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .content {
            padding: 30px;
        }
        
        .scan-form {
            background: white;
            padding: 25px;
            border: 1px solid #ddd;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }

        .form-row {
            display: flex;
            gap: 20px;
        }

        .form-row .form-group {
            margin-bottom: 0;
        }

        .form-row .form-group.url-group {
            flex: 3;
        }

        .form-row .form-group.timeout-group {
            flex: 1;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        
        input[type="url"], input[type="number"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        input[type="url"]:focus, input[type="number"]:focus {
            outline: none;
            border-color: #666;
        }
        
        .checkbox-group {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 10px;
        }
        
        .checkbox-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .checkbox-item input[type="checkbox"] {
            width: 20px;
            height: 20px;
            cursor: pointer;
        }
        
        .btn {
            background: #007bff;
            color: white;
            border: none;
            padding: 15px 40px;
            font-size: 18px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
        }
        
        .btn:hover {
            background: #0056b3;
        }
        
        .btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        
        .status-section {
            display: none;
            background: white;
            padding: 25px;
            border: 1px solid #ddd;
            margin-bottom: 30px;
        }
        
        .status-section.active {
            display: block;
        }
        
        .status-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .status-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
        }
        
        .status-badge.pending {
            background: #ffc107;
            color: #000;
        }
        
        .status-badge.running {
            background: #007bff;
            color: white;
        }
        
        .status-badge.completed {
            background: #28a745;
            color: white;
        }
        
        .status-badge.error {
            background: #dc3545;
            color: white;
        }
        
        .progress-bar {
            width: 100%;
            height: 30px;
            background: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            margin-top: 10px;
        }
        
        .progress-fill {
            height: 100%;
            background: #007bff;
            width: 0%;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            font-size: 12px;
        }
        
        .report-section {
            display: none;
        }
        
        .report-section.active {
            display: block;
        }
        
        .report-header {
            background: white;
            color: #333;
            padding: 20px;
            border-bottom: 1px solid #ddd;
        }
        
        .report-content {
            padding: 25px;
            background: white;
        }
        
        .vuln-card {
            background: #fff;
            border: 1px solid #ddd;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin-bottom: 15px;
        }
        
        .vuln-card.medium {
            border-left-color: #ffc107;
        }
        
        .vuln-card.low {
            border-left-color: #007bff;
        }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .vuln-title {
            font-weight: 600;
            font-size: 18px;
            color: #333;
        }
        
        .severity-badge {
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .severity-badge.high {
            background: #dc3545;
            color: white;
        }
        
        .severity-badge.medium {
            background: #ffc107;
            color: #000;
        }
        
        .severity-badge.low {
            background: #007bff;
            color: white;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            color: #333;
            padding: 20px;
            border: 1px solid #ddd;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
            color: #333;
        }
        
        .stat-label {
            color: #666;
            font-size: 14px;
        }
        
        .section-title {
            font-size: 1.5em;
            margin: 30px 0 15px 0;
            color: #333;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Web Security Scanner</h1>
            <p>OWASP Top 10 - Basic Security Assessment</p>
        </div>
        
        <div class="content">
            <div class="scan-form">
                <h2 style="margin-bottom: 20px;">Start Security Scan</h2>
                <form id="scanForm">
                    <div class="form-row">
                        <div class="form-group url-group">
                            <label for="url">Target URL *</label>
                            <input type="url" id="url" name="url" required 
                                   placeholder="https://example.com" value="">
                        </div>
                        <div class="form-group timeout-group">
                            <label for="timeout">Timeout (seconds)</label>
                            <input type="number" id="timeout" name="timeout" value="10" min="1" max="60">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Scan Options</label>
                        <div class="checkbox-group">
                            <div class="checkbox-item">
                                <input type="checkbox" id="scan_headers" name="scan_headers" checked>
                                <label for="scan_headers">Security Headers</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="scan_endpoints" name="scan_endpoints" checked>
                                <label for="scan_endpoints">Sensitive Files</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="scan_xss" name="scan_xss" checked>
                                <label for="scan_xss">XSS Testing</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="scan_redirect" name="scan_redirect" checked>
                                <label for="scan_redirect">Open Redirect</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="scan_sqli" name="scan_sqli" checked>
                                <label for="scan_sqli">SQL Injection (basic)</label>
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn" id="scanBtn">Start Scan</button>
                </form>
            </div>
            
            <div class="status-section" id="statusSection">
                <div class="status-header">
                    <div>
                        <h3>Scan Status</h3>
                        <p id="progressText" style="margin-top: 5px; color: #666;"></p>
                    </div>
                    <span class="status-badge" id="statusBadge">pending</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="progressFill">0%</div>
                </div>
            </div>
            
            <div class="report-section" id="reportSection">
                <div class="report-header">
                    <h2>Security Scan Report</h2>
                    <p id="reportMeta" style="margin-top: 5px; opacity: 0.9;"></p>
                </div>
                <div class="report-content" id="reportContent">
                    <!-- Report will be rendered here -->
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let currentScanId = null;
        let statusInterval = null;
        
        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const data = {
                url: formData.get('url'),
                scan_headers: formData.get('scan_headers') === 'on',
                scan_endpoints: formData.get('scan_endpoints') === 'on',
                scan_xss: formData.get('scan_xss') === 'on',
                scan_redirect: formData.get('scan_redirect') === 'on',
                scan_sqli: formData.get('scan_sqli') === 'on',
                timeout: parseInt(formData.get('timeout')) || 10,
                verify_ssl: false
            };
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                currentScanId = result.scan_id;
                
                document.getElementById('scanBtn').disabled = true;
                document.getElementById('statusSection').classList.add('active');
                document.getElementById('reportSection').classList.remove('active');
                
                startStatusPolling();
            } catch (error) {
                alert('Error starting scan: ' + error.message);
            }
        });
        
        function startStatusPolling() {
            if (statusInterval) clearInterval(statusInterval);
            
            statusInterval = setInterval(async () => {
                if (!currentScanId) return;
                
                try {
                    const response = await fetch(`/api/status/${currentScanId}`);
                    const status = await response.json();
                    
                    updateStatus(status);
                    
                    if (status.status === 'completed' || status.status === 'error') {
                        clearInterval(statusInterval);
                        document.getElementById('scanBtn').disabled = false;
                        
                        if (status.status === 'completed') {
                            loadReport(currentScanId);
                        }
                    }
                } catch (error) {
                    console.error('Error polling status:', error);
                }
            }, 1000);
        }
        
        function updateStatus(status) {
            const badge = document.getElementById('statusBadge');
            badge.textContent = status.status;
            badge.className = 'status-badge ' + status.status;
            
            document.getElementById('progressText').textContent = status.progress;
            
            const progressFill = document.getElementById('progressFill');
            if (status.status === 'running') {
                progressFill.style.width = '60%';
                progressFill.textContent = 'Scanning...';
            } else if (status.status === 'completed') {
                progressFill.style.width = '100%';
                progressFill.textContent = 'Complete';
            } else if (status.status === 'error') {
                progressFill.style.width = '100%';
                progressFill.style.background = '#dc3545';
                progressFill.textContent = 'Error';
            } else {
                progressFill.style.background = '#007bff';
            }
        }
        
        async function loadReport(scanId) {
            try {
                const response = await fetch(`/api/results/${scanId}`);
                const results = await response.json();
                
                renderReport(results);
                document.getElementById('reportSection').classList.add('active');
            } catch (error) {
                console.error('Error loading report:', error);
            }
        }
        
        function renderReport(results) {
            const summary = results.summary || {};
            const content = document.getElementById('reportContent');
            
            const meta = results.scan_info || {};
            document.getElementById('reportMeta').textContent = 
                `Target: ${meta.target_url || 'N/A'} | Scanned: ${new Date(meta.scan_timestamp || '').toLocaleString() || 'N/A'}`;
            
            let html = `
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">${summary.total_vulnerabilities || 0}</div>
                        <div class="stat-label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${summary.high_severity || 0}</div>
                        <div class="stat-label">High Severity</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${summary.medium_severity || 0}</div>
                        <div class="stat-label">Medium Severity</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${summary.low_severity || 0}</div>
                        <div class="stat-label">Low Severity</div>
                    </div>
                </div>
                
                <div style="text-align: center; margin: 20px 0;">
                    <h2 style="color: #333;">Overall Risk: <span style="color: ${getRiskColor(summary.overall_risk)}">${summary.overall_risk || 'Unknown'}</span></h2>
                </div>
            `;
            
            const vulnerabilities = summary.all_vulnerabilities || [];
            if (vulnerabilities.length > 0) {
                html += '<div class="section-title">Vulnerabilities</div>';
                vulnerabilities.forEach((vuln, index) => {
                    html += `
                        <div class="vuln-card ${vuln.severity || 'low'}">
                            <div class="vuln-header">
                                <span class="vuln-title">[${index + 1}] ${vuln.type || 'Unknown'}</span>
                                <span class="severity-badge ${vuln.severity || 'low'}">${(vuln.severity || 'low').toUpperCase()}</span>
                            </div>
                            <p style="color: #666; margin-bottom: 10px;">${vuln.description || 'N/A'}</p>
                            ${vuln.url ? `<p style="font-size: 12px; color: #999; word-break: break-all;">URL: ${vuln.url}</p>` : ''}
                        </div>
                    `;
                });
            }
            
            content.innerHTML = html;
        }
        
        function getRiskColor(risk) {
            switch(risk?.toLowerCase()) {
                case 'high': return '#dc3545';
                case 'medium': return '#ffc107';
                case 'low': return '#007bff';
                default: return '#666';
            }
        }
    </script>
</body>
</html>
    """


@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new security scan."""
    scan_id = str(uuid.uuid4())
    
    scan_results[scan_id] = {
        'scan_id': scan_id,
        'status': 'pending',
        'progress': 'Queued for scanning...',
        'created_at': datetime.now().isoformat(),
        'completed_at': None,
        'results': None,
        'error': None
    }
    
    # Run scan in background
    background_tasks.add_task(
        run_scan,
        scan_id=scan_id,
        url=request.url,
        scan_headers=request.scan_headers,
        scan_endpoints=request.scan_endpoints,
        scan_xss=request.scan_xss,
        scan_redirect=request.scan_redirect,
        scan_sqli=request.scan_sqli,
        timeout=request.timeout,
        verify_ssl=request.verify_ssl
    )
    
    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/status/{scan_id}")
async def get_status(scan_id: str):
    """Get scan status."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    result = scan_results[scan_id]
    return {
        "scan_id": scan_id,
        "status": result['status'],
        "progress": result['progress'],
        "created_at": result['created_at'],
        "completed_at": result.get('completed_at')
    }


@app.get("/api/results/{scan_id}")
async def get_results(scan_id: str):
    """Get scan results."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    result = scan_results[scan_id]
    
    if result['status'] != 'completed':
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    
    return result['results']


@app.get("/api/scans")
async def list_scans():
    """List all scans."""
    return {
        "scans": [
            {
                "scan_id": scan_id,
                "status": data['status'],
                "created_at": data['created_at'],
                "url": data.get('results', {}).get('scan_info', {}).get('target_url', 'N/A')
            }
            for scan_id, data in scan_results.items()
        ]
    }
