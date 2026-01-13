class SubARGUI {
    constructor() {
        this.socket = null;
        this.currentScanId = null;
        this.results = new Map();
        this.initialize();
    }

    async initialize() {
        // Initialize socket connection
        this.initSocket();
        
        // Set up event listeners
        this.setupEventListeners();
        
        // Load initial data
        await this.loadToolStatus();
        await this.loadRecentScans();
        
        // Update connection status periodically
        setInterval(() => this.updateConnectionStatus(), 5000);
    }

    initSocket() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            this.showNotification('Connected to server', 'success');
            document.getElementById('connection-status').textContent = 'Connected';
            document.getElementById('connection-status').className = 'connected';
        });
        
        this.socket.on('disconnect', () => {
            this.showNotification('Disconnected from server', 'error');
            document.getElementById('connection-status').textContent = 'Disconnected';
            document.getElementById('connection-status').className = '';
        });
        
        this.socket.on('scan_update', (data) => {
            this.updateScanProgress(data);
        });
        
        this.socket.on('new_result', (data) => {
            this.addLiveResult(data);
        });
        
        this.socket.on('scan_complete', (data) => {
            this.handleScanComplete(data);
        });
        
        this.socket.on('scan_error', (data) => {
            this.handleScanError(data);
        });
    }

    setupEventListeners() {
        // Tab switching
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tab = e.target.dataset.tab;
                this.switchTab(tab);
            });
        });
        
        // Format selection
        document.querySelectorAll('.format-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.format-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
            });
        });
        
        // Start scan button
        document.getElementById('start-scan').addEventListener('click', () => {
            this.startScan();
        });
        
        // File input
        document.getElementById('target-list').addEventListener('change', (e) => {
            this.handleFileUpload(e);
        });
        
        // Modal close
        document.querySelector('.close-modal').addEventListener('click', () => {
            this.closeModal();
        });
        
        // Close modal when clicking outside
        document.getElementById('results-modal').addEventListener('click', (e) => {
            if (e.target.id === 'results-modal') {
                this.closeModal();
            }
        });
        
        // Download button
        document.getElementById('download-btn').addEventListener('click', () => {
            this.downloadResults();
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'Enter') {
                this.startScan();
            }
            if (e.key === 'Escape') {
                this.closeModal();
            }
        });
    }

    switchTab(tab) {
        // Update active tab button
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tab);
        });
        
        // Show corresponding tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `${tab}-tab`);
        });
    }

    async loadToolStatus() {
        try {
            const response = await fetch('/api/installed_tools');
            const tools = await response.json();
            this.displayToolStatus(tools);
        } catch (error) {
            console.error('Failed to load tool status:', error);
        }
    }

    displayToolStatus(tools) {
        const container = document.getElementById('tool-status');
        container.innerHTML = '';
        
        Object.entries(tools).forEach(([tool, installed]) => {
            const toolElement = document.createElement('div');
            toolElement.className = `tool-item ${installed ? 'installed' : 'not-installed'}`;
            
            toolElement.innerHTML = `
                <div class="tool-name">${tool}</div>
                <div class="tool-status-icon">
                    <i class="fas fa-${installed ? 'check-circle' : 'times-circle'}"></i>
                </div>
                <div class="tool-status-text">${installed ? 'Installed' : 'Missing'}</div>
            `;
            
            container.appendChild(toolElement);
        });
    }

    async loadRecentScans() {
        try {
            const response = await fetch('/api/results');
            const scans = await response.json();
            this.displayRecentScans(scans);
            
            // Update stats
            document.getElementById('total-scans').textContent = scans.length;
            const totalSubdomains = scans.reduce((sum, scan) => sum + (scan.total || 0), 0);
            document.getElementById('total-subdomains').textContent = totalSubdomains;
        } catch (error) {
            console.error('Failed to load recent scans:', error);
        }
    }

    displayRecentScans(scans) {
        const container = document.getElementById('recent-scans');
        
        if (scans.length === 0) {
            container.innerHTML = `
                <div class="empty-results">
                    <i class="fas fa-inbox"></i>
                    <p>No recent scans found</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = scans.map(scan => `
            <div class="scan-item" data-filename="${scan.filename}">
                <div class="scan-item-header">
                    <div class="scan-domain">${scan.filename}</div>
                    <div class="scan-status completed">Completed</div>
                </div>
                <div class="scan-info">
                    <div class="scan-date">${new Date(scan.created).toLocaleDateString()}</div>
                    <div class="scan-size">${this.formatFileSize(scan.size)}</div>
                </div>
            </div>
        `).join('');
        
        // Add click listeners
        container.querySelectorAll('.scan-item').forEach(item => {
            item.addEventListener('click', () => {
                const filename = item.dataset.filename;
                this.viewResults(filename);
            });
        });
    }

    async startScan() {
        const targetInput = document.getElementById('target');
        const fileInput = document.getElementById('target-list');
        const filenameInput = document.getElementById('filename');
        const formatBtn = document.querySelector('.format-btn.active');
        
        let target = targetInput.value.trim();
        let targetList = null;
        let format = formatBtn?.dataset.format || 'txt';
        let filename = filenameInput.value.trim() || null;
        
        // Validate input
        const isSingleTab = document.getElementById('single-tab').classList.contains('active');
        
        if (isSingleTab) {
            if (!target) {
                this.showNotification('Please enter a target domain', 'error');
                targetInput.focus();
                return;
            }
            
            if (!this.isValidDomain(target)) {
                this.showNotification('Please enter a valid domain', 'error');
                targetInput.focus();
                return;
            }
        } else {
            if (!fileInput.files.length) {
                this.showNotification('Please select a domain list file', 'error');
                return;
            }
            targetList = await this.readFile(fileInput.files[0]);
            target = 'multiple_domains'; // Placeholder
        }
        
        // Disable start button
        const startBtn = document.getElementById('start-scan');
        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';
        
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    target: isSingleTab ? target : null,
                    target_list: !isSingleTab ? targetList : null,
                    output_format: format,
                    filename: filename
                })
            });
            
            const data = await response.json();
            this.currentScanId = data.scan_id;
            
            this.showNotification('Scan started successfully', 'success');
            this.initializeScanProgress();
            
        } catch (error) {
            this.showNotification('Failed to start scan: ' + error.message, 'error');
            console.error('Start scan error:', error);
        } finally {
            // Re-enable start button
            startBtn.disabled = false;
            startBtn.innerHTML = '<i class="fas fa-play"></i> Start Enumeration';
        }
    }

    initializeScanProgress() {
        const progressContainer = document.getElementById('scan-progress');
        progressContainer.innerHTML = `
            <div class="scan-progress">
                <div class="progress-header">
                    <h3>Scan in Progress</h3>
                    <div class="scan-id">ID: ${this.currentScanId.substring(0, 8)}...</div>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="progress-fill" style="width: 0%"></div>
                </div>
                <div class="progress-info">
                    <div class="current-tool" id="current-tool">Initializing...</div>
                    <div class="progress-percent" id="progress-percent">0%</div>
                </div>
                <div class="scan-stats">
                    <div class="subdomain-count">Subdomains found: <span id="subdomain-count">0</span></div>
                </div>
            </div>
        `;
        
        // Clear live results
        document.getElementById('live-results').innerHTML = `
            <table class="results-table">
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>Tool</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody id="results-table-body"></tbody>
            </table>
        `;
        
        this.results.clear();
    }

    updateScanProgress(data) {
        if (data.scan_id !== this.currentScanId) return;
        
        const progressFill = document.getElementById('progress-fill');
        const progressPercent = document.getElementById('progress-percent');
        const currentTool = document.getElementById('current-tool');
        
        if (progressFill && progressPercent && currentTool) {
            progressFill.style.width = `${data.progress}%`;
            progressPercent.textContent = `${Math.round(data.progress)}%`;
            currentTool.textContent = data.current_tool || 'Processing...';
        }
    }

    addLiveResult(data) {
        if (data.scan_id !== this.currentScanId) return;
        
        const tableBody = document.getElementById('results-table-body');
        if (!tableBody) return;
        
        // Update count
        const countElement = document.getElementById('subdomain-count');
        if (countElement) {
            const currentCount = parseInt(countElement.textContent) || 0;
            countElement.textContent = currentCount + 1;
        }
        
        // Add to results map for deduplication
        if (!this.results.has(data.subdomain)) {
            this.results.set(data.subdomain, {
                tool: data.tool,
                time: new Date().toLocaleTimeString()
            });
            
            // Add to table
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="subdomain">${data.subdomain}</td>
                <td class="tool">${data.tool}</td>
                <td class="time">${new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</td>
            `;
            tableBody.appendChild(row);
            
            // Scroll to bottom
            tableBody.parentElement.parentElement.scrollTop = tableBody.parentElement.parentElement.scrollHeight;
        }
    }

    handleScanComplete(data) {
        if (data.scan_id !== this.currentScanId) return;
        
        this.showNotification(`Scan completed! Found ${data.total_subdomains} subdomains`, 'success');
        
        // Update progress to 100%
        const progressFill = document.getElementById('progress-fill');
        const progressPercent = document.getElementById('progress-percent');
        const currentTool = document.getElementById('current-tool');
        
        if (progressFill && progressPercent && currentTool) {
            progressFill.style.width = '100%';
            progressPercent.textContent = '100%';
            currentTool.textContent = 'Scan completed';
        }
        
        // Reload recent scans
        this.loadRecentScans();
        
        // Show results modal after delay
        setTimeout(() => {
            this.showResultsModal(data);
        }, 1000);
    }

    handleScanError(data) {
        if (data.scan_id !== this.currentScanId) return;
        
        this.showNotification(`Scan failed: ${data.error}`, 'error');
        
        const progressContainer = document.getElementById('scan-progress');
        if (progressContainer) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'scan-error';
            errorDiv.innerHTML = `
                <div class="error-message">
                    <i class="fas fa-exclamation-triangle"></i>
                    Scan failed: ${data.error}
                </div>
            `;
            progressContainer.appendChild(errorDiv);
        }
    }

    showResultsModal(data) {
        const modal = document.getElementById('results-modal');
        const modalResults = document.getElementById('modal-results');
        
        modalResults.innerHTML = `
            <div class="scan-summary">
                <h3><i class="fas fa-trophy"></i> Scan Summary</h3>
                <div class="summary-grid">
                    <div class="summary-item">
                        <div class="summary-label">Target</div>
                        <div class="summary-value">${data.scan_id ? data.scan_id.substring(0, 8) + '...' : 'Unknown'}</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-label">Total Subdomains</div>
                        <div class="summary-value neon-text">${data.total_subdomains || 0}</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-label">Output File</div>
                        <div class="summary-value">${data.output_file || 'N/A'}</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-label">Status</div>
                        <div class="summary-value success-text">Completed</div>
                    </div>
                </div>
            </div>
            
            <div class="quick-actions">
                <h3><i class="fas fa-bolt"></i> Quick Actions</h3>
                <div class="action-buttons">
                    <button class="action-btn" onclick="subargUI.downloadResults()">
                        <i class="fas fa-download"></i> Download Results
                    </button>
                    <button class="action-btn" onclick="subargUI.startNewScan()">
                        <i class="fas fa-redo"></i> Start New Scan
                    </button>
                    <button class="action-btn" onclick="subargUI.viewAllResults()">
                        <i class="fas fa-list"></i> View All Results
                    </button>
                </div>
            </div>
            
            <div class="top-subdomains">
                <h3><i class="fas fa-crown"></i> Top Subdomains Found</h3>
                <div class="subdomain-list">
                    ${Array.from(this.results.keys()).slice(0, 10).map(sub => `
                        <div class="subdomain-item">
                            <i class="fas fa-link"></i> ${sub}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
        
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }

    closeModal() {
        const modal = document.getElementById('results-modal');
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }

    async downloadResults() {
        if (!this.currentScanId) return;
        
        try {
            // Get scan info to find filename
            const response = await fetch(`/api/scan/${this.currentScanId}`);
            const scanInfo = await response.json();
            
            if (scanInfo.output_file) {
                window.open(`/api/download/${scanInfo.output_file}`, '_blank');
                this.showNotification('Download started', 'success');
            }
        } catch (error) {
            this.showNotification('Failed to download results', 'error');
        }
    }

    async viewResults(filename) {
        window.open(`/api/download/${filename}`, '_blank');
    }

    showNotification(message, type = 'info') {
        const container = document.getElementById('notification-container');
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                ${message}
            </div>
        `;
        
        container.appendChild(notification);
        
        // Remove after animation completes
        setTimeout(() => {
            if (notification.parentNode === container) {
                container.removeChild(notification);
            }
        }, 3000);
    }

    async readFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(e);
            reader.readAsText(file);
        });
    }

    isValidDomain(domain) {
        const pattern = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i;
        return pattern.test(domain);
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    updateConnectionStatus() {
        if (this.socket && this.socket.connected) {
            document.getElementById('connection-status').textContent = 'Connected';
            document.getElementById('connection-status').className = 'connected';
        } else {
            document.getElementById('connection-status').textContent = 'Disconnected';
            document.getElementById('connection-status').className = '';
        }
    }

    startNewScan() {
        this.closeModal();
        // Reset form and focus on target input
        document.getElementById('target').value = '';
        document.getElementById('target').focus();
    }

    viewAllResults() {
        this.closeModal();
        // Scroll to recent scans section
        document.getElementById('recent-scans').scrollIntoView({ behavior: 'smooth' });
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.subargUI = new SubARGUI();
});
