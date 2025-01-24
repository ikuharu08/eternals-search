let deviceModal = null;
let statusPollingInterval = null;

// Wrap all event listeners in DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
    // Load saved theme
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-bs-theme', savedTheme);
    const icon = document.querySelector('#themeToggle i');
    icon.className = savedTheme === 'dark' ? 'bi bi-sun' : 'bi bi-moon-stars';
    
    // Initialize deviceModal
    const deviceModal = new bootstrap.Modal(document.getElementById('deviceModal'));
    
    // Initialize event listeners only if elements exist
    const initializeEventListener = (elementId, event, handler) => {
        const element = document.getElementById(elementId);
        if (element) {
            element.addEventListener(event, handler);
        } else {
            console.warn(`Element with id '${elementId}' not found`);
        }
    };

    // Theme toggle
    initializeEventListener('themeToggle', 'click', () => {
        const html = document.documentElement;
        const isDark = html.getAttribute('data-bs-theme') === 'dark';
        html.setAttribute('data-bs-theme', isDark ? 'light' : 'dark');
        
        const icon = document.querySelector('#themeToggle i');
        if (icon) {
            icon.className = isDark ? 'bi bi-moon-stars' : 'bi bi-sun';
        }
        
        localStorage.setItem('theme', isDark ? 'light' : 'dark');
    });

    // Export button
    initializeEventListener('exportCsvBtn', 'click', () => {
        window.location.href = '/api/export?format=csv';
    });

    // Filter handlers
    initializeEventListener('ipFilter', 'input', loadDevices);
    initializeEventListener('portFilter', 'change', loadDevices);
    initializeEventListener('sortBy', 'change', loadDevices);
    initializeEventListener('refreshBtn', 'click', loadDevices);

    // Scan type radio buttons
    const scanTypeRadios = document.querySelectorAll('input[name="scanType"]');
    if (scanTypeRadios.length > 0) {
        scanTypeRadios.forEach(radio => {
            radio.addEventListener('change', updateScanType);
        });
    }

    // Country selection
    initializeEventListener('countryCode', 'change', function() {
        updatePreview();
        const countryCode = this.value;
        if (!countryCode) return;
        
        fetch(`/api/country/${countryCode}/ranges`)
            .then(response => response.json())
            .then(ranges => {
                window.selectedCountryRanges = ranges;
                const rangeInfo = document.getElementById('rangeInfo');
                if (rangeInfo) {
                    rangeInfo.textContent = `Selected country has ${ranges.length} IP ranges`;
                }
            })
            .catch(error => {
                console.error('Error fetching ranges:', error);
                alert('Failed to fetch IP ranges for selected country');
            });
    });

    // IP Range and Exclude IPs inputs
    initializeEventListener('ipRange', 'input', updatePreview);
    initializeEventListener('excludeIps', 'input', updatePreview);

    // Control buttons
    initializeEventListener('startScanBtn', 'click', () => {
        const selectedRadio = document.querySelector('input[name="scanType"]:checked');
        if (!selectedRadio) return;

        const config = {
            scan_type: selectedRadio.value,
            port_range: document.getElementById('portRange')?.value || '1-1000',
            speed: document.getElementById('scanSpeed')?.value || 'normal'
        };
        
        if (config.scan_type === 'country') {
            const countrySelect = document.getElementById('countryCode');
            if (!countrySelect) return;

            const selectedCountries = Array.from(countrySelect.selectedOptions)
                .map(opt => opt.value);
                
            if (selectedCountries.length === 0) {
                alert('Please select at least one country');
                return;
            }
            
            config.country_codes = selectedCountries;
        } else {
            const ipRange = document.getElementById('ipRange');
            if (!ipRange) return;
            config.ip_range = ipRange.value;
        }
        
        fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(config)
        })
        .then(response => response.json())
        .then(data => {
            if (!data.success) {
                alert(data.message);
            } else {
                if (!statusPollingInterval) {
                    statusPollingInterval = setInterval(updateStatus, 2000);
                }
            }
        });
    });

    // Pause/Resume button
    initializeEventListener('pauseResumeBtn', 'click', function() {
        const action = this.textContent.toLowerCase();
        fetch(`/api/scan/${action}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateStatus();
            }
        });
    });

    // Stop button
    initializeEventListener('stopScanBtn', 'click', function() {
        if (confirm('Are you sure you want to stop the current scan?')) {
            fetch('/api/scan/stop', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateStatus();
                }
            });
        }
    });

    // Load initial data
    loadDevices();
    loadCountries();
    updateStatus();
});

function updateStatus() {
    fetch('/api/status')
        .then(response => response.json())
        .then(status => {
            const statusElement = document.getElementById('scanStatus');
            const detailsElement = document.getElementById('scanDetails');
            const startButton = document.getElementById('startScanBtn');
            const progressBar = document.getElementById('scanProgress');
            
            if (!statusElement || !detailsElement || !startButton || !progressBar) {
                console.warn('Some status elements not found');
                return;
            }

            statusElement.textContent = status.status;
            startButton.disabled = status.is_scanning;
            
            if (status.is_scanning) {
                statusElement.classList.add('text-primary');
                if (status.start_time) {
                    const startTime = new Date(status.start_time);
                    const duration = Math.floor((new Date() - startTime) / 1000);
                    detailsElement.textContent = 
                        `Running for ${duration}s - Found ${status.discovered_devices} devices`;
                    
                    const progress = Math.min(
                        (status.discovered_devices / (status.total_devices || 1)) * 100, 
                        100
                    );
                    progressBar.style.width = `${progress}%`;
                    progressBar.textContent = `${Math.round(progress)}%`;
                }
            } else {
                if (statusPollingInterval) {
                    clearInterval(statusPollingInterval);
                    statusPollingInterval = null;
                }
                
                statusElement.classList.remove('text-primary');
                if (status.discovered_devices > 0) {
                    detailsElement.textContent = 
                        `Last scan found ${status.discovered_devices} devices`;
                    progressBar.style.width = '100%';
                    progressBar.textContent = '100%';
                } else {
                    detailsElement.textContent = '';
                    progressBar.style.width = '0%';
                    progressBar.textContent = '0%';
                }
            }
            
            updateControlButtons(status);
        });
}

function loadDevices() {
    const ipFilter = document.getElementById('ipFilter').value;
    const portFilter = document.getElementById('portFilter').value;
    const sortBy = document.getElementById('sortBy').value;
    
    let url = '/api/devices';
    const params = new URLSearchParams();
    if (ipFilter) params.append('ip', ipFilter);
    if (portFilter) params.append('port', portFilter);
    if (sortBy) params.append('sort', sortBy);
    
    if (params.toString()) {
        url += '?' + params.toString();
    }
    
    fetch(url)
        .then(response => response.json())
        .then(devices => {
            updateDevicesList(devices);
            updateScanHistory();
        });
}

function updateDevicesList(devices) {
    const tbody = document.getElementById('devicesList');
    tbody.innerHTML = '';
    
    devices.forEach(device => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${device.ip}</td>
            <td>${device.port}</td>
            <td><div class="banner-text">${device.banner}</div></td>
            <td>${new Date(device.timestamp).toLocaleString()}</td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-info view-details" 
                            data-device='${JSON.stringify(device)}'>
                        <i class="bi bi-info-circle"></i>
                    </button>
                    <button class="btn btn-sm btn-warning rescan-device" 
                            data-ip="${device.ip}" data-port="${device.port}">
                        <i class="bi bi-arrow-repeat"></i>
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });
    
    // Add event listeners
    document.querySelectorAll('.view-details').forEach(btn => {
        btn.addEventListener('click', () => {
            const device = JSON.parse(btn.dataset.device);
            showDeviceDetails(device);
        });
    });
    
    document.querySelectorAll('.rescan-device').forEach(btn => {
        btn.addEventListener('click', () => {
            const ip = btn.dataset.ip;
            const port = btn.dataset.port;
            rescanDevice(ip, port);
        });
    });
}

function updateScanHistory() {
    fetch('/api/scan/history')
        .then(response => response.json())
        .then(history => {
            const container = document.getElementById('scanHistoryContent');
            
            // Create chart data
            const ctx = document.createElement('canvas');
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: history.map(h => new Date(h.timestamp).toLocaleTimeString()),
                    datasets: [{
                        label: 'Devices Found',
                        data: history.map(h => h.devices_found),
                        borderColor: 'rgb(75, 192, 192)',
                        tension: 0.1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
            
            container.innerHTML = '';
            container.appendChild(ctx);
        });
}

function rescanDevice(ip, port) {
    fetch('/api/scan/device', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip, port })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            loadDevices();
        }
    });
}

function showDeviceDetails(device) {
    const detailsDiv = document.getElementById('deviceDetails');
    detailsDiv.innerHTML = `
        <div class="mb-3">
            <h6>IP Address:</h6>
            <p>${device.ip}</p>
        </div>
        <div class="mb-3">
            <h6>Port:</h6>
            <p>${device.port}</p>
        </div>
        <div class="mb-3">
            <h6>Banner:</h6>
            <pre class="bg-light p-2">${device.banner}</pre>
        </div>
        <div class="mb-3">
            <h6>Last Seen:</h6>
            <p>${new Date(device.timestamp).toLocaleString()}</p>
        </div>
    `;
    deviceModal.show();
}

function loadCountries() {
    fetch('/api/countries')
        .then(response => response.json())
        .then(countries => {
            const select = document.getElementById('countryCode');
            select.innerHTML = countries.map(country => 
                `<option value="${country.code}">${country.name}</option>`
            ).join('');
        })
        .catch(error => {
            console.error('Error loading countries:', error);
            document.getElementById('countryCode').innerHTML = 
                '<option value="">Error loading countries</option>';
        });
}

function updateScanType() {
    const scanType = document.querySelector('input[name="scanType"]:checked').value;
    const countrySelect = document.getElementById('countrySelect');
    const customRanges = document.getElementById('customRanges');
    
    if (scanType === 'country') {
        countrySelect.classList.remove('d-none');
        customRanges.classList.add('d-none');
    } else {
        countrySelect.classList.add('d-none');
        customRanges.classList.remove('d-none');
    }
}

function updatePreview() {
    const scanType = document.querySelector('input[name="scanType"]:checked').value;
    let ranges = [];
    
    if (scanType === 'country') {
        const selected = Array.from(document.getElementById('countryCode').selectedOptions);
        if (selected.length === 0) return;
        
        // Fetch ranges for selected countries
        Promise.all(selected.map(opt => 
            fetch(`/api/country/${opt.value}/ranges`).then(r => r.json())
        )).then(results => {
            ranges = results.flat();
            fetchPreview(ranges);
        });
    } else {
        ranges = document.getElementById('ipRange').value.split('\n');
        fetchPreview(ranges);
    }
}

function fetchPreview(ranges) {
    const excludeRanges = document.getElementById('excludeIps').value.split('\n');
    
    fetch('/api/preview', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ranges, exclude_ranges: excludeRanges })
    })
    .then(response => response.json())
    .then(preview => {
        document.getElementById('previewCard').classList.remove('d-none');
        document.getElementById('previewRangeCount').textContent = preview.range_count;
        document.getElementById('previewTotalIps').textContent = preview.total_ips.toLocaleString();
        document.getElementById('previewEstTime').textContent = preview.estimated_time;
    });
}

function updateControlButtons(status) {
    const startButton = document.getElementById('startScanBtn');
    const pauseResumeButton = document.getElementById('pauseResumeBtn');
    const stopButton = document.getElementById('stopScanBtn');

    if (status.is_scanning) {
        startButton.classList.add('d-none');
        pauseResumeButton.classList.remove('d-none');
        stopButton.classList.remove('d-none');
        
        // Update pause/resume button text
        if (status.is_paused) {
            pauseResumeButton.textContent = 'Resume';
            pauseResumeButton.classList.replace('btn-warning', 'btn-success');
        } else {
            pauseResumeButton.textContent = 'Pause';
            pauseResumeButton.classList.replace('btn-success', 'btn-warning');
        }
    } else {
        startButton.classList.remove('d-none');
        pauseResumeButton.classList.add('d-none');
        stopButton.classList.add('d-none');
    }
} 