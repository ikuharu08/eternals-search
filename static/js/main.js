let deviceModal = null;
let statusPollingInterval = null;
let currentPage = 1;
const PER_PAGE = 100;
let historyCurrentPage = 1;
const HISTORY_PER_PAGE = 100;

// Wrap all event listeners in DOMContentLoaded
document.addEventListener('DOMContentLoaded', async function() {
    try {
        const response = await fetch('/api/users/current');
        if (response.status === 401) {
            console.warn('User is not authenticated');
            return;
        }
        if (!response.ok) {
            throw new Error('Network response was not ok ' + response.statusText);
        }
        const user = await response.json();
        document.getElementById('userName').textContent = user.username;
        if (user.profile_pic) {
            const avatar = document.getElementById('userAvatar');
            avatar.src = user.profile_pic;
            avatar.onerror = function() {
                this.src = '/static/img/default-avatar.png';
            };
        }
    } catch (error) {
        console.error('Error loading user:', error);
    }

    // Initialize other components
    initThemeToggle();
    initScanControls();

    // Inisialisasi modal
    const modalElement = document.getElementById('deviceModal');
    if (modalElement) {
        deviceModal = new bootstrap.Modal(modalElement);
    }

    initSearchFeatures();
});

// Get cookie helper
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// Logout function
async function logout() {
    try {
        document.cookie = "token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
        window.location.href = '/login';
    } catch (error) {
        console.error('Error during logout:', error);
    }
}

// Theme toggle
function initThemeToggle() {
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-bs-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-bs-theme', newTheme);
            
            // Update icon
            const icon = this.querySelector('i');
            icon.className = newTheme === 'dark' ? 'bi bi-moon-stars' : 'bi bi-sun';
        });
    }
}

// Initialize scan controls
function initScanControls() {
    // Load saved theme
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-bs-theme', savedTheme);
    const icon = document.querySelector('#themeToggle i');
    icon.className = savedTheme === 'dark' ? 'bi bi-sun' : 'bi bi-moon-stars';
    
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
            scan_type: selectedRadio.value
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
            if (!ipRange || !ipRange.value.trim()) {
                alert('Please enter IP ranges');
                return;
            }
            config.ip_range = ipRange.value;
        }
        
        // Disable start button
        const startButton = document.getElementById('startScanBtn');
        startButton.disabled = true;
        
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
                startButton.disabled = false;  // Re-enable if error
            } else {
                if (!statusPollingInterval) {
                    statusPollingInterval = setInterval(updateStatus, 2000);
                }
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Failed to start scan');
            startButton.disabled = false;  // Re-enable if error
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
}

function updateStatus() {
    fetch('/api/status')
        .then(response => {
            if (response.status === 401) {
                console.warn('User is not authenticated');
                clearInterval(statusPollingInterval);
                statusPollingInterval = null;
                return;
            }
            if (!response.ok) {
                throw new Error('Network response was not ok ' + response.statusText);
            }
            return response.json();
        })
        .then(data => {
            if (data) {
                const statusElement = document.getElementById('scanStatus');
                const detailsElement = document.getElementById('scanDetails');
                const startButton = document.getElementById('startScanBtn');
                const progressBar = document.getElementById('scanProgress');
                
                if (!statusElement || !detailsElement || !startButton || !progressBar) {
                    console.warn('Some status elements not found');
                    return;
                }

                statusElement.textContent = data.status;
                startButton.disabled = data.is_scanning;
                
                if (data.is_scanning) {
                    statusElement.classList.add('text-primary');
                    if (data.start_time) {
                        const startTime = new Date(data.start_time);
                        const duration = Math.floor((new Date() - startTime) / 1000);
                        detailsElement.textContent = 
                            `Running for ${duration}s - Found ${data.discovered_devices} devices`;
                        
                        const progress = Math.min(
                            (data.discovered_devices / (data.total_devices || 1)) * 100, 
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
                    if (data.discovered_devices > 0) {
                        detailsElement.textContent = 
                            `Last scan found ${data.discovered_devices} devices`;
                        progressBar.style.width = '100%';
                        progressBar.textContent = '100%';
                    } else {
                        detailsElement.textContent = '';
                        progressBar.style.width = '0%';
                        progressBar.textContent = '0%';
                    }
                }
                
                updateControlButtons(data);
            }
        })
        .catch(error => {
            console.error('Error fetching status:', error);
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
    
    if (devices.length === 0) {
        // Tambahkan row untuk menampilkan pesan ketika tidak ada data
        const row = document.createElement('tr');
        row.innerHTML = `
            <td colspan="5" class="text-center py-5">
                <i class="bi bi-search display-4 text-muted"></i>
                <h5 class="mt-3">No devices found</h5>
                <p class="text-muted">Try adjusting your filters or start a new scan</p>
            </td>
        `;
        tbody.appendChild(row);
        return;
    }
    
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
    if (!deviceModal) {
        console.error('Device modal not initialized');
        return;
    }

    const detailsDiv = document.getElementById('deviceDetails');
    if (!detailsDiv) {
        console.error('Device details div not found');
        return;
    }

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

function updateScanStatus(data) {
    const progressBar = document.getElementById('scanProgress');
    const statusText = document.getElementById('scanStatus');
    const startButton = document.getElementById('startScanBtn');
    
    // Update progress bar
    progressBar.style.width = `${data.progress}%`;
    progressBar.textContent = `${data.progress}%`;
    
    // Update status
    statusText.textContent = data.status;
    statusText.className = `text-${data.status === 'scanning' ? 'primary' : 'secondary'}`;
    
    // Disable/enable start button
    startButton.disabled = data.status === 'scanning';
    
    // Update current IP
    const currentIpElement = document.getElementById('currentIp');
    if (currentIpElement) {
        currentIpElement.textContent = data.current_ip || 'N/A';
    }
    
    // Update scan details
    const detailsElement = document.getElementById('scanDetails');
    if (detailsElement) {
        if (data.status === 'scanning') {
            const duration = Math.floor((new Date() - new Date(data.start_time)) / 1000);
            detailsElement.textContent = 
                `Running for ${duration}s - Scanned ${data.completed_ips}/${data.total_ips} IPs`;
        } else {
            detailsElement.textContent = '';
        }
    }
}

async function pollScanStatus() {
    try {
        document.getElementById('startScanBtn').disabled = true;
        const response = await fetch('/api/status');
        const data = await response.json();
        
        updateScanStatus(data);
        
        if (data.status === 'scanning') {
            setTimeout(pollScanStatus, 1000);  // Poll every second
        } else {
            document.getElementById('startScanBtn').disabled = false;
        }
    } catch (error) {
        console.error('Error fetching scan status:', error);
        document.getElementById('startScanBtn').disabled = false;
    }
}

// Start polling when page loads
document.addEventListener('DOMContentLoaded', pollScanStatus);

async function fetchHistory() {
    try {
        const params = new URLSearchParams({
            page: historyCurrentPage,
            per_page: HISTORY_PER_PAGE
        });

        const response = await fetch(`/api/history?${params.toString()}`);
        if (!response.ok) throw new Error('Failed to fetch history');
        
        const data = await response.json();
        updateHistoryTable(data.items);
        updateHistoryPagination(data.pagination);
    } catch (error) {
        console.error('Error fetching history:', error);
        alert('Failed to load history');
    }
}

function updateHistoryTable(items) {
    const tbody = document.getElementById('historyTableBody');
    if (!tbody) return;

    tbody.innerHTML = '';
    
    if (items.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" class="text-center py-5">
                    <i class="bi bi-clock-history display-4 text-muted"></i>
                    <h5 class="mt-3">No history found</h5>
                </td>
            </tr>
        `;
        return;
    }

    items.forEach(item => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${item.ip}</td>
            <td>${item.port}</td>
            <td><div class="banner-text">${item.banner || '-'}</div></td>
            <td>${new Date(item.timestamp).toLocaleString()}</td>
        `;
        tbody.appendChild(row);
    });
}

function updateHistoryPagination(pagination) {
    const paginationElement = document.getElementById('historyPagination');
    if (!paginationElement) return;

    let html = '<nav><ul class="pagination justify-content-center">';
    
    // Previous button
    html += `
        <li class="page-item ${pagination.page <= 1 ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${pagination.page - 1}">Previous</a>
        </li>
    `;
    
    // Page numbers
    for (let i = 1; i <= pagination.total_pages; i++) {
        if (
            i === 1 || // First page
            i === pagination.total_pages || // Last page
            (i >= pagination.page - 2 && i <= pagination.page + 2) // Pages around current
        ) {
            html += `
                <li class="page-item ${i === pagination.page ? 'active' : ''}">
                    <a class="page-link" href="#" data-page="${i}">${i}</a>
                </li>
            `;
        } else if (
            i === pagination.page - 3 ||
            i === pagination.page + 3
        ) {
            html += '<li class="page-item disabled"><span class="page-link">...</span></li>';
        }
    }
    
    // Next button
    html += `
        <li class="page-item ${pagination.page >= pagination.total_pages ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${pagination.page + 1}">Next</a>
        </li>
    `;
    
    html += '</ul></nav>';
    
    // Add pagination info
    html += `
        <div class="text-center mt-2">
            <small class="text-muted">
                Showing ${(pagination.page - 1) * pagination.per_page + 1} 
                to ${Math.min(pagination.page * pagination.per_page, pagination.total_items)} 
                of ${pagination.total_items} entries
            </small>
        </div>
    `;
    
    paginationElement.innerHTML = html;
    
    // Add click handlers
    paginationElement.querySelectorAll('.page-link').forEach(link => {
        link.addEventListener('click', async (e) => {
            e.preventDefault();
            const newPage = parseInt(e.target.dataset.page);
            if (!isNaN(newPage) && newPage !== pagination.page) {
                historyCurrentPage = newPage;
                await fetchHistory();
                // Scroll back to top of results
                document.getElementById('historyTableBody')?.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
}

// Call this function when loading history tab
function initHistory() {
    historyCurrentPage = 1;
    fetchHistory();
}

function updateStartButtonState() {
    const startButton = document.getElementById('startScanBtn');
    const selectedRadio = document.querySelector('input[name="scanType"]:checked');
    
    if (!selectedRadio) {
        startButton.disabled = true;
        return;
    }

    if (selectedRadio.value === 'country') {
        const countrySelect = document.getElementById('countryCode');
        startButton.disabled = !countrySelect || countrySelect.selectedOptions.length === 0;
    } else {
        const ipRange = document.getElementById('ipRange');
        startButton.disabled = !ipRange || !ipRange.value.trim();
    }
}

// Event listeners untuk input fields
document.getElementById('countryCode')?.addEventListener('change', updateStartButtonState);
document.getElementById('ipRange')?.addEventListener('input', updateStartButtonState);
document.querySelectorAll('input[name="scanType"]').forEach(radio => {
    radio.addEventListener('change', updateStartButtonState);
});

// Update button state saat halaman load
document.addEventListener('DOMContentLoaded', updateStartButtonState);

// Search functionality
function initSearchFeatures() {
    const searchForm = document.getElementById('searchForm');
    if (!searchForm) return;

    searchForm.addEventListener('submit', handleSearch);
}

async function handleSearch(e) {
    e.preventDefault();
    currentPage = 1;  // Reset ke halaman pertama saat search baru
    await fetchSearchResults();
}

async function fetchSearchResults() {
    const query = document.getElementById('searchQuery')?.value;
    const port = document.getElementById('searchPort')?.value;
    const banner = document.getElementById('searchBanner')?.value;
    
    // Build query parameters
    const params = new URLSearchParams();
    if (query) params.append('query', query);
    if (port) params.append('port', port);
    if (banner) params.append('banner', banner);
    params.append('page', currentPage);
    params.append('per_page', PER_PAGE);
    
    try {
        const response = await fetch(`/api/search?${params.toString()}`);
        if (!response.ok) throw new Error('Search failed');
        
        const data = await response.json();
        updateSearchResults(data.items);
        updatePagination(data.pagination);
    } catch (error) {
        console.error('Search error:', error);
        alert('Failed to perform search');
    }
}

function updateSearchResults(results) {
    const tbody = document.getElementById('searchResults');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (results.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center py-5">
                    <i class="bi bi-search display-4 text-muted"></i>
                    <h5 class="mt-3">No results found</h5>
                    <p class="text-muted">Try different search terms</p>
                </td>
            </tr>
        `;
        return;
    }
    
    results.forEach(result => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${result.ip}</td>
            <td>${result.port}</td>
            <td><div class="banner-text">${result.banner || '-'}</div></td>
            <td>${new Date(result.timestamp).toLocaleString()}</td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-info view-details" 
                            data-device='${JSON.stringify(result)}'>
                        <i class="bi bi-info-circle"></i>
                    </button>
                    <button class="btn btn-sm btn-warning rescan-device" 
                            data-ip="${result.ip}" data-port="${result.port}">
                        <i class="bi bi-arrow-repeat"></i>
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });
    
    attachSearchResultEventListeners();
}

function attachSearchResultEventListeners() {
    // Attach view details listeners
    document.querySelectorAll('.view-details').forEach(btn => {
        btn.addEventListener('click', () => {
            const device = JSON.parse(btn.dataset.device);
            showDeviceDetails(device);
        });
    });
    
    // Attach rescan listeners
    document.querySelectorAll('.rescan-device').forEach(btn => {
        btn.addEventListener('click', () => {
            const ip = btn.dataset.ip;
            const port = btn.dataset.port;
            rescanDevice(ip, port);
        });
    });
}

function updatePagination(pagination) {
    const paginationElement = document.getElementById('searchPagination');
    if (!paginationElement) return;

    let html = '<nav><ul class="pagination justify-content-center">';
    
    // Previous button
    html += `
        <li class="page-item ${pagination.page <= 1 ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${pagination.page - 1}">Previous</a>
        </li>
    `;
    
    // Page numbers
    for (let i = 1; i <= pagination.total_pages; i++) {
        if (
            i === 1 || // First page
            i === pagination.total_pages || // Last page
            (i >= pagination.page - 2 && i <= pagination.page + 2) // Pages around current
        ) {
            html += `
                <li class="page-item ${i === pagination.page ? 'active' : ''}">
                    <a class="page-link" href="#" data-page="${i}">${i}</a>
                </li>
            `;
        } else if (
            i === pagination.page - 3 ||
            i === pagination.page + 3
        ) {
            html += '<li class="page-item disabled"><span class="page-link">...</span></li>';
        }
    }
    
    // Next button
    html += `
        <li class="page-item ${pagination.page >= pagination.total_pages ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${pagination.page + 1}">Next</a>
        </li>
    `;
    
    html += '</ul></nav>';
    
    // Add pagination info
    html += `
        <div class="text-center mt-2">
            <small class="text-muted">
                Showing ${(pagination.page - 1) * pagination.per_page + 1} 
                to ${Math.min(pagination.page * pagination.per_page, pagination.total_items)} 
                of ${pagination.total_items} entries
            </small>
        </div>
    `;
    
    paginationElement.innerHTML = html;
    
    // Add click handlers
    paginationElement.querySelectorAll('.page-link').forEach(link => {
        link.addEventListener('click', async (e) => {
            e.preventDefault();
            const newPage = parseInt(e.target.dataset.page);
            if (!isNaN(newPage) && newPage !== pagination.page) {
                currentPage = newPage;
                await fetchSearchResults();
                // Scroll back to top of results
                document.getElementById('searchResults')?.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
} 