// CSRF token management
let csrfToken = '';

// Fetch CSRF token
async function fetchCSRFToken() {
    try {
        const response = await fetch('/api/csrf-token');
        const data = await response.json();
        csrfToken = data.csrfToken;
        // Set CSRF token in a hidden form field
        const form = document.getElementById('enrollmentForm');
        if (form && !form.querySelector('input[name="_csrf"]')) {
            const csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = '_csrf';
            csrfInput.value = csrfToken;
            form.appendChild(csrfInput);
        }
    } catch (error) {
        console.error('Failed to fetch CSRF token:', error);
        showStatus('error', 'Failed to initialize security token. Please refresh the page.');
    }
}

// Auto-detect zone from domain
// Zone is the registered domain under which the subdomain is enrolled
// For example: domain=testapp.nym.re, zone=nym.re (not just "re")
function detectZone(domain) {
    if (!domain || domain.trim() === '') {
        return null;
    }

    const trimmed = domain.trim();
    // Remove trailing dot if present
    const cleanDomain = trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed;

    // Split by dots
    const parts = cleanDomain.split('.');

    // Need at least 2 parts (subdomain + registered domain)
    if (parts.length < 2) {
        return null;
    }

    // If we have exactly 2 parts (e.g., "example.com"), the zone is the TLD
    // If we have more (e.g., "testapp.nym.re"), the zone is everything except the first label
    // So for "testapp.nym.re", zone should be "nym.re"
    if (parts.length === 2) {
        // Simple case: example.com -> zone is "com"
        return parts[parts.length - 1];
    } else {
        // Subdomain case: testapp.nym.re -> zone is "nym.re"
        // Take all parts except the first one
        return parts.slice(1).join('.');
    }
}

// Show status message
function showStatus(type, message) {
    const statusEl = document.getElementById('statusMessage');
    statusEl.className = `status-message ${type}`;
    statusEl.textContent = message;
    statusEl.style.display = 'block';

    // Auto-hide after 5 seconds for success/info messages
    if (type === 'success' || type === 'info') {
        setTimeout(() => {
            statusEl.style.display = 'none';
        }, 5000);
    }
}

// Hide status message
function hideStatus() {
    document.getElementById('statusMessage').style.display = 'none';
}

// Load oracle endpoints
async function loadOracles() {
    const oracleListEl = document.getElementById('oracleList');

    try {
        const response = await fetch('/api/oracles');
        const data = await response.json();

        if (data.error) {
            oracleListEl.innerHTML = `<p class="error-text">${data.error}</p>`;
            return;
        }

        if (!data.oracles || data.oracles.length === 0) {
            oracleListEl.innerHTML = '<p class="error-text">No oracle endpoints configured</p>';
            return;
        }

        oracleListEl.innerHTML = data.oracles.map(oracle => `
            <div class="oracle-item">
                <div class="endpoint">${escapeHtml(oracle.endpoint)}</div>
                ${oracle.identity ? `<div class="identity">${escapeHtml(oracle.identity)}</div>` : ''}
            </div>
        `).join('');
    } catch (error) {
        oracleListEl.innerHTML = `<p class="error-text">Failed to load oracle endpoints: ${error.message}</p>`;
    }
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Format results
function displayResults(results) {
    const resultsEl = document.getElementById('results');
    const resultsContentEl = document.getElementById('resultsContent');

    if (!results || results.length === 0) {
        resultsEl.style.display = 'none';
        return;
    }

    resultsEl.style.display = 'block';

    const summary = `
        <p style="margin-bottom: 15px; font-weight: 600;">
            Submitted to ${results.filter(r => r.success).length} of ${results.length} oracles
        </p>
    `;

    const items = results.map(result => {
        const className = result.success ? 'success' : 'error';
        const statusText = result.success
            ? `Status: ${result.status}`
            : `Error: ${result.error || 'Unknown error'}`;

        return `
            <div class="result-item ${className}">
                <div class="endpoint">${escapeHtml(result.endpoint)}</div>
                <div class="status">${escapeHtml(statusText)}</div>
            </div>
        `;
    }).join('');

    resultsContentEl.innerHTML = summary + items;
}

// Handle form submission
async function handleSubmit(event) {
    event.preventDefault();
    hideStatus();

    const domainInput = document.getElementById('domain');
    const zoneInput = document.getElementById('zone');
    const submitBtn = document.getElementById('submitBtn');

    const domain = domainInput.value.trim();
    const zone = zoneInput.value.trim();

    if (!domain || !zone) {
        showStatus('error', 'Please fill in both domain and zone fields');
        return;
    }

    // Disable submit button
    submitBtn.disabled = true;
    submitBtn.textContent = 'Submitting...';

    try {
        // Ensure we have a CSRF token
        if (!csrfToken) {
            await fetchCSRFToken();
        }

        const response = await fetch('/api/submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify({ domain, zone })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Submission failed');
        }

        if (data.success) {
            showStatus('success', `Successfully submitted to ${data.submitted} of ${data.total} oracles`);
            displayResults(data.results);
        } else {
            showStatus('error', `Failed to submit to any oracles. ${data.results?.[0]?.error || ''}`);
            displayResults(data.results);
        }
    } catch (error) {
        showStatus('error', `Submission failed: ${error.message}`);
        console.error('Submission error:', error);
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Begin Enrollment';
    }
}

// Handle auto-detect zone button
function handleDetectZone() {
    const domainInput = document.getElementById('domain');
    const zoneInput = document.getElementById('zone');
    const detectBtn = document.getElementById('detectZoneBtn');

    const domain = domainInput.value.trim();

    if (!domain) {
        showStatus('error', 'Please enter a domain first');
        domainInput.focus();
        return;
    }

    detectBtn.disabled = true;
    detectBtn.textContent = 'Detecting...';

    // Simulate a small delay for better UX
    setTimeout(() => {
        const zone = detectZone(domain);

        if (zone) {
            zoneInput.value = zone;
            showStatus('info', `Detected zone: ${zone}`);
        } else {
            showStatus('error', 'Could not detect zone. Please enter it manually.');
        }

        detectBtn.disabled = false;
        detectBtn.textContent = 'Auto-detect';
    }, 300);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Fetch CSRF token
    fetchCSRFToken();

    // Load oracle endpoints
    loadOracles();

    // Set up form submission
    document.getElementById('enrollmentForm').addEventListener('submit', handleSubmit);

    // Set up auto-detect button
    document.getElementById('detectZoneBtn').addEventListener('click', handleDetectZone);

    // Auto-detect zone when domain changes (optional, can be removed if too aggressive)
    let domainChangeTimeout;
    document.getElementById('domain').addEventListener('input', (e) => {
        clearTimeout(domainChangeTimeout);
        const zoneInput = document.getElementById('zone');
        // Only auto-detect if zone is empty
        if (!zoneInput.value.trim()) {
            domainChangeTimeout = setTimeout(() => {
                const zone = detectZone(e.target.value);
                if (zone) {
                    zoneInput.value = zone;
                }
            }, 1000); // Wait 1 second after user stops typing
        }
    });
});
