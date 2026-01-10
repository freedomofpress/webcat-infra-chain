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
    const submitBtn = document.getElementById('submitBtn');

    const domain = domainInput.value.trim();

    if (!domain) {
        showStatus('error', 'Please enter a domain');
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
            body: JSON.stringify({ domain })
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


// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Fetch CSRF token
    fetchCSRFToken();

    // Load oracle endpoints
    loadOracles();

    // Set up form submission
    document.getElementById('enrollmentForm').addEventListener('submit', handleSubmit);
});
