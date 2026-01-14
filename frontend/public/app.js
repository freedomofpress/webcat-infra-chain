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

// Request PoW challenge from server
async function requestPoWChallenge(domain) {
    try {
        const response = await fetch(`/api/pow-challenge?domain=${encodeURIComponent(domain)}`);
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to get PoW challenge');
        }
        return await response.json();
    } catch (error) {
        console.error('PoW challenge request failed:', error);
        throw error;
    }
}

// Compute SHA-256 hash
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Count leading zero bits in a hex string
function countLeadingZeros(hex) {
    let count = 0;
    for (let i = 0; i < hex.length; i += 2) {
        const byte = parseInt(hex.substr(i, 2), 16);
        if (byte === 0) {
            count += 8;
        } else {
            // Count leading zeros in this byte
            // Convert to binary and count leading zeros
            const binary = byte.toString(2).padStart(8, '0');
            let leadingZeros = 0;
            for (let j = 0; j < binary.length; j++) {
                if (binary[j] === '0') {
                    leadingZeros++;
                } else {
                    break;
                }
            }
            count += leadingZeros;
            break;
        }
    }
    return count;
}

async function computePoW(challenge, difficulty, onProgress) {
    let nonce = 0;
    const startTime = Date.now();
    const maxAttempts = 10000000; // Safety limit
    let lastProgressUpdate = 0;

    while (nonce < maxAttempts) {
        const hashInput = challenge + nonce.toString();
        const hash = await sha256(hashInput);
        const leadingZeros = countLeadingZeros(hash);

        // Update progress every 1000 attempts
        if (nonce % 1000 === 0 && onProgress) {
            const elapsed = Date.now() - startTime;
            onProgress(nonce, elapsed);
            // Yield to browser to prevent blocking
            await new Promise(resolve => setTimeout(resolve, 0));
        }

        if (leadingZeros >= difficulty) {
            const elapsed = Date.now() - startTime;
            console.log(`PoW solved in ${elapsed}ms with nonce ${nonce} (${nonce} attempts, hash: ${hash.substring(0, 32)}...)`);
            console.log(`Leading zeros: ${leadingZeros}, required: ${difficulty}`);
            return { nonce, hash };
        }

        // Log every 10000 attempts for debugging
        if (nonce > 0 && nonce % 10000 === 0) {
            console.log(`PoW progress: ${nonce} attempts, ${Math.round((Date.now() - startTime) / 1000)}s, best leading zeros so far: ${leadingZeros}`);
        }

        nonce++;
    }

    throw new Error('PoW computation exceeded maximum attempts');
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
    submitBtn.textContent = 'Requesting challenge...';

    try {
        // Ensure we have a CSRF token
        if (!csrfToken) {
            await fetchCSRFToken();
        }

        // Request PoW challenge
        submitBtn.textContent = 'Getting challenge...';
        let challengeData;
        try {
            challengeData = await requestPoWChallenge(domain);
            console.log('Received challenge:', challengeData);
        } catch (error) {
            console.error('Failed to get PoW challenge:', error);
            throw new Error(`Failed to get PoW challenge: ${error.message}. Is the oracle server running?`);
        }

        if (!challengeData || !challengeData.challenge || !challengeData.difficulty) {
            throw new Error('Invalid challenge response from server');
        }

        // Compute PoW
        submitBtn.textContent = 'Computing proof of work...';
        showStatus('info', `Computing proof of work (difficulty: ${challengeData.difficulty}, this may take a few seconds)...`);

        console.log(`Starting PoW computation: challenge=${challengeData.challenge.substring(0, 16)}..., difficulty=${challengeData.difficulty}`);
        const powStartTime = Date.now();

        const powResult = await computePoW(
            challengeData.challenge,
            challengeData.difficulty,
            (attempts, elapsed) => {
                // Update button text with progress
                submitBtn.textContent = `Computing PoW... (${attempts} attempts, ${Math.round(elapsed / 1000)}s)`;
            }
        );

        const powElapsed = Date.now() - powStartTime;
        console.log(`PoW computation completed in ${powElapsed}ms`);

        // Create PoW token
        const powToken = {
            challenge: challengeData.challenge,
            nonce: powResult.nonce,
            timestamp: challengeData.timestamp
        };

        console.log('PoW token created:', { challenge: powToken.challenge.substring(0, 16) + '...', nonce: powToken.nonce, timestamp: powToken.timestamp });

        // Submit with PoW token
        submitBtn.textContent = 'Submitting...';
        hideStatus();

        const response = await fetch('/api/submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify({ domain, powToken })
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
