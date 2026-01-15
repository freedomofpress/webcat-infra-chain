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

// Request PoW challenges from all oracles
async function requestPoWChallenges(domain) {
    try {
        const response = await fetch(`/api/pow-challenge?domain=${encodeURIComponent(domain)}`);
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to get PoW challenges');
        }
        const data = await response.json();
        if (!data.challenges || !Array.isArray(data.challenges)) {
            throw new Error('Invalid challenges response from server');
        }
        return data.challenges;
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
        const byte = parseInt(hex.substring(i, i + 2), 16);
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

        // Request PoW challenges from all oracles
        submitBtn.textContent = 'Getting challenges...';
        let challenges;
        try {
            challenges = await requestPoWChallenges(domain);
            console.log('Received challenges:', challenges);
        } catch (error) {
            console.error('Failed to get PoW challenges:', error);
            throw new Error(`Failed to get PoW challenges: ${error.message}. Are the oracle servers running?`);
        }

        // Filter to only successful challenges
        const validChallenges = challenges.filter(c => c.success);
        if (validChallenges.length === 0) {
            const errors = challenges.map(c => `${c.endpoint}: ${c.error || 'Unknown error'}`).join('; ');
            throw new Error(`Failed to get valid challenges from any oracle: ${errors}`);
        }

        // Compute PoW for each challenge
        submitBtn.textContent = `Computing proof of work (${validChallenges.length} oracles)...`;
        const difficulty = validChallenges[0].difficulty; // Assume all have same difficulty for user output
        showStatus('info', `Computing proof of work for ${validChallenges.length} oracles (difficulty: ${difficulty}, this may take a while)...`);

        const powTokens = {};
        let completed = 0;
        const totalChallenges = validChallenges.length;

        // Compute PoW for each challenge (we do sequentially to show progress)
        for (const challengeData of validChallenges) {
            if (!challengeData.challenge || !challengeData.difficulty || !challengeData.timestamp) {
                console.warn(`Skipping invalid challenge from ${challengeData.endpoint}`);
                continue;
            }

            submitBtn.textContent = `Computing PoW for oracle ${completed + 1}/${totalChallenges}...`;
            console.log(`Starting PoW computation for ${challengeData.endpoint}: challenge=${challengeData.challenge.substring(0, 16)}..., difficulty=${challengeData.difficulty}`);
            const powStartTime = Date.now();

            try {
                const powResult = await computePoW(
                    challengeData.challenge,
                    challengeData.difficulty,
                    (attempts, elapsed) => {
                        // Update button text with progress
                        submitBtn.textContent = `Computing PoW ${completed + 1}/${totalChallenges}... (${attempts} attempts, ${Math.round(elapsed / 1000)}s)`;
                    }
                );

                const powElapsed = Date.now() - powStartTime;
                console.log(`PoW computation for ${challengeData.endpoint} completed in ${powElapsed}ms`);

                // Create PoW token for this oracle
                powTokens[challengeData.endpoint] = {
                    challenge: challengeData.challenge,
                    nonce: powResult.nonce,
                    timestamp: challengeData.timestamp
                };

                completed++;
                console.log(`PoW token created for ${challengeData.endpoint}:`, {
                    challenge: powTokens[challengeData.endpoint].challenge.substring(0, 16) + '...',
                    nonce: powTokens[challengeData.endpoint].nonce,
                    timestamp: powTokens[challengeData.endpoint].timestamp
                });
            } catch (error) {
                console.error(`Failed to compute PoW for ${challengeData.endpoint}:`, error);
                // Continue with other oracles
            }
        }

        if (Object.keys(powTokens).length === 0) {
            throw new Error('Failed to compute PoW for any oracle');
        }

        // Submit with PoW tokens
        submitBtn.textContent = 'Submitting...';
        hideStatus();

        const response = await fetch('/api/submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify({ domain, powTokens })
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
