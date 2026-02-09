const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();

// Parse bind address (host:port format) using URL parser
function parseBindAddress(addr) {
  const defaultHost = '127.0.0.1';
  const defaultPort = 3000;

  if (!addr) {
    return { host: defaultHost, port: defaultPort };
  }

  try {
    const url = new URL(`http://${addr}`);
    return {
      host: url.hostname || defaultHost,
      port: url.port ? parseInt(url.port, 10) : defaultPort
    };
  } catch {
    console.error(`Invalid bind address: ${addr}`);
    process.exit(1);
  }
}

const bindAddress = parseBindAddress(process.env.BIND_ADDRESS);

// CSRF protection - simple token-based implementation
const CSRF_SECRET = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');
const CSRF_COOKIE_NAME = '_csrf';
const CSRF_HEADER_NAME = 'x-csrf-token';

// Generate CSRF token
function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

// CSRF middleware
function csrfProtection(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }

  const token = req.headers[CSRF_HEADER_NAME] || req.body._csrf;
  const cookieToken = req.cookies[CSRF_COOKIE_NAME];

  if (!token || !cookieToken || token !== cookieToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  next();
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  credentials: true
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Validate that each oracle entry has a well-formed endpoint URL.
// Normalizes each endpoint to end with '/' so that relative URL resolution
// via new URL('path', base) appends correctly.
function validateOracleEndpoints(oracles, source) {
  for (const oracle of oracles) {
    if (!oracle.endpoint) {
      console.error(`Oracle entry from ${source} is missing 'endpoint' field`);
      process.exit(1);
    }
    try {
      new URL(oracle.endpoint);
    } catch {
      console.error(`Invalid oracle endpoint URL from ${source}: ${oracle.endpoint}`);
      process.exit(1);
    }
    if (!oracle.endpoint.endsWith('/')) {
      oracle.endpoint += '/';
    }
  }
  return oracles;
}

// Load configuration.
// Precedence (highest to lowest): env vars > config.json > defaults.
let config = {
  chainApiUrl: 'http://localhost:8080',
  oracleEndpoints: null // Will be loaded from config file, env var, or chain API
};

// 1. Load config.json as base layer, if present.
const configPath = path.join(__dirname, 'config.json');
if (fs.existsSync(configPath)) {
  try {
    const configFile = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    if (configFile.chainApiUrl) {
      config.chainApiUrl = configFile.chainApiUrl;
    }
    if (configFile.oracleEndpoints && Array.isArray(configFile.oracleEndpoints)) {
      config.oracleEndpoints = validateOracleEndpoints(configFile.oracleEndpoints, 'config.json');
    }
    console.log('Loaded config from config.json');
  } catch (error) {
    console.warn('Failed to load config.json:', error.message);
  }
}

// 2. Env vars override config.json values.
if (process.env.CHAIN_API_URL) {
  config.chainApiUrl = process.env.CHAIN_API_URL;
}

// Validate and normalize chainApiUrl with trailing slash for correct
// relative URL resolution via new URL('path', base).
try {
  new URL(config.chainApiUrl);
} catch {
  console.error(`Invalid CHAIN_API_URL: ${config.chainApiUrl}`);
  process.exit(1);
}
if (!config.chainApiUrl.endsWith('/')) {
  config.chainApiUrl += '/';
}

if (process.env.ORACLE_ENDPOINTS) {
  try {
    const envOracles = JSON.parse(process.env.ORACLE_ENDPOINTS);
    if (Array.isArray(envOracles)) {
      config.oracleEndpoints = validateOracleEndpoints(envOracles, 'ORACLE_ENDPOINTS env var');
      console.log(`Loaded ${config.oracleEndpoints.length} oracle endpoints from ORACLE_ENDPOINTS env var`);
    } else {
      console.error('ORACLE_ENDPOINTS env var must be a JSON array');
      process.exit(1);
    }
  } catch (error) {
    console.error('Failed to parse ORACLE_ENDPOINTS env var:', error.message);
    process.exit(1);
  }
}

if (config.oracleEndpoints) {
  console.log(`Configured ${config.oracleEndpoints.length} oracle endpoints`);
}

// Helper function to fetch oracle endpoints from chain API
async function fetchOracleEndpoints() {
  try {
    const response = await axios.get(new URL('/oracles', config.chainApiUrl).href, {
      timeout: 5000
    });
    if (response.data && Array.isArray(response.data)) {
      const oracles = response.data.map(oracle => ({
        endpoint: oracle.endpoint,
        identity: oracle.identity
      }));
      validateOracleEndpoints(oracles, 'chain API');
      return oracles;
    }
  } catch (error) {
    console.error('Failed to fetch oracle endpoints from chain API:', error.message);
  }
  return null;
}

// Get CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
  const token = generateCSRFToken();
  res.cookie(CSRF_COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000 // 1 hour
  });
  res.json({ csrfToken: token });
});

// Get oracle endpoints
app.get('/api/oracles', async (req, res) => {
  try {
    let oracles = config.oracleEndpoints;

    // If not configured, try to fetch from chain API
    if (!oracles) {
      oracles = await fetchOracleEndpoints();
      if (oracles) {
        config.oracleEndpoints = oracles;
      }
    }

    if (!oracles || oracles.length === 0) {
      return res.status(503).json({
        error: 'No oracle endpoints configured. Set ORACLE_ENDPOINTS env var, configure config.json, or ensure chain API is accessible.'
      });
    }

    res.json({ oracles });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get PoW challenge from all oracles (each oracle has its own secret)
app.get('/api/pow-challenge', async (req, res) => {
  const { domain } = req.query;

  if (!domain || typeof domain !== 'string') {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  // Get oracle endpoints
  let oracles = config.oracleEndpoints;
  if (!oracles) {
    oracles = await fetchOracleEndpoints();
    if (!oracles || oracles.length === 0) {
      return res.status(503).json({
        error: 'No oracle endpoints available. Please configure oracle endpoints.'
      });
    }
    config.oracleEndpoints = oracles;
  }

  // Request challenge from each oracle (each has its own secret)
  const challengePromises = oracles.map(async (oracle) => {
    const challengeUrl = new URL(`pow-challenge?domain=${encodeURIComponent(domain)}`, oracle.endpoint);

    try {
      const response = await axios.get(challengeUrl, {
        timeout: 5000,
        headers: {
          'Content-Type': 'application/json'
        }
      });

      return {
        endpoint: oracle.endpoint,
        success: true,
        challenge: response.data.challenge,
        timestamp: response.data.timestamp,
        difficulty: response.data.difficulty
      };
    } catch (error) {
      return {
        endpoint: oracle.endpoint,
        success: false,
        error: error.response?.data?.message || error.message || 'Failed to get PoW challenge'
      };
    }
  });

  const results = await Promise.allSettled(challengePromises);
  const challenges = results.map((result, index) => {
    if (result.status === 'fulfilled') {
      return result.value;
    } else {
      return {
        endpoint: oracles[index]?.endpoint || 'unknown',
        success: false,
        error: result.reason?.message || 'Unknown error'
      };
    }
  });

  // Return challenges for all oracles
  res.json({ challenges });
});

// Submit observation to all oracles
app.post('/api/submit', csrfProtection, async (req, res) => {
  const { domain, powTokens } = req.body;

  // Validate input
  if (!domain || typeof domain !== 'string') {
    return res.status(400).json({ error: 'Domain is required' });
  }

  // Normalize domain (ensure it ends with a dot for FQDN format)
  const normalizedDomain = domain.trim().endsWith('.') ? domain.trim() : domain.trim() + '.';

  // Get oracle endpoints
  let oracles = config.oracleEndpoints;
  if (!oracles) {
    oracles = await fetchOracleEndpoints();
    if (!oracles || oracles.length === 0) {
      return res.status(503).json({
        error: 'No oracle endpoints available. Please configure oracle endpoints.'
      });
    }
    config.oracleEndpoints = oracles;
  }

  // powTokens should be a map: { endpoint: powToken }
  // For backward compatibility, also accept single powToken
  const powTokenMap = powTokens || (req.body.powToken ? { [oracles[0].endpoint]: req.body.powToken } : {});

  // Submit to each oracle endpoint with its corresponding PoW token
  const results = await Promise.allSettled(
    oracles.map(async (oracle) => {
      const endpoint = oracle.endpoint;
      const url = new URL('observe', endpoint);

      // Get the PoW token for this specific oracle
      const powToken = powTokenMap[endpoint];

      // Prepare request body
      const requestBody = {
        domain: normalizedDomain
      };
      if (powToken) {
        requestBody.pow_token = powToken;
      }

      try {
        const response = await axios.post(
          url,
          requestBody,
          {
            timeout: 30000, // 30 second timeout
            headers: {
              'Content-Type': 'application/json'
            }
          }
        );

        return {
          endpoint,
          success: true,
          status: response.status,
          data: response.data
        };
      } catch (error) {
        return {
          endpoint,
          success: false,
          status: error.response?.status || 'N/A',
          error: error.response?.data?.message || error.response?.data?.error || error.message
        };
      }
    })
  );

  // Format results
  const formattedResults = results.map((result, index) => {
    if (result.status === 'fulfilled') {
      return result.value;
    } else {
      return {
        endpoint: oracles[index]?.endpoint || 'unknown',
        success: false,
        status: 'N/A',
        error: result.reason?.message || 'Unknown error'
      };
    }
  });

  const successCount = formattedResults.filter(r => r.success).length;
  const totalCount = formattedResults.length;

  res.json({
    success: successCount > 0,
    submitted: successCount,
    total: totalCount,
    results: formattedResults
  });
});

// Serve the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(bindAddress.port, bindAddress.host, () => {
  console.log(`Frontend server running on http://${bindAddress.host}:${bindAddress.port}`);
  console.log(`Chain API URL: ${config.chainApiUrl}`);
  if (!config.oracleEndpoints) {
    console.log('Oracle endpoints will be fetched from chain API');
  }
});
