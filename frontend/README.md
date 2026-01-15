# WEBCAT Frontend

A simple web application for submitting domain enrollment requests to the oracle network.

## Setup

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn

### Installation

1. Install dependencies:
```bash
npm install
```

2. (Optional) Configure oracle endpoints in `config.json`:
```bash
cp config.json.example config.json
# Edit config.json with your oracle endpoints
```

If `config.json` is not provided, the application will attempt to fetch oracle endpoints from the felidae query API at `/oracles`.

### Configuration

The application can be configured via environment variables:

- `PORT`: Server port (default: 3000)
- `CHAIN_API_URL`: URL of the felidae query API (default: `http://localhost`)
- `ORACLE_PORT`: Port for oracle endpoints (default: 8080)
- `ORACLE_PROTOCOL`: Protocol for oracle endpoints (default: `http`)
- `ALLOWED_ORIGIN`: CORS allowed origin (default: `*`)

### Running

Start the server:
```bash
npm start
```

For development with auto-reload:
```bash
npm run dev
```

The application will be available at `http://localhost:3000` (or your configured port).

## Oracle Endpoint Format

Oracle endpoints should be configured as either:
- IP addresses (e.g., `127.0.0.1`)
- Domain names (e.g., `oracle.example.com`)

The application will construct the full URL as:
`{ORACLE_PROTOCOL}://{endpoint}:{ORACLE_PORT}/observe`

For example, with defaults:
- `http://127.0.0.1:8080/observe`
- `http://oracle.example.com:8080/observe`
