# WEBCAT whiskers

A simple web application frontend for submitting domain enrollment requests to Felidae oracles on the WEBCAT network.

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

- `BIND_ADDRESS`: Server bind address in `host:port` format (default: `127.0.0.1:3000`)
  - Examples: `127.0.0.1:3000`, `0.0.0.0:8080`, `[::1]:3000` (IPv6)
- `CHAIN_API_URL`: URL of the felidae query API (default: `http://localhost`)
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

The application will be available at `http://localhost:3000` (or your configured bind address).

## Oracle Endpoint Format

Oracle endpoints in `config.json` should be full URLs:

```json
{
  "oracleEndpoints": [
    {
      "endpoint": "http://127.0.0.1:8080",
      "identity": "04b92e..."
    },
    {
      "endpoint": "https://oracle.example.com:8443",
      "identity": "04a1c3..."
    }
  ]
}
```

The application appends `/observe` or `/pow-challenge` paths as needed.

### What's with the name?

The app provides a frontend to WEBCAT, and whiskers are on the front end of a cat.
