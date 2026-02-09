# WEBCAT whiskers

A simple web application frontend for submitting domain enrollment requests to Felidae oracles on the WEBCAT network.

## Setup

### Prerequisites

- Node.js (v22 or higher)
- npm or yarn

### Installation

1. Install dependencies:
```bash
npm install
```

### Configuration

The application should be configured via environment variables:

- `BIND_ADDRESS`: Server bind address in `host:port` format (default: `127.0.0.1:3000`)
  - Examples: `127.0.0.1:3000`, `0.0.0.0:8080`, `[::1]:3000` (IPv6)
- `CHAIN_API_URL`: URL of the felidae query API (default: `http://localhost:8080`)
- `ALLOWED_ORIGIN`: CORS allowed origin (default: `*`)
- `ORACLE_ENDPOINTS`: JSON-encoded custom oracleEndpoints (default: `null`; oracles will be fetched from chain API )

It's also possible to provide a `config.json` file, rather than env vars.

```bash
cp config.json.example config.json
# Edit config.json with your oracle endpoints
```

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

## Deployment

There's a container image available at [ghcr.io/freedomofpress/whiskers](http://ghcr.io/freedomofpress/whiskers).
See example deployment manifests in [`examples/`](./examples/).

## What's with the name?

The app provides a frontend to WEBCAT, and whiskers are on the front end of a cat.

## License

AGPLv3
