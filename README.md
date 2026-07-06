# SBPDCL Bills Fetching API

Flask API for fetching SBPDCL electricity bill PDFs by CA number.

## What it does

This service accepts a CA number, encrypts the request payload in the format expected by the SBPDCL backend, downloads the PDF bill, and returns it as a file response.

## Features

- Single HTTP endpoint for bill retrieval
- Runtime fetch of the SBPDCL RSA public key
- AES + RSA encrypted request payload generation
- Direct PDF response with a friendly download name

## Requirements

- Python 3.10 or newer
- pip

Python dependencies are listed in [requirements.txt](requirements.txt).

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run locally

Start the Flask app with:

```bash
python api/index.py
```

By default, Flask will listen on `http://127.0.0.1:5000` when run in development mode.

## API

### `GET /api/get-sbpdcl-bill`

Query parameters:

- `ca` - the SBPDCL consumer account number

Example:

```bash
curl -L "http://127.0.0.1:5000/api/get-sbpdcl-bill?ca=1234567890" -o SBPDCL_1234567890.pdf
```

Response:

- `200 OK` with `application/pdf` when the bill is found
- `400 Bad Request` when `ca` is missing
- `500 Internal Server Error` when the upstream request or encryption flow fails

## Implementation notes

- The service fetches the upstream SBPDCL configuration endpoint at request time to obtain the RSA public key.
- The bill payload is encrypted using a random 32-byte AES key and 16-byte IV.
- The encrypted AES key is then wrapped with the upstream RSA public key.

## Security and usage notes

- This code depends on an external SBPDCL endpoint that may change without notice.
- The API should be treated as a thin proxy over the upstream service and not as a stable public contract.
- The endpoint returns a PDF file directly; if you need JSON metadata, add a separate response mode instead of changing the existing behavior.

## Project structure

```text
.
├── api/
│   └── index.py
├── README.md
├── docs/
│   └── API.md
└── requirements.txt
```

## Next steps

Consider adding a production WSGI entrypoint, request timeouts, and tests around payload generation if this service will be deployed publicly.