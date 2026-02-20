# AML Registry Backend

FastAPI backend for Anti-Money Laundering transaction analysis and blockchain integration.

## Features

- 📊 **Transaction Graph Analysis** using NetworkX
- 🔍 **Money Mule Detection** (circular routing patterns)
- 💰 **Smurfing Detection** (fan-in/fan-out patterns)
- 🏢 **Shell Network Detection** (dormant intermediary chains)
- 🔐 **Privacy-Preserving Hashing** (SHA-256)
- ⛓️ **Algorand Blockchain Integration** (smart contract calls)

## Setup

### Prerequisites
- Python 3.12+
- pip or poetry

### Installation

```powershell
# Navigate to backend folder
cd backend

# Install dependencies
pip install -r requirements.txt
```

### Running the Server

```powershell
# Development mode (auto-reload)
python main.py

# Or using uvicorn directly
uvicorn main:app --reload --port 8000
```

The API will be available at: `http://localhost:8000`

API Documentation: `http://localhost:8000/docs`

## API Endpoints

### Health Check
```
GET /health
```

### Analyze Transactions
```
POST /analyze
Content-Type: multipart/form-data
Body: CSV file

Returns: Mule rings, smurfing accounts, risk scores, graph data
```

### Hash Customer Identity
```
POST /hash
Content-Type: application/json
Body: {
  "customer_id": "string",
  "name": "string" (optional),
  "ssn": "string" (optional)
}

Returns: SHA-256 hash for blockchain storage
```

### Flag Account to Blockchain
```
POST /flag-to-blockchain
Content-Type: application/json
Body: {
  "hashed_id": "string",
  "risk_score": integer (0-100),
  "transaction_count": integer,
  "flagged_connections": integer
}
```

### Query Wallet Status
```
GET /query-wallet/{hashed_id}

Returns: Flagged status and risk score
```

## Testing with Sample Data

```powershell
# Test with provided sample CSV
curl -X POST http://localhost:8000/analyze -F "file=@sample_transactions.csv"
```

## CSV Format

Required columns:
- `transaction_id` - Unique transaction identifier
- `sender_id` - Source account ID (becomes a node)
- `receiver_id` - Destination account ID (becomes a node)
- `amount` - Transaction amount in currency units
- `timestamp` - Transaction timestamp (Format: YYYY-MM-DD HH:MM:SS)

Example:
```csv
transaction_id,sender_id,receiver_id,amount,timestamp
TXN_1001,ACC_USER_01,ACC_USER_05,45.50,2026-02-19 09:00:15
TXN_1002,ACC_USER_05,ACC_USER_08,42.00,2026-02-19 09:05:22
```

## Detection Algorithms

### 1. Money Mule Rings (Circular Routing)
- Detects cycles of length 3-5 nodes
- Pattern: A → B → C → A
- Risk: +40 points

### 2. Smurfing
- Many small deposits → one large withdrawal
- Pattern: 10+ incoming, 1-2 outgoing
- Risk: +30 points

### 3. Shell Networks
- Long chains with dormant intermediaries
- Pattern: A → B → C → D → E (B, C, D minimal activity)
- Risk: +20 points

## Tech Stack

- **FastAPI** - Modern Python web framework
- **NetworkX** - Graph analysis
- **pandas** - Data processing
- **Algorand Python SDK** - Blockchain integration
- **Pydantic** - Data validation

## Next Steps

- [ ] Integrate Algorand SDK for real blockchain transactions
- [ ] Add authentication/authorization
- [ ] Deploy to Railway/Render
- [ ] Add database for transaction history
- [ ] Implement WebSocket for real-time updates
