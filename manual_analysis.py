"""
Manual analysis of test.csv to generate expected output
This helps verify backend accuracy by comparing with known patterns
"""

import pandas as pd
from collections import defaultdict

# Read the CSV
df = pd.read_csv(r"c:\Users\Admin\OneDrive\Desktop\test.csv")

# Count transactions per account
account_txn_count = defaultdict(int)
account_connections = defaultdict(set)

for _, row in df.iterrows():
    sender = row['sender_id']
    receiver = row['receiver_id']
    
    account_txn_count[sender] += 1
    account_txn_count[receiver] += 1
    
    account_connections[sender].add(receiver)
    account_connections[receiver].add(sender)

print("=" * 80)
print("TRANSACTION COUNTS PER ACCOUNT")
print("=" * 80)
for account in sorted(account_txn_count.keys()):
    count = account_txn_count[account]
    if count >= 3:  # Only show accounts with 3+ transactions
        print(f"{account}: {count} transactions, {len(account_connections[account])} connections")

print("\n" + "=" * 80)
print("DETECTED PATTERNS")
print("=" * 80)

# Pattern 1: Mule Ring Detection (3-cycle)
print("\n1. MULE RING (3-cycle): ACC_MULE_A → ACC_MULE_B → ACC_MULE_C → ACC_MULE_A")
print("   - ACC_MULE_A: 2 transactions")
print("   - ACC_MULE_B: 2 transactions")
print("   - ACC_MULE_C: 2 transactions")
print("   Risk: +40 (cycle detection)")

# Pattern 2: Mule Ring Detection (4-cycle)
print("\n2. MULE RING (4-cycle): ACC_RING_1 → ACC_RING_2 → ACC_RING_3 → ACC_RING_4 → ACC_RING_1")
print("   - ACC_RING_1: 2 transactions")
print("   - ACC_RING_2: 2 transactions")
print("   - ACC_RING_3: 2 transactions")
print("   - ACC_RING_4: 2 transactions")
print("   Risk: +40 (cycle detection)")

# Pattern 3: Smurfing Detection (fan-in)
print("\n3. SMURFING (fan-in): ACC_KINGPIN_Z receives from 10 accounts")
smurf_accounts = [f"ACC_SMURF_{i:02d}" for i in range(1, 11)]
print(f"   - ACC_KINGPIN_Z: {len(account_connections['ACC_KINGPIN_Z'])} incoming connections")
print(f"   - From: {', '.join(smurf_accounts[:3])} ... {smurf_accounts[-1]}")
print("   Risk: +25 (smurfing)")

# Pattern 4: High Velocity Detection (≥8 transactions)
print("\n4. HIGH VELOCITY ACCOUNTS (≥8 transactions):")
high_velocity = [(acc, count) for acc, count in account_txn_count.items() 
                 if count >= 8 and not acc.startswith('ACC_SHOP') and not acc.startswith('ACC_SUPPLIER')]
for acc, count in sorted(high_velocity, key=lambda x: x[1], reverse=True):
    print(f"   - {acc}: {count} transactions (+10 risk)")

print("\n" + "=" * 80)
print("EXPECTED OUTPUT FORMAT")
print("=" * 80)

# Calculate which accounts should be flagged after false positive controls
# Rule: Must have ≥2 patterns AND risk_score ≥60

suspicious = {}

# Mule ring accounts (1 pattern each, risk 40)
for acc in ['ACC_MULE_A', 'ACC_MULE_B', 'ACC_MULE_C']:
    suspicious[acc] = {
        'patterns': ['mule_ring'],
        'risk': 40,
        'txn_count': account_txn_count[acc],
        'connections': len(account_connections[acc])
    }

# Ring accounts (1 pattern each, risk 40)
for acc in ['ACC_RING_1', 'ACC_RING_2', 'ACC_RING_3', 'ACC_RING_4']:
    suspicious[acc] = {
        'patterns': ['mule_ring'],
        'risk': 40,
        'txn_count': account_txn_count[acc],
        'connections': len(account_connections[acc])
    }

# Kingpin (1 pattern: smurfing, risk 25)
suspicious['ACC_KINGPIN_Z'] = {
    'patterns': ['smurfing'],
    'risk': 25,
    'txn_count': account_txn_count['ACC_KINGPIN_Z'],
    'connections': len(account_connections['ACC_KINGPIN_Z'])
}

# Check for high velocity on flagged accounts
for acc in suspicious.keys():
    if account_txn_count[acc] >= 8:
        suspicious[acc]['patterns'].append('high_velocity')
        suspicious[acc]['risk'] += 10

# Check user accounts for multiple patterns
for acc, count in account_txn_count.items():
    if acc.startswith('ACC_USER_'):
        patterns = []
        risk = 0
        
        if count >= 8:
            patterns.append('high_velocity')
            risk += 10
        
        # Check if in any detected cycles or chains
        # (would need graph analysis for this)
        
        if patterns and acc not in suspicious:
            suspicious[acc] = {
                'patterns': patterns,
                'risk': risk,
                'txn_count': count,
                'connections': len(account_connections[acc])
            }

print("\nAccounts after pattern detection:")
for acc, data in sorted(suspicious.items()):
    print(f"{acc}: {data['patterns']}, risk={data['risk']}, txn={data['txn_count']}, conn={data['connections']}")

print("\n" + "=" * 80)
print("After FALSE POSITIVE CONTROLS (≥2 patterns AND risk ≥60):")
print("=" * 80)

final_flagged = {acc: data for acc, data in suspicious.items() 
                 if len(data['patterns']) >= 2 and data['risk'] >= 60}

if final_flagged:
    for acc, data in sorted(final_flagged.items()):
        print(f"{acc}: {data['patterns']}, risk={data['risk']}")
else:
    print("NO ACCOUNTS meet the criteria (≥2 patterns AND risk ≥60)")
    print("\nSingle-pattern accounts (filtered out by false positive controls):")
    single_pattern = {acc: data for acc, data in suspicious.items() 
                      if len(data['patterns']) == 1 or data['risk'] < 60}
    for acc, data in sorted(single_pattern.items()):
        print(f"  {acc}: {data['patterns']}, risk={data['risk']} (FILTERED)")

print("\n" + "=" * 80)
print("EXPECTED JSON OUTPUT")
print("=" * 80)

import json

expected_output = {
    "suspicious_accounts": [
        {
            "account_id": acc,
            "risk_score": data['risk'],
            "patterns_detected": data['patterns'],
            "transaction_count": data['txn_count'],
            "flagged_connections": data['connections']
        }
        for acc, data in sorted(final_flagged.items(), key=lambda x: x[1]['risk'], reverse=True)
    ],
    "fraud_rings": [
        {
            "ring_id": "RING_001",
            "accounts": ["ACC_MULE_A", "ACC_MULE_B", "ACC_MULE_C"],
            "pattern": "mule_ring",
            "transaction_count": 3
        },
        {
            "ring_id": "RING_002",
            "accounts": ["ACC_RING_1", "ACC_RING_2", "ACC_RING_3", "ACC_RING_4"],
            "pattern": "mule_ring",
            "transaction_count": 4
        },
        {
            "ring_id": "RING_003",
            "accounts": smurf_accounts + ["ACC_KINGPIN_Z"],
            "pattern": "smurfing",
            "transaction_count": 10
        }
    ],
    "summary": {
        "total_transactions_analyzed": len(df),
        "unique_accounts": len(account_txn_count),
        "suspicious_accounts_count": len(final_flagged),
        "fraud_rings_detected": 3,
        "processing_time_seconds": 0.0
    }
}

print(json.dumps(expected_output, indent=2))

print("\n" + "=" * 80)
print("COMPARISON NOTES")
print("=" * 80)
print("""
When testing the backend with test.csv, compare:

1. ✅ Fraud rings detected: Should be 3 rings
   - RING_001: 3-cycle mule ring (ACC_MULE_A/B/C)
   - RING_002: 4-cycle mule ring (ACC_RING_1/2/3/4)
   - RING_003: Smurfing network (10 smurfs → ACC_KINGPIN_Z)

2. ⚠️ Suspicious accounts flagged: Depends on false positive controls
   - If ≥2 patterns required: Might be EMPTY or minimal
   - Single-pattern accounts should be FILTERED OUT

3. ✅ Patterns detected correctly:
   - Cycle detection should find the 2 ring structures
   - Smurfing should detect ACC_KINGPIN_Z with 10 incoming
   - High velocity should detect accounts with 8+ transactions

4. ⚠️ Expected behavior with current rules:
   - Most accounts have only 1 pattern → FILTERED by false positive control
   - Need ≥2 patterns AND risk ≥60 to be flagged
   - This is CORRECT behavior to reduce false positives!
""")
