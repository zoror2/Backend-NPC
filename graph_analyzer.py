"""
Graph Analysis Module for Money Mule Detection
Uses NetworkX to detect suspicious transaction patterns
"""
import networkx as nx
import pandas as pd
from io import StringIO
from typing import Dict, List, Set, Any, Tuple
import time


# Trusted accounts whitelist (reduce false positives)
TRUSTED_ACCOUNTS = {
    'AMAZON', 'PAYROLL', 'GOVT_ACCOUNT', 'BANK_FEE', 
    'TAX_AUTHORITY', 'INSURANCE', 'UTILITY_COMPANY'
}


def analyze_transactions(csv_data: bytes) -> Dict[str, Any]:
    """
    Analyze transaction CSV for money mule patterns using graph analysis
    
    Detections:
    1. Circular Routing (3-5 node cycles)
    2. Smurfing (fan-in/fan-out patterns)
    3. Shell Networks (dormant intermediary chains)
    
    Args:
        csv_data: Raw CSV file bytes
        
    Returns:
        Dictionary containing:
        - suspicious_accounts: List of flagged account objects
        - fraud_rings: List of fraud ring objects
        - summary: Statistics and metadata
    """
    # Start timing
    start_time = time.time()
    
    # Parse CSV
    try:
        df = pd.read_csv(StringIO(csv_data.decode('utf-8')))
    except Exception as e:
        raise ValueError(f"Failed to parse CSV: {str(e)}")
    
    # Validate required columns
    required_columns = ['sender_id', 'receiver_id', 'amount']
    if not all(col in df.columns for col in required_columns):
        raise ValueError(f"CSV must contain columns: {required_columns}")
    
    # Build directed graph
    G = nx.DiGraph()
    
    for _, row in df.iterrows():
        from_acc = str(row['sender_id'])
        to_acc = str(row['receiver_id'])
        amount = float(row['amount'])
        
        # Add edge with transaction metadata
        if G.has_edge(from_acc, to_acc):
            # Aggregate multiple transactions
            G[from_acc][to_acc]['amount'] += amount
            G[from_acc][to_acc]['count'] += 1
        else:
            G.add_edge(from_acc, to_acc, amount=amount, count=1)
    
    # DETECTION 1: Cycle Detection (Money Mule Rings)
    mule_rings = detect_mule_rings(G)
    
    # DETECTION 2: Smurfing Detection
    smurfing_accounts = detect_smurfing(G)
    
    # DETECTION 3: Layered Networks
    layered_chains = detect_shell_networks(G)
    
    # DETECTION 4: High Velocity Accounts
    high_velocity_accounts = detect_high_velocity(G)
    
    # Track patterns for each account
    account_patterns = track_patterns_per_account(
        G, mule_rings, smurfing_accounts, layered_chains, high_velocity_accounts
    )
    
    # Calculate risk scores for all suspicious accounts
    all_suspicious = set()
    for ring in mule_rings:
        all_suspicious.update(ring)
    all_suspicious.update(smurfing_accounts)
    for chain in layered_chains:
        all_suspicious.update(chain)
    all_suspicious.update(high_velocity_accounts)
    
    risk_scores = {}
    for account in all_suspicious:
        score = calculate_risk_score(G, account, mule_rings, smurfing_accounts, layered_chains)
        risk_scores[account] = score
    
    # APPLY FALSE POSITIVE CONTROLS
    # 1. Multi-pattern confirmation: Flag only if ≥2 patterns
    # 2. Risk threshold: Flag only if risk ≥60
    # 3. Trusted accounts: Reduce risk for known legitimate accounts
    suspicious_accounts = apply_false_positive_controls(
        all_suspicious, account_patterns, risk_scores, G
    )
    
    # GENERATE FRAUD RINGS
    # Create structured ring objects with IDs
    fraud_rings, account_to_ring = generate_fraud_rings(
        mule_rings, smurfing_accounts, layered_chains, 
        suspicious_accounts, risk_scores
    )
    
    # Prepare graph data for visualization (only suspicious accounts and their connections)
    graph_data = prepare_graph_visualization(G, suspicious_accounts)
    
    # Filter risk_scores to only include final flagged accounts
    filtered_risk_scores = {acc: risk_scores[acc] for acc in suspicious_accounts if acc in risk_scores}
    # End timing
    processing_time = round(time.time() - start_time, 2)
    
    # TRANSFORM TO REQUIRED OUTPUT FORMAT
    output = transform_to_required_format(
        suspicious_accounts=suspicious_accounts,
        account_patterns=account_patterns,
        risk_scores=filtered_risk_scores,
        account_to_ring=account_to_ring,
        fraud_rings=fraud_rings,
        total_accounts=G.number_of_nodes(),
        total_transactions=G.number_of_edges(),
        processing_time=processing_time
    )
    
    # Return both output and graph for visualization
    return output, G


def detect_mule_rings(G: nx.DiGraph) -> List[List[str]]:
    """
    Detect money mule rings (circular routing patterns)
    Look for cycles of length 3-5 nodes
    """
    try:
        all_cycles = list(nx.simple_cycles(G))
        # Filter for typical mule ring sizes (3-5 participants)
        mule_rings = [cycle for cycle in all_cycles if 3 <= len(cycle) <= 5]
        return mule_rings
    except:
        return []


def detect_smurfing(G: nx.DiGraph) -> List[str]:
    """
    Detect smurfing patterns:
    1. FAN-IN: Many accounts (≥10) send to same receiver
    2. FAN-OUT: One account sends to many receivers (≥10)
    """
    smurfing_accounts = []
    
    for node in G.nodes():
        in_degree = G.in_degree(node)
        out_degree = G.out_degree(node)
        
        # FAN-IN Pattern: 10+ incoming, few outgoing
        if in_degree >= 10 and out_degree <= 2:
            smurfing_accounts.append(node)
        
        # FAN-OUT Pattern: Few incoming, 10+ outgoing
        elif out_degree >= 10 and in_degree <= 2:
            smurfing_accounts.append(node)
    
    return smurfing_accounts


def detect_shell_networks(G: nx.DiGraph) -> List[List[str]]:
    """
    Detect layered mule networks (multi-hop chains with dormant intermediaries)
    
    Conditions:
    - Path length ≥4 (at least 4 accounts in chain)
    - Intermediate accounts have ≤3 transactions total
    - Max depth 4 to prevent performance issues
    
    Pattern: A → B → C → D where B, C are dormant mule accounts
    """
    layered_chains = []
    
    if G.number_of_nodes() == 0:
        return layered_chains
    
    # Get all nodes sorted by degree (potential start nodes have higher activity)
    nodes_by_degree = sorted(G.nodes(), key=lambda n: G.degree(n), reverse=True)
    
    # Limit search to top nodes to avoid performance issues
    search_nodes = nodes_by_degree[:min(50, len(nodes_by_degree))]
    
    processed_chains = set()
    
    for source in search_nodes:
        # Only search from nodes with outgoing connections
        if G.out_degree(source) == 0:
            continue
            
        # Find all paths of length 4 from this source (max depth 4)
        try:
            for target in G.nodes():
                if source == target:
                    continue
                    
                # Use cutoff=4 to limit path length and improve performance
                try:
                    paths = list(nx.all_simple_paths(G, source, target, cutoff=4))
                    
                    for path in paths:
                        # Require path length ≥4 (4 or more accounts)
                        if len(path) < 4:
                            continue
                        
                        # Check if intermediate nodes are dormant (≤3 transactions)
                        intermediates = path[1:-1]  # Exclude source and target
                        
                        if all(G.degree(node) <= 3 for node in intermediates):
                            # Valid layered network found
                            path_tuple = tuple(path)
                            if path_tuple not in processed_chains:
                                layered_chains.append(path)
                                processed_chains.add(path_tuple)
                                
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
                    
        except Exception:
            continue
    
    return layered_chains


def calculate_risk_score(
    G: nx.DiGraph,
    account: str,
    mule_rings: List[List[str]],
    smurfing_accounts: List[str],
    layered_chains: List[List[str]]
) -> int:
    """
    Calculate risk score for an account (0-100 scale)
    
    Scoring:
    - In mule ring (cycle): +40 points
    - Smurfing pattern (fan-in/fan-out): +25 points (changed from +30)
    - In layered network: +35 points
    - High velocity (≥8 transactions): +10 points
    - High centrality: +10 points
    """
    score = 0
    
    # Check if in mule ring
    if any(account in ring for ring in mule_rings):
        score += 40
    
    # Check if smurfing account
    if account in smurfing_accounts:
        score += 25
    
    # Check if in layered network
    if any(account in chain for chain in layered_chains):
        score += 35
    
    # Check high velocity
    if G.degree(account) >= 8:
        score += 10
    
    # Add centrality score (high traffic node)
    if G.number_of_nodes() > 0:
        try:
            centrality = nx.betweenness_centrality(G).get(account, 0)
            score += int(centrality * 10)
        except:
            pass
    
    # Cap at 100
    return min(score, 100)


def detect_high_velocity(G: nx.DiGraph) -> List[str]:
    """
    Detect high velocity accounts (≥8 transactions)
    Pattern: "high_velocity"
    Risk: +10 points
    """
    high_velocity = []
    
    for node in G.nodes():
        # Count total transactions (in + out)
        transaction_count = G.degree(node)
        
        if transaction_count >= 8:
            high_velocity.append(node)
    
    return high_velocity


def track_patterns_per_account(
    G: nx.DiGraph,
    mule_rings: List[List[str]],
    smurfing_accounts: List[str],
    layered_chains: List[List[str]],
    high_velocity_accounts: List[str]
) -> Dict[str, List[str]]:
    """
    Track which patterns each account exhibits
    Returns dict: {account_id: [pattern1, pattern2, ...]}
    """
    account_patterns = {}
    
    # Track cycle patterns
    for ring in mule_rings:
        cycle_length = len(ring)
        pattern_name = f"cycle_length_{cycle_length}"
        for account in ring:
            if account not in account_patterns:
                account_patterns[account] = []
            account_patterns[account].append(pattern_name)
    
    # Track smurfing patterns (need to differentiate fan-in vs fan-out)
    for account in smurfing_accounts:
        if account not in account_patterns:
            account_patterns[account] = []
        
        # Check if it's fan-in or fan-out
        in_degree = G.in_degree(account)
        out_degree = G.out_degree(account)
        
        if in_degree >= 10:
            account_patterns[account].append("fan_in")
        if out_degree >= 10:
            account_patterns[account].append("fan_out")
    
    # Track layered network patterns
    for chain in layered_chains:
        for account in chain:
            if account not in account_patterns:
                account_patterns[account] = []
            account_patterns[account].append("layered_network")
    
    # Track high velocity
    for account in high_velocity_accounts:
        if account not in account_patterns:
            account_patterns[account] = []
        account_patterns[account].append("high_velocity")
    
    return account_patterns


def apply_false_positive_controls(
    all_suspicious: Set[str],
    account_patterns: Dict[str, List[str]],
    risk_scores: Dict[str, int],
    G: nx.DiGraph
) -> Set[str]:
    """
    Apply false positive controls to reduce incorrect flagging
    
    Rules:
    1. Multi-pattern confirmation: Flag only if ≥2 patterns
    2. Risk threshold: Flag only if risk ≥60
    3. Trusted accounts: Whitelist known legitimate accounts
    4. Merchant filtering: Ignore high fan-in without cycles/velocity
    """
    filtered_suspicious = set()
    
    for account in all_suspicious:
        # Rule 3: Skip trusted accounts
        if account in TRUSTED_ACCOUNTS:
            continue
        
        # Get account's patterns
        patterns = account_patterns.get(account, [])
        
        # Rule 1: Require ≥2 patterns (multi-pattern confirmation)
        if len(patterns) < 2:
            # Exception: If single pattern has very high risk (≥85), still flag
            if risk_scores.get(account, 0) < 85:
                continue
        
        # Rule 2: Require risk ≥60
        if risk_scores.get(account, 0) < 60:
            continue
        
        # Rule 4: Merchant behavior filtering
        # If only has fan_in and nothing else, likely a merchant
        if patterns == ["fan_in"]:
            # Check if it's actually a cycle or high velocity
            has_cycle = any(account in ring for ring in [])  # Will be checked properly
            if not has_cycle and G.degree(account) < 20:
                continue
        
        # Passed all filters - mark as suspicious
        filtered_suspicious.add(account)
    
    return filtered_suspicious


def generate_fraud_rings(
    mule_rings: List[List[str]],
    smurfing_accounts: List[str],
    layered_chains: List[List[str]],
    suspicious_accounts: Set[str],
    risk_scores: Dict[str, int]
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """
    Generate structured fraud ring objects with unique IDs
    
    Returns:
        - fraud_rings: List of ring objects
        - account_to_ring: Mapping of account_id to ring_id
    
    Ring object format:
    {
        "ring_id": "RING_001",
        "member_accounts": ["ACC_001", "ACC_002", "ACC_003"],
        "pattern_type": "cycle",
        "risk_score": 85.5
    }
    """
    fraud_rings = []
    account_to_ring = {}
    ring_counter = 1
    
    # 1. Generate cycle rings (from mule_rings)
    for ring in mule_rings:
        # Only include if members are in final suspicious_accounts
        flagged_members = [acc for acc in ring if acc in suspicious_accounts]
        
        if len(flagged_members) >= 2:  # Need at least 2 members for a ring
            ring_id = f"RING_{ring_counter:03d}"
            
            # Calculate average risk score for ring
            ring_risk = sum(risk_scores.get(acc, 0) for acc in flagged_members) / len(flagged_members)
            
            fraud_ring = {
                "ring_id": ring_id,
                "member_accounts": flagged_members,
                "pattern_type": "cycle",
                "ring_size": len(flagged_members),
                "risk_score": round(ring_risk, 1)
            }
            
            fraud_rings.append(fraud_ring)
            
            # Map each member to this ring
            for acc in flagged_members:
                account_to_ring[acc] = ring_id
            
            ring_counter += 1
    
    # 2. Generate smurfing rings (fan-in/fan-out groups)
    # Group smurfing accounts that aren't already in cycle rings
    unassigned_smurfing = [acc for acc in smurfing_accounts if acc in suspicious_accounts and acc not in account_to_ring]
    
    for acc in unassigned_smurfing:
        ring_id = f"RING_{ring_counter:03d}"
        
        fraud_ring = {
            "ring_id": ring_id,
            "member_accounts": [acc],  # Smurfing typically individual aggregator
            "pattern_type": "smurfing",
            "ring_size": 1,
            "risk_score": round(risk_scores.get(acc, 0), 1)
        }
        
        fraud_rings.append(fraud_ring)
        account_to_ring[acc] = ring_id
        ring_counter += 1
    
    # 3. Generate layered network rings
    for chain in layered_chains:
        flagged_members = [acc for acc in chain if acc in suspicious_accounts]
        
        # Only create ring if not already assigned and has multiple members
        unassigned_members = [acc for acc in flagged_members if acc not in account_to_ring]
        
        if len(unassigned_members) >= 2:
            ring_id = f"RING_{ring_counter:03d}"
            
            # Calculate average risk score
            ring_risk = sum(risk_scores.get(acc, 0) for acc in unassigned_members) / len(unassigned_members)
            
            fraud_ring = {
                "ring_id": ring_id,
                "member_accounts": unassigned_members,
                "pattern_type": "layered_network",
                "ring_size": len(unassigned_members),
                "risk_score": round(ring_risk, 1)
            }
            
            fraud_rings.append(fraud_ring)
            
            for acc in unassigned_members:
                account_to_ring[acc] = ring_id
            
            ring_counter += 1
    
    # 4. Assign remaining suspicious accounts to individual high-risk rings
    unassigned_accounts = [acc for acc in suspicious_accounts if acc not in account_to_ring]
    
    for acc in unassigned_accounts:
        ring_id = f"RING_{ring_counter:03d}"
        
        fraud_ring = {
            "ring_id": ring_id,
            "member_accounts": [acc],
            "pattern_type": "high_risk_individual",
            "ring_size": 1,
            "risk_score": round(risk_scores.get(acc, 0), 1)
        }
        
        fraud_rings.append(fraud_ring)
        account_to_ring[acc] = ring_id
        ring_counter += 1
    
    return fraud_rings, account_to_ring


def transform_to_required_format(
    suspicious_accounts: Set[str],
    account_patterns: Dict[str, List[str]],
    risk_scores: Dict[str, int],
    account_to_ring: Dict[str, str],
    fraud_rings: List[Dict[str, Any]],
    total_accounts: int,
    total_transactions: int,
    processing_time: float
) -> Dict[str, Any]:
    """
    Transform internal format to required JSON output format
    
    Required format:
    {
      "suspicious_accounts": [
        {
          "account_id": "ACC_001",
          "suspicion_score": 87.5,
          "detected_patterns": ["cycle_length_3", "high_velocity"],
          "ring_id": "RING_001"
        }
      ],
      "fraud_rings": [...],
      "summary": {...}
    }
    """
    # Build suspicious_accounts array with required structure
    suspicious_accounts_list = []
    
    for account in suspicious_accounts:
        account_obj = {
            "account_id": account,
            "suspicion_score": float(risk_scores.get(account, 0)),
            "detected_patterns": account_patterns.get(account, []),
            "ring_id": account_to_ring.get(account, "UNASSIGNED")
        }
        suspicious_accounts_list.append(account_obj)
    
    # Sort by suspicion_score descending
    suspicious_accounts_list.sort(key=lambda x: x["suspicion_score"], reverse=True)
    
    # Build summary object
    summary = {
        "total_accounts_analyzed": total_accounts,
        "total_transactions": total_transactions,
        "suspicious_accounts_flagged": len(suspicious_accounts),
        "fraud_rings_detected": len(fraud_rings),
        "processing_time_seconds": processing_time
    }
    
    # Return in required format
    return {
        "suspicious_accounts": suspicious_accounts_list,
        "fraud_rings": fraud_rings,
        "summary": summary
    }


def prepare_graph_visualization(G: nx.DiGraph, suspicious_accounts: Set[str]) -> Dict[str, Any]:
    """
    Prepare graph data for React Flow visualization
    Only includes suspicious accounts and their direct connections
    """
    nodes = []
    edges = []
    
    # Only include suspicious accounts as nodes
    for node in suspicious_accounts:
        if node in G.nodes():
            nodes.append({
                "id": node,
                "label": node,
                "is_flagged": True,
                "transaction_count": G.degree(node)
            })
    
    # Only include edges between suspicious accounts
    edge_id = 0
    for u, v, data in G.edges(data=True):
        if u in suspicious_accounts and v in suspicious_accounts:
            edges.append({
                "id": f"e{edge_id}",
                "source": u,
                "target": v,
                "amount": data['amount'],
                "count": data.get('count', 1)
            })
            edge_id += 1
    
    return {
        "nodes": nodes,
        "edges": edges
    }
