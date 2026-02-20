"""
Graph Visualization Module
Creates visual representations of transaction networks and detected fraud rings
"""
import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for server use
import matplotlib.pyplot as plt
from typing import Dict, List, Set, Any
from pathlib import Path


def visualize_full_graph(G: nx.DiGraph, output_path: str = "graph_full.png") -> str:
    """
    Visualize the complete transaction network
    
    Args:
        G: NetworkX directed graph
        output_path: Path to save the image
        
    Returns:
        Path to saved image file
    """
    plt.figure(figsize=(16, 12))
    
    # Calculate node sizes based on degree (more connections = larger node)
    node_sizes = [G.degree(node) * 100 + 300 for node in G.nodes()]
    
    # Use spring layout for better visualization
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
    
    # Draw nodes
    nx.draw_networkx_nodes(
        G, pos, 
        node_color='lightblue',
        node_size=node_sizes,
        alpha=0.7
    )
    
    # Draw edges with transparency
    nx.draw_networkx_edges(
        G, pos,
        edge_color='gray',
        arrows=True,
        arrowsize=15,
        alpha=0.3,
        width=1.5
    )
    
    # Draw labels
    nx.draw_networkx_labels(
        G, pos,
        font_size=8,
        font_weight='bold'
    )
    
    plt.title(f"Transaction Network Graph\n{G.number_of_nodes()} Accounts, {G.number_of_edges()} Transactions", 
              fontsize=16, fontweight='bold')
    plt.axis('off')
    plt.tight_layout()
    
    # Save to file
    output_file = Path(output_path)
    plt.savefig(output_file, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    
    return str(output_file)


def visualize_fraud_rings(G: nx.DiGraph, rings: List[Dict], output_path: str = "graph_fraud_rings.png") -> str:
    """
    Visualize detected fraud rings with highlighted cycles and patterns
    
    Args:
        G: NetworkX directed graph
        rings: List of detected fraud ring dictionaries
        output_path: Path to save the image
        
    Returns:
        Path to saved image file
    """
    plt.figure(figsize=(18, 14))
    
    # Collect all accounts involved in fraud rings
    fraud_accounts = set()
    for ring in rings:
        # Support both 'accounts' and 'member_accounts' field names
        accounts_list = ring.get('member_accounts') or ring.get('accounts', [])
        fraud_accounts.update(accounts_list)
    
    # Create subgraph with fraud accounts
    if fraud_accounts:
        fraud_subgraph = G.subgraph(fraud_accounts)
    else:
        fraud_subgraph = G
    
    pos = nx.spring_layout(fraud_subgraph, k=3, iterations=50, seed=42)
    
    # Color code by ring
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F']
    
    # Draw each ring separately with different colors
    for idx, ring in enumerate(rings):
        # Support both 'accounts' and 'member_accounts' field names
        accounts_list = ring.get('member_accounts') or ring.get('accounts', [])
        ring_nodes = [n for n in accounts_list if n in fraud_subgraph.nodes()]
        if ring_nodes:
            color = colors[idx % len(colors)]
            
            # Get pattern (support both 'pattern' and 'pattern_type')
            pattern = ring.get('pattern_type') or ring.get('pattern', 'unknown')
            
            # Draw ring nodes
            nx.draw_networkx_nodes(
                fraud_subgraph, pos,
                nodelist=ring_nodes,
                node_color=color,
                node_size=800,
                alpha=0.9,
                label=f"{ring['ring_id']}: {pattern} ({len(ring_nodes)} accounts)"
            )
    
    # Draw edges
    nx.draw_networkx_edges(
        fraud_subgraph, pos,
        edge_color='#2C3E50',
        arrows=True,
        arrowsize=20,
        alpha=0.6,
        width=2.5,
        connectionstyle='arc3,rad=0.1'
    )
    
    # Draw labels
    nx.draw_networkx_labels(
        fraud_subgraph, pos,
        font_size=10,
        font_weight='bold',
        font_color='white'
    )
    
    plt.title(f"Detected Fraud Rings\n{len(rings)} Rings, {len(fraud_accounts)} Accounts",
              fontsize=18, fontweight='bold')
    plt.legend(loc='upper left', fontsize=10)
    plt.axis('off')
    plt.tight_layout()
    
    # Save to file
    output_file = Path(output_path)
    plt.savefig(output_file, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    
    return str(output_file)


def visualize_suspicious_accounts(G: nx.DiGraph, suspicious: List[Dict], output_path: str = "graph_suspicious.png") -> str:
    """
    Visualize suspicious accounts and their immediate connections
    
    Args:
        G: NetworkX directed graph
        suspicious: List of suspicious account dictionaries
        output_path: Path to save the image
        
    Returns:
        Path to saved image file
    """
    plt.figure(figsize=(16, 12))
    
    if not suspicious:
        # Empty graph with message
        plt.text(0.5, 0.5, 'No Suspicious Accounts Detected\n(False Positive Controls Active)',
                ha='center', va='center', fontsize=20, fontweight='bold')
        plt.axis('off')
        output_file = Path(output_path)
        plt.savefig(output_file, dpi=150, bbox_inches='tight', facecolor='white')
        plt.close()
        return str(output_file)
    
    # Get suspicious account IDs
    suspicious_ids = {acc['account_id'] for acc in suspicious}

    # Create subgraph with suspicious accounts and their neighbors
    ego_graphs = []
    for acc_id in suspicious_ids:
        if acc_id in G:
            ego_graphs.append(nx.ego_graph(G, acc_id, radius=1))

    if ego_graphs:
        subgraph = nx.compose_all(ego_graphs)
    else:
        subgraph = G.subgraph(suspicious_ids)

    pos = nx.spring_layout(subgraph, k=2, iterations=50, seed=42)

    # Separate suspicious vs. connected accounts
    suspicious_nodes = [n for n in subgraph.nodes() if n in suspicious_ids]
    connected_nodes = [n for n in subgraph.nodes() if n not in suspicious_ids]

    # Draw connected accounts (gray)
    if connected_nodes:
        nx.draw_networkx_nodes(
            subgraph, pos,
            nodelist=connected_nodes,
            node_color='lightgray',
            node_size=400,
            alpha=0.6
        )

    # Draw suspicious accounts (red) with size based on risk/suspicion score
    if suspicious_nodes:
        # Create risk score mapping (support both 'risk_score' and 'suspicion_score')
        risk_map = {}
        for acc in suspicious:
            score = acc.get('risk_score')
            if score is None:
                score = acc.get('suspicion_score', 50)
            risk_map[acc['account_id']] = score
        node_sizes = [risk_map.get(n, 50) * 10 + 500 for n in suspicious_nodes]

        nx.draw_networkx_nodes(
            subgraph, pos,
            nodelist=suspicious_nodes,
            node_color='#E74C3C',
            node_size=node_sizes,
            alpha=0.9
        )

    # Draw edges
    nx.draw_networkx_edges(
        subgraph, pos,
        edge_color='#34495E',
        arrows=True,
        arrowsize=15,
        alpha=0.5,
        width=2
    )

    # Draw labels
    nx.draw_networkx_labels(
        subgraph, pos,
        font_size=9,
        font_weight='bold'
    )

    plt.title(f"Suspicious Accounts Network\n{len(suspicious_ids)} Flagged Accounts",
              fontsize=16, fontweight='bold')
    plt.axis('off')
    plt.tight_layout()

    # Save to file
    output_file = Path(output_path)
    plt.savefig(output_file, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()

    return str(output_file)


def generate_all_visualizations(G: nx.DiGraph, analysis_results: Dict[str, Any]) -> Dict[str, str]:
    """
    Generate all graph visualizations and return file paths
    
    Args:
        G: NetworkX directed graph
        analysis_results: Complete analysis results dictionary
        
    Returns:
        Dictionary mapping visualization type to file path
    """
    visualizations = {}
    
    # Full network graph
    visualizations['full_graph'] = visualize_full_graph(G, "graph_full.png")
    
    # Fraud rings
    if analysis_results.get('fraud_rings'):
        visualizations['fraud_rings'] = visualize_fraud_rings(
            G, 
            analysis_results['fraud_rings'],
            "graph_fraud_rings.png"
        )
    
    # Suspicious accounts
    visualizations['suspicious_accounts'] = visualize_suspicious_accounts(
        G,
        analysis_results.get('suspicious_accounts', []),
        "graph_suspicious.png"
    )
    
    return visualizations
