"""
PROJECT TOTALITY: BLOCKCHAIN API FETCHER
========================================
Fetches full transaction data from mempool.space API to extract:
- R, S values from signature scripts
- Z (message hash) for HNP lattice attacks

Supports rate limiting, error handling, and batch processing.
"""

import requests
import time
import json
import os
from typing import Dict, List, Optional, Tuple
from tqdm import tqdm
import hashlib
from ecdsa.util import sigdecode_der
from ecdsa.curves import SECP256k1

# Constants
P_GATEKEEPER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class BlockchainAPIFetcher:
    """
    High-performance fetcher for Bitcoin transaction data via mempool.space API.
    Implements rate limiting, caching, and robust error handling.
    """
    
    def __init__(self, 
                 base_url: str = "https://mempool.space/api",
                 rate_limit: float = 0.5,  # seconds between requests
                 max_retries: int = 3,
                 cache_file: str = "tx_cache.json"):
        """
        Initialize the fetcher.
        
        Args:
            base_url: API base URL (mempool.space or alternative)
            rate_limit: Minimum seconds between API calls
            max_retries: Number of retry attempts on failure
            cache_file: Path to JSON cache file for persistence
        """
        self.base_url = base_url
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.cache_file = cache_file
        self.last_request_time = 0
        self.cache = self._load_cache()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Project-Totality/1.0 (Blockchain Security Research)'
        })
        
        print(f"📡 [API FETCHER] Initialized:")
        print(f"   Base URL: {base_url}")
        print(f"   Rate Limit: {rate_limit}s between requests")
        print(f"   Cache File: {cache_file}")
        print(f"   Cached TXIDs: {len(self.cache)}")
    
    def _load_cache(self) -> Dict:
        """Load existing cache from disk."""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️ Warning: Could not load cache: {e}")
        return {}
    
    def _save_cache(self):
        """Save cache to disk."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
            print(f"💾 Cache saved: {len(self.cache)} transactions")
        except Exception as e:
            print(f"❌ Error saving cache: {e}")
    
    def _enforce_rate_limit(self):
        """Enforce rate limiting between API calls."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit:
            sleep_time = self.rate_limit - elapsed
            time.sleep(sleep_time)
        self.last_request_time = time.time()
    
    def fetch_transaction(self, txid: str, verbose: bool = True) -> Optional[Dict]:
        """
        Fetch a single transaction by TXID.
        
        Args:
            txid: Transaction ID (hex string)
            verbose: Print progress messages
            
        Returns:
            Transaction data dict or None if failed
        """
        # Check cache first
        if txid in self.cache:
            if verbose:
                print(f"✅ [CACHED] {txid[:16]}...")
            return self.cache[txid]
        
        endpoint = f"{self.base_url}/tx/{txid}"
        
        for attempt in range(self.max_retries):
            try:
                self._enforce_rate_limit()
                
                if verbose:
                    print(f"📡 [FETCH {attempt+1}/{self.max_retries}] {txid[:16]}...")
                
                response = self.session.get(endpoint, timeout=30)
                
                if response.status_code == 200:
                    tx_data = response.json()
                    self.cache[txid] = tx_data
                    
                    # Save cache periodically (every 100 txs)
                    if len(self.cache) % 100 == 0:
                        self._save_cache()
                    
                    if verbose:
                        print(f"✅ [SUCCESS] {txid[:16]}... | Size: {tx_data.get('size', 0)} bytes")
                    return tx_data
                
                elif response.status_code == 404:
                    if verbose:
                        print(f"❌ [NOT FOUND] {txid[:16]}...")
                    return None
                
                elif response.status_code == 429:
                    wait_time = 60 * (attempt + 1)  # Exponential backoff
                    if verbose:
                        print(f"⚠️ [RATE LIMITED] Waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                
                else:
                    if verbose:
                        print(f"❌ [ERROR {response.status_code}] {txid[:16]}...")
                    
            except requests.exceptions.Timeout:
                if verbose:
                    print(f"⚠️ [TIMEOUT] {txid[:16]}... (Attempt {attempt+1})")
                time.sleep(5 * (attempt + 1))
                continue
                
            except requests.exceptions.RequestException as e:
                if verbose:
                    print(f"❌ [REQUEST ERROR] {txid[:16]}...: {str(e)}")
                break
        
        return None
    
    def fetch_batch(self, 
                   txids: List[str], 
                   verbose: bool = True,
                   save_interval: int = 50) -> Dict[str, Dict]:
        """
        Fetch multiple transactions with progress tracking.
        
        Args:
            txids: List of transaction IDs
            verbose: Show progress bar
            save_interval: Save cache every N transactions
            
        Returns:
            Dict mapping txid -> transaction data
        """
        results = {}
        total = len(txids)
        
        print(f"\n🚀 [BATCH FETCH] Starting {total} transactions...")
        print(f"   Estimated time: {total * self.rate_limit / 60:.1f} minutes")
        
        iterator = tqdm(txids, desc="Fetching TXs", disable=not verbose)
        
        for i, txid in enumerate(iterator):
            tx_data = self.fetch_transaction(txid, verbose=False)
            
            if tx_data:
                results[txid] = tx_data
            
            # Update progress description
            success_count = len(results)
            iterator.set_postfix({
                'Success': success_count,
                'Failed': i + 1 - success_count,
                'Rate': f"{success_count / (i + 1) * 100:.1f}%"
            })
            
            # Periodic cache save
            if (i + 1) % save_interval == 0:
                self._save_cache()
        
        # Final cache save
        self._save_cache()
        
        print(f"\n✅ [BATCH COMPLETE]")
        print(f"   Successful: {len(results)}/{total}")
        print(f"   Failed: {total - len(results)}")
        print(f"   Success Rate: {len(results) / total * 100:.1f}%")
        
        return results
    
    def extract_signature_components(self, tx_data: Dict, vout_index: int) -> Optional[Dict]:
        """
        Extract R, S, Z from a transaction's input script.
        
        Args:
            tx_data: Full transaction data from API
            vout_index: The output index being spent (to identify correct input)
            
        Returns:
            Dict with r, s, z values or None if extraction fails
        """
        try:
            # Get the first input (or specific input if vout_index provided)
            vin = tx_data.get('vin', [])[0]
            
            if not vin:
                return None
            
            # Get scriptSig
            scriptsig = vin.get('scriptsig', '')
            
            if not scriptsig:
                # Try witness data for SegWit
                witness = vin.get('witness', [])
                if witness:
                    scriptsig = witness[0]  # Signature is first witness element
            
            if not scriptsig:
                return None
            
            # Parse DER signature from hex
            sig_hex = scriptsig[:-66]  # Remove pubkey (last 33 bytes = 66 hex chars)
            sig_bytes = bytes.fromhex(sig_hex)
            
            # Decode DER signature
            try:
                r, s = sigdecode_der(sig_bytes, N_CURVE_ORDER)
            except Exception as e:
                # Try removing potential SIGHASH flag
                if len(sig_bytes) > 1 and sig_bytes[-1] <= 0x03:
                    sig_bytes = sig_bytes[:-1]
                    r, s = sigdecode_der(sig_bytes, N_CURVE_ORDER)
                else:
                    raise e
            
            # Calculate Z (message hash)
            # For legacy P2PKH: Z = SHA256(SHA256(serialized_tx_without_script))
            z = self._calculate_message_hash(tx_data, vin, vout_index)
            
            return {
                'r': r,
                's': s,
                'z': z,
                'r_hex': format(r, '064x'),
                's_hex': format(s, '064x'),
                'z_hex': format(z, '064x') if z else None
            }
            
        except Exception as e:
            print(f"⚠️ Signature extraction failed: {e}")
            return None
    
    def _calculate_message_hash(self, tx_data: Dict, vin: Dict, vout_index: int) -> int:
        """
        Calculate the message hash (Z) for a transaction input.
        
        This is a simplified implementation. For accurate Z calculation,
        you need to serialize the transaction according to Bitcoin protocol
        rules (handling sighash types, previous outputs, etc.).
        
        For production use, consider using the 'bitcoin' library:
        pip install python-bitcoinlib
        """
        try:
            # Simplified: Use the transaction's own hash as approximation
            # This is NOT cryptographically correct for HNP attacks!
            # You MUST implement proper sighash calculation for real attacks.
            
            txid = tx_data.get('txid', '')
            if txid:
                # Return txid as integer (placeholder - NOT REAL Z)
                return int(txid[:16], 16)  # First 8 bytes as placeholder
            
            return None
            
        except Exception as e:
            print(f"⚠️ Message hash calculation failed: {e}")
            return None
    
    def fetch_and_extract(self, 
                         txid: str, 
                         vout_index: int = 0,
                         verbose: bool = True) -> Optional[Dict]:
        """
        Combined fetch and extraction for a single transaction.
        
        Args:
            txid: Transaction ID
            vout_index: Output index being spent
            verbose: Print progress
            
        Returns:
            Dict with txid, r, s, z, pubkey or None
        """
        tx_data = self.fetch_transaction(txid, verbose=verbose)
        
        if not tx_data:
            return None
        
        sig_components = self.extract_signature_components(tx_data, vout_index)
        
        if not sig_components:
            return None
        
        # Extract pubkey from scriptSig
        scriptsig = tx_data.get('vin', [{}])[0].get('scriptsig', '')
        pubkey = scriptsig[-66:] if len(scriptsig) >= 66 else None
        
        result = {
            'txid': txid,
            'pubkey': pubkey,
            **sig_components
        }
        
        if verbose:
            print(f"✅ Extracted: R={result['r_hex'][:16]}..., S={result['s_hex'][:16]}...")
        
        return result


def fetch_chains_for_attack(fetcher: BlockchainAPIFetcher,
                           target_txids: List[str],
                           output_file: str = "fetched_attack_chains.json",
                           min_sigs_per_key: int = 3) -> List[Dict]:
    """
    Fetch transactions and group into attack-ready chains.
    
    Args:
        fetcher: BlockchainAPIFetcher instance
        target_txids: List of TXIDs to fetch
        output_file: JSON file to save results
        min_sigs_per_key: Minimum signatures per pubkey for lattice attack
        
    Returns:
        List of attack chains (pubkey -> list of signatures)
    """
    print(f"\n🔥 [FETCH CHAINS FOR ATTACK]")
    print(f"   Target TXIDs: {len(target_txids)}")
    print(f"   Min Sigs/Key: {min_sigs_per_key}")
    
    # Fetch all transactions
    tx_results = fetcher.fetch_batch(target_txids)
    
    # Extract signatures and group by pubkey
    pubkey_groups = {}
    
    print("\n🔑 Grouping by Public Key...")
    for txid, tx_data in tqdm(tx_results.items(), desc="Extracting Signatures"):
        result = fetcher.fetch_and_extract(txid, verbose=False)
        
        if result and result['pubkey']:
            pubkey = result['pubkey']
            
            if pubkey not in pubkey_groups:
                pubkey_groups[pubkey] = []
            
            pubkey_groups[pubkey].append({
                'txid': txid,
                'r': result['r'],
                's': result['s'],
                'z': result['z'],
                'r_hex': result['r_hex'],
                's_hex': result['s_hex'],
                'z_hex': result['z_hex']
            })
    
    # Filter for keys with sufficient signatures
    attack_chains = []
    
    for pubkey, sigs in pubkey_groups.items():
        if len(sigs) >= min_sigs_per_key:
            attack_chains.append({
                'pubkey': pubkey,
                'signature_count': len(sigs),
                'signatures': sigs
            })
    
    # Sort by signature count (descending)
    attack_chains.sort(key=lambda x: x['signature_count'], reverse=True)
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(attack_chains, f, indent=2)
    
    print(f"\n✅ [ATTACK CHAINS READY]")
    print(f"   Total Keys: {len(pubkey_groups)}")
    print(f"   Attack-Ready Chains (≥{min_sigs_per_key} sigs): {len(attack_chains)}")
    print(f"   Saved to: {output_file}")
    
    if attack_chains:
        print(f"\n🏆 Top 3 Attack Targets:")
        for i, chain in enumerate(attack_chains[:3], 1):
            print(f"   {i}. {chain['pubkey'][:20]}... ({chain['signature_count']} sigs)")
    
    return attack_chains


# Example Usage
if __name__ == "__main__":
    print("🚀 PROJECT TOTALITY: API FETCHER DEMO\n")
    
    # Initialize fetcher
    fetcher = BlockchainAPIFetcher(
        rate_limit=0.5,  # Conservative for free tier
        cache_file="totality_tx_cache.json"
    )
    
    # Example: Fetch a known transaction
    # Replace with your target TXIDs from absolute_bridge_state.csv
    demo_txids = [
        "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",  # Satoshi's first TX
        "ea44e9727169199015e5a01aa83e77b6d43e2c8cc6f9e2e8e5e6f7d8c9b0a1b2",  # Example (may not exist)
    ]
    
    # Fetch and extract
    results = fetcher.fetch_batch(demo_txids)
    
    # If you have a list of target TXIDs from your CSV:
    # import pandas as pd
    # df = pd.read_csv('/content/drive/MyDrive/CRYPTO_CONSOLIDATED/absolute_bridge_state.csv')
    # target_txids = df['txid'].tolist()[:100]  # Start with 100 for testing
    # attack_chains = fetch_chains_for_attack(fetcher, target_txids)
    
    print("\n✅ Demo complete. Ready for full-scale extraction.")
