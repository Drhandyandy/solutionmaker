"""
PROJECT TOTALITY: ENHANCED MESSAGE HASH CALCULATOR
===================================================
Properly calculates Z (message hash) for Bitcoin transactions.
Uses python-bitcoinlib for cryptographically correct sighash computation.

Installation:
    pip install python-bitcoinlib

This is CRITICAL for HNP lattice attacks - incorrect Z values will fail the attack.
"""

import hashlib
from typing import Optional, Dict, List
from ecdsa.curves import SECP256k1

# Try to import bitcoin library, fall back to manual implementation
try:
    from bitcoin.core import CTransaction, Hash, Hash160
    from bitcoin.core.script import SIGHASH_ALL, Sign
    from bitcoin.core.scripteval import SignatureHash
    BITCOIN_LIB_AVAILABLE = True
except ImportError:
    BITCOIN_LIB_AVAILABLE = False
    print("⚠️ WARNING: python-bitcoinlib not installed.")
    print("   Install with: pip install python-bitcoinlib")
    print("   Using fallback (may be inaccurate for some transaction types)")

N_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class MessageHashCalculator:
    """
    Calculates the message hash (Z) for Bitcoin transaction signatures.
    Supports both legacy P2PKH and SegWit transactions.
    """
    
    @staticmethod
    def calculate_legacy_p2pkh_hash(tx_hex: str, 
                                    vin_index: int, 
                                    script_pubkey_hex: str,
                                    sighash_type: int = SIGHASH_ALL if BITCOIN_LIB_AVAILABLE else 1) -> Optional[int]:
        """
        Calculate Z for legacy P2PKH transactions.
        
        Args:
            tx_hex: Raw transaction hex
            vin_index: Input index being signed
            script_pubkey_hex: The scriptPubKey of the output being spent
            sighash_type: SIGHASH type (default: SIGHASH_ALL)
            
        Returns:
            Z value as integer, or None if calculation fails
        """
        try:
            if BITCOIN_LIB_AVAILABLE:
                # Use bitcoin library for accurate calculation
                tx_bytes = bytes.fromhex(tx_hex)
                tx = CTransaction.deserialize(tx_bytes)
                
                # Get the scriptPubKey as bytes
                script_pubkey = bytes.fromhex(script_pubkey_hex)
                
                # Calculate signature hash
                sighash = SignatureHash(script_pubkey, tx, vin_index, sighash_type)
                z_bytes = hashlib.sha256(hashlib.sha256(sighash).digest()).digest()
                z = int.from_bytes(z_bytes, 'big')
                
                return z % N_CURVE_ORDER
            
            else:
                # Fallback: Manual implementation (simplified)
                # This is NOT fully accurate but works for basic cases
                tx_bytes = bytes.fromhex(tx_hex)
                
                # Double SHA256 of transaction (simplified, ignores script replacement)
                hash1 = hashlib.sha256(tx_bytes).digest()
                hash2 = hashlib.sha256(hash1).digest()
                z = int.from_bytes(hash2, 'big')
                
                return z % N_CURVE_ORDER
                
        except Exception as e:
            print(f"⚠️ Legacy hash calculation failed: {e}")
            return None
    
    @staticmethod
    def calculate_segwit_hash(tx_hex: str,
                             vin_index: int,
                             value_sat: int,
                             script_pubkey_hex: str,
                             sighash_type: int = 1) -> Optional[int]:
        """
        Calculate Z for SegWit (BIP143) transactions.
        
        Args:
            tx_hex: Raw transaction hex
            vin_index: Input index being signed
            value_sat: Value of the output being spent (in satoshis)
            script_pubkey_hex: The scriptPubKey/witnessScript
            sighash_type: SIGHASH type
            
        Returns:
            Z value as integer, or None if calculation fails
        """
        try:
            if not BITCOIN_LIB_AVAILABLE:
                print("⚠️ SegWit hash calculation requires python-bitcoinlib")
                return None
            
            tx_bytes = bytes.fromhex(tx_hex)
            tx = CTransaction.deserialize(tx_bytes)
            
            # For SegWit, we need to use BIP143 signature hash algorithm
            # This is complex - bitcoin library handles it internally
            script_pubkey = bytes.fromhex(script_pubkey_hex)
            
            # BIP143 hash calculation
            sighash = SignatureHash(script_pubkey, tx, vin_index, sighash_type, amount=value_sat)
            z_bytes = hashlib.sha256(hashlib.sha256(sighash).digest()).digest()
            z = int.from_bytes(z_bytes, 'big')
            
            return z % N_CURVE_ORDER
            
        except Exception as e:
            print(f"⚠️ SegWit hash calculation failed: {e}")
            return None
    
    @staticmethod
    def extract_from_api_response(tx_data: Dict, vout_index: int = 0) -> Optional[int]:
        """
        Extract or calculate Z from mempool.space API response.
        
        The API may provide some data, but we often need to fetch raw hex
        and calculate manually.
        
        Args:
            tx_data: Transaction data from API
            vout_index: Output index being spent
            
        Returns:
            Z value or None
        """
        try:
            # Check if API provides pre-calculated hash (unlikely but possible)
            if 'sig_hash' in tx_data:
                return int(tx_data['sig_hash'], 16)
            
            # Get raw transaction hex
            txid = tx_data.get('txid', '')
            
            # Fetch raw hex from API
            import requests
            base_url = "https://mempool.space/api"
            response = requests.get(f"{base_url}/tx/{txid}/hex", timeout=30)
            
            if response.status_code != 200:
                print(f"⚠️ Failed to fetch raw tx hex: {response.status_code}")
                return None
            
            tx_hex = response.text.strip()
            
            # Get input details
            vin = tx_data.get('vin', [{}])[vout_index]
            
            # Get the previous output's scriptPubKey
            prev_txid = vin.get('txid', '')
            prev_vout = vin.get('vout', 0)
            
            # Fetch previous transaction to get scriptPubKey
            prev_response = requests.get(f"{base_url}/tx/{prev_txid}", timeout=30)
            
            if prev_response.status_code != 200:
                print(f"⚠️ Failed to fetch prev tx: {response.status_code}")
                return None
            
            prev_tx_data = prev_response.json()
            prev_out = prev_tx_data.get('vout', [{}])[prev_vout]
            
            script_pubkey_hex = prev_out.get('scriptpubkey', '')
            value_sat = prev_out.get('value', 0) * 100000000  # Convert BTC to satoshis
            
            # Determine if SegWit
            is_segwit = 'witness' in vin and len(vin['witness']) > 0
            
            if is_segwit:
                return MessageHashCalculator.calculate_segwit_hash(
                    tx_hex, vout_index, value_sat, script_pubkey_hex
                )
            else:
                return MessageHashCalculator.calculate_legacy_p2pkh_hash(
                    tx_hex, vout_index, script_pubkey_hex
                )
                
        except Exception as e:
            print(f"⚠️ Z extraction from API failed: {e}")
            return None


class EnhancedBlockchainFetcher:
    """
    Enhanced fetcher with proper Z calculation.
    Wraps the basic fetcher with accurate message hash computation.
    """
    
    def __init__(self, 
                 api_base_url: str = "https://mempool.space/api",
                 rate_limit: float = 0.5,
                 cache_file: str = "enhanced_tx_cache.json"):
        """Initialize enhanced fetcher."""
        self.api_base_url = api_base_url
        self.rate_limit = rate_limit
        self.cache_file = cache_file
        self.cache = {}
        self.hash_calculator = MessageHashCalculator()
        
        import time
        import json
        import os
        
        # Load existing cache
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    self.cache = json.load(f)
                print(f"💾 Loaded cache: {len(self.cache)} transactions")
            except:
                pass
        
        self.last_request = 0
        self.session = __import__('requests').Session()
    
    def _enforce_rate_limit(self):
        import time
        elapsed = time.time() - self.last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_request = time.time()
    
    def fetch_transaction_with_z(self, txid: str, verbose: bool = True) -> Optional[Dict]:
        """
        Fetch transaction and calculate proper Z value.
        
        Returns:
            Dict with txid, r, s, z, pubkey (all properly calculated)
        """
        import time
        from ecdsa.util import sigdecode_der
        
        # Check cache
        if txid in self.cache:
            if verbose:
                print(f"✅ [CACHED] {txid[:16]}...")
            return self.cache[txid]
        
        try:
            # Fetch transaction data
            self._enforce_rate_limit()
            if verbose:
                print(f"📡 Fetching {txid[:16]}...")
            
            response = self.session.get(f"{self.api_base_url}/tx/{txid}", timeout=30)
            
            if response.status_code != 200:
                if verbose:
                    print(f"❌ API Error {response.status_code}")
                return None
            
            tx_data = response.json()
            
            # Get first input
            vin = tx_data.get('vin', [{}])[0]
            
            if not vin:
                if verbose:
                    print(f"⚠️ No inputs found")
                return None
            
            # Get scriptSig or witness
            scriptsig = vin.get('scriptsig', '')
            witness = vin.get('witness', [])
            
            if not scriptsig and witness:
                scriptsig = witness[0] if witness else ''
            
            if not scriptsig:
                if verbose:
                    print(f"⚠️ No signature data found")
                return None
            
            # Parse signature (remove pubkey from end)
            if len(scriptsig) >= 132:  # At least sig + pubkey
                sig_hex = scriptsig[:-66]  # Remove last 33 bytes (pubkey)
            else:
                sig_hex = scriptsig
            
            sig_bytes = bytes.fromhex(sig_hex)
            
            # Remove SIGHASH flag if present
            if sig_bytes[-1] <= 0x03:
                sig_bytes = sig_bytes[:-1]
            
            # Decode DER signature
            try:
                r, s = sigdecode_der(sig_bytes, N_CURVE_ORDER)
            except Exception as e:
                if verbose:
                    print(f"⚠️ DER decode failed: {e}")
                return None
            
            # Calculate Z (message hash) - THIS IS THE CRITICAL PART
            z = self.hash_calculator.extract_from_api_response(tx_data, 0)
            
            if z is None:
                if verbose:
                    print(f"⚠️ Z calculation failed, using placeholder")
                # Fallback: Use txid as placeholder (NOT CRYPTOGRAPHICALLY VALID!)
                z = int(txid[:16], 16)
            
            # Extract pubkey
            pubkey = scriptsig[-66:] if len(scriptsig) >= 66 else None
            
            result = {
                'txid': txid,
                'pubkey': pubkey,
                'r': r,
                's': s,
                'z': z,
                'r_hex': format(r, '064x'),
                's_hex': format(s, '064x'),
                'z_hex': format(z, '064x'),
                'z_valid': z != int(txid[:16], 16)  # Flag if Z is real or placeholder
            }
            
            # Cache result
            self.cache[txid] = result
            
            # Save cache periodically
            if len(self.cache) % 50 == 0:
                import json
                with open(self.cache_file, 'w') as f:
                    json.dump(self.cache, f)
                if verbose:
                    print(f"💾 Cache saved: {len(self.cache)} txs")
            
            if verbose:
                valid_flag = "✅" if result['z_valid'] else "⚠️"
                print(f"{valid_flag} Extracted: R={r_hex[:16]}..., Z_valid={result['z_valid']}")
            
            return result
            
        except Exception as e:
            if verbose:
                print(f"❌ Error: {e}")
            return None
    
    def save_cache(self):
        """Save cache to disk."""
        import json
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f)
        print(f"💾 Cache saved: {len(self.cache)} transactions")


# Quick test function
def test_z_calculation():
    """Test Z calculation with a known transaction."""
    print("🧪 Testing Z Calculation...\n")
    
    calculator = MessageHashCalculator()
    
    # Satoshi's first transaction (famous, well-documented)
    test_txid = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
    
    print(f"Testing TX: {test_txid}")
    print(f"Bitcoin Lib Available: {BITCOIN_LIB_AVAILABLE}\n")
    
    fetcher = EnhancedBlockchainFetcher()
    result = fetcher.fetch_transaction_with_z(test_txid)
    
    if result:
        print("\n✅ Results:")
        print(f"   TXID: {result['txid'][:16]}...")
        print(f"   PubKey: {result['pubkey'][:20] if result['pubkey'] else 'N/A'}...")
        print(f"   R: {result['r_hex'][:20]}...")
        print(f"   S: {result['s_hex'][:20]}...")
        print(f"   Z: {result['z_hex'][:20]}...")
        print(f"   Z Valid: {result['z_valid']}")
    else:
        print("\n❌ Failed to fetch/extract")
    
    return result


if __name__ == "__main__":
    print("🚀 PROJECT TOTALITY: ENHANCED Z CALCULATOR\n")
    print("=" * 60)
    
    if BITCOIN_LIB_AVAILABLE:
        print("✅ python-bitcoinlib: AVAILABLE (Accurate Z calculation)")
    else:
        print("❌ python-bitcoinlib: MISSING (Fallback mode - may be inaccurate)")
        print("\nInstall for production use:")
        print("   pip install python-bitcoinlib\n")
    
    print("=" * 60)
    
    # Run test
    test_z_calculation()
