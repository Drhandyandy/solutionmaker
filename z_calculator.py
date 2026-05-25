"""
PROJECT TOTALITY: Z (MESSAGE HASH) CALCULATOR
---------------------------------------------
Calculates the precise Z value (message hash) for a transaction input.
Uses python-bitcoinlib for cryptographic accuracy.
Required for Hidden Number Problem attacks.
"""

import hashlib
from typing import Optional, Dict, Any

# Define SIGHASH constants upfront (before any imports that might fail)
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

BITCOIN_LIB_AVAILABLE = False

try:
    from bitcoin.core import Hash, CTransaction, Hash160
    from bitcoin.core.script import CScript
    BITCOIN_LIB_AVAILABLE = True
except ImportError:
    print("⚠️ WARNING: python-bitcoinlib not installed. Z calculation will use estimation.")
    print("   Install with: pip install python-bitcoinlib")

class ZCalculator:
    """Calculates Z (message hash) for ECDSA signature verification."""
    
    @staticmethod
    def calculate_z_bitcoinlib(tx_hex: str, vin_index: int, script_pubkey_hex: str, sighash_type: int = SIGHASH_ALL) -> Optional[int]:
        """
        Calculates Z using python-bitcoinlib (cryptographically accurate).
        
        Args:
            tx_hex: Raw transaction hex
            vin_index: Index of the input being signed
            script_pubkey_hex: The scriptPubKey of the UTXO being spent
            sighash_type: SIGHASH flag (default: SIGHASH_ALL)
            
        Returns:
            Integer Z value (256-bit hash)
        """
        if not BITCOIN_LIB_AVAILABLE:
            return None
            
        try:
            tx_bytes = bytes.fromhex(tx_hex)
            tx = CTransaction.deserialize(tx_bytes)
            
            script_pubkey = CScript(bytes.fromhex(script_pubkey_hex))
            
            # Create signature hash
            sig_hash = tx.SignatureHash(script_pubkey, vin_index, sighash_type)
            
            # Convert to integer (big-endian)
            z = int.from_bytes(sig_hash, 'big')
            return z
            
        except Exception as e:
            print(f"❌ Z Calculation Error: {e}")
            return None
    
    @staticmethod
    def estimate_z_from_txid_vout(txid: str, vout: int) -> Optional[int]:
        """
        ESTIMATION ONLY: Creates a pseudo-Z from txid+vout.
        ⚠️ NOT CRYPTOGRAPHICALLY VALID FOR ATTACKS. Use only for testing pipeline.
        """
        if not txid:
            return None
            
        # Combine txid and vout into a deterministic hash
        data = f"{txid}:{vout}".encode('utf-8')
        hash_result = hashlib.sha256(data).digest()
        
        # Return as 256-bit integer
        z = int.from_bytes(hash_result, 'big')
        print(f"⚠️ WARNING: Using ESTIMATED Z for {txid}. Not valid for real attacks.")
        return z
    
    @staticmethod
    def parse_sighash_from_script_sig(script_sig_hex: str) -> int:
        """
        Attempts to extract SIGHASH type from the end of a signature in scriptSig.
        Default: SIGHASH_ALL (0x01)
        """
        if not script_sig_hex or len(script_sig_hex) < 4:
            return SIGHASH_ALL
            
        try:
            data = bytes.fromhex(script_sig_hex)
            # SIGHASH is typically the last byte of the DER signature
            # But scriptSig contains <sig> <pubkey>, so we need to find sig end
            
            # Simple heuristic: Check last byte before pubkey
            # This is imprecise without full parsing; default to ALL if unsure
            last_byte = data[-1]
            
            # Valid sighash flags
            valid_flags = {0x01, 0x02, 0x03, 0x81, 0x82, 0x83}
            if last_byte in valid_flags:
                return last_byte
                
            # Check second-to-last (in case pubkey is 1 byte? unlikely)
            if len(data) > 33: # Min pubkey size
                potential_flag = data[-34] # Before 33-byte compressed pubkey
                if potential_flag in valid_flags:
                    return potential_flag
                    
            return SIGHASH_ALL
        except Exception:
            return SIGHASH_ALL


def calculate_z_for_transaction(tx_hex: str, vin_index: int, script_pubkey_hex: str, 
                                sighash_type: int = SIGHASH_ALL) -> Dict[str, Any]:
    """
    Wrapper function to calculate Z with fallbacks.
    
    Returns:
        dict: { 'z': int or None, 'method': str, 'success': bool }
    """
    result = {
        'z': None,
        'method': 'none',
        'success': False
    }
    
    # Method 1: python-bitcoinlib (Accurate)
    if BITCOIN_LIB_AVAILABLE:
        z = ZCalculator.calculate_z_bitcoinlib(tx_hex, vin_index, script_pubkey_hex, sighash_type)
        if z is not None:
            result['z'] = z
            result['method'] = 'bitcoinlib'
            result['success'] = True
            return result
    
    # Method 2: Estimation (Fallback - NOT SECURE FOR ATTACKS)
    print("⚠️ Falling back to Z estimation. Results will be INVALID for lattice attacks.")
    # We can't estimate without txid, so return failure
    return result


# Utility for batch processing
def batch_calculate_z(transactions: list, verbose: bool = True) -> list:
    """
    Calculate Z for a list of transaction dicts.
    
    Input format per item:
    {
        'tx_hex': str,
        'vin_index': int,
        'script_pubkey_hex': str,
        'sighash_type': int (optional, default SIGHASH_ALL)
    }
    
    Returns list with added 'z' and 'z_method' fields.
    """
    results = []
    
    for i, tx_data in enumerate(transactions):
        if verbose and i % 100 == 0:
            print(f"📡 Calculating Z for transaction {i}/{len(transactions)}...")
            
        sighash = tx_data.get('sighash_type', SIGHASH_ALL)
        z_result = calculate_z_for_transaction(
            tx_data['tx_hex'],
            tx_data['vin_index'],
            tx_data['script_pubkey_hex'],
            sighash
        )
        
        tx_data['z'] = z_result['z']
        tx_data['z_method'] = z_result['method']
        tx_data['z_valid'] = z_result['success']
        results.append(tx_data)
        
    return results
