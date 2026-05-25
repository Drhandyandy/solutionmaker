"""
Mock Data Generator for PROJECT TOTALITY
Generates a synthetic absolute_bridge_state.csv with realistic Bitcoin transaction data
to test the Phase 2 pipeline when real data is unavailable.
"""

import pandas as pd
import numpy as np
import secrets
import hashlib
from ecdsa import SigningKey, SECP256k1
import csv

def generate_mock_dataset(output_path: str, num_rows: int = 10000, num_multi_sig_keys: int = 50):
    """
    Generates a mock dataset mimicking absolute_bridge_state.csv
    
    Args:
        output_path: Path to save the CSV
        num_rows: Total number of rows
        num_multi_sig_keys: Number of public keys that will have multiple signatures (for lattice attack testing)
    """
    print(f"🔨 Generating mock dataset with {num_rows:,} rows...")
    print(f"   Creating {num_multi_sig_keys} multi-signature public keys for attack testing...")
    
    np.random.seed(42)  # For reproducibility of non-critical fields
    
    # Generate some "multi-sig" keys first (keys used multiple times)
    multi_sig_keys = []
    for i in range(num_multi_sig_keys):
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.get_verifying_key()
        pubkey_hex = vk.to_string('compressed').hex()
        multi_sig_keys.append({
            'privkey': sk,
            'pubkey': pubkey_hex,
            'address': pubkey_to_address(pubkey_hex)
        })
    
    # Generate single-use keys for the rest
    single_use_keys = []
    remaining_rows = num_rows - (num_multi_sig_keys * 5)  # Reserve space for multi-sig txs
    for _ in range(remaining_rows):
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.get_verifying_key()
        pubkey_hex = vk.to_string('compressed').hex()
        single_use_keys.append({
            'privkey': sk,
            'pubkey': pubkey_hex,
            'address': pubkey_to_address(pubkey_hex)
        })
    
    data = []
    
    # Generate transactions for multi-sig keys (3-10 sigs each)
    print("   Generating multi-signature transactions...")
    row_count = 0
    for key_info in multi_sig_keys:
        num_sigs = np.random.randint(3, 11)  # 3 to 10 signatures per key
        for _ in range(num_sigs):
            tx_data = generate_mock_transaction(key_info, biased_nonce=(secrets.randbelow(100) < 30))  # 30% chance of biased nonce
            data.append(tx_data)
            row_count += 1
    
    # Fill remaining with single-use keys
    print("   Generating single-use transactions...")
    while row_count < num_rows:
        key_info = single_use_keys[row_count % len(single_use_keys)]
        tx_data = generate_mock_transaction(key_info, biased_nonce=False)
        data.append(tx_data)
        row_count += 1
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    # Reorder columns to match expected schema
    expected_cols = ['txid', 'script', 'n', 'entropy_source', 'Open', 'High', 'Low', 'Close', 'Volume', 'Timestamp', 
                     'script_len', 'pubkey', 'r_scalar', 's_scalar', 'z_hash']
    
    # Ensure all expected columns exist
    for col in expected_cols:
        if col not in df.columns:
            df[col] = None
    
    df = df[expected_cols]
    
    # Save to CSV
    df.to_csv(output_path, index=False)
    print(f"✅ Mock dataset saved to: {output_path}")
    print(f"   Total rows: {len(df):,}")
    print(f"   Multi-sig keys (≥3 sigs): {num_multi_sig_keys}")
    
    return df

def generate_mock_transaction(key_info, biased_nonce=False):
    """
    Generates a mock transaction entry with valid R, S, Z values
    """
    sk = key_info['privkey']
    vk = key_info['pubkey']
    
    # Generate a random message hash (Z)
    z = secrets.randbits(256)
    z_hex = f"{z:064x}"
    
    # Sign the message
    if biased_nonce:
        # Create a biased nonce (small k value) - vulnerable to lattice attack
        k = secrets.randbelow(2**128)  # Small nonce (bias)
    else:
        # Normal random nonce
        k = secrets.randbits(256)
    
    # Manual ECDSA signing to get R and S
    n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    
    # Calculate R = k*G
    from ecdsa.curves import SECP256k1
    curve = SECP256k1.curve
    G = SECP256k1.generator
    
    point = k * G
    r = point.x() % n
    
    # Calculate S = k^-1 * (z + r*d) mod n
    d = sk.privkey.secret_multiplier
    s = (pow(k, -1, n) * (z + r * d)) % n
    
    # Format R and S as hex (remove leading zeros for realism)
    r_hex = f"{r:x}"
    s_hex = f"{s:x}"
    
    # Create a fake TXID
    txid = secrets.token_hex(32)
    
    # Create a mock scriptSig (DER signature + pubkey)
    der_sig = create_mock_der_signature(r, s)
    script_sig = f"{der_sig} {vk}"
    
    # Legacy P2PKH scriptPubKey is always 25 bytes (76 bytes in hex)
    # OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    script_pubkey = "76a914" + secrets.token_hex(20) + "88ac"
    
    return {
        'txid': txid,
        'script': script_sig,  # scriptSig containing signature and pubkey
        'n': np.random.randint(0, 10),  # Input index
        'entropy_source': 'blockchain',
        'Open': None,  # Null market data as per audit
        'High': None,
        'Low': None,
        'Close': None,
        'Volume': None,
        'Timestamp': None,
        'script_len': 25,  # Legacy P2PKH
        'pubkey': vk,
        'r_scalar': r_hex,
        's_scalar': s_hex,
        'z_hash': z_hex
    }

def create_mock_der_signature(r: int, s: int) -> str:
    """
    Creates a mock DER-encoded signature hex string
    """
    def encode_integer(val: int) -> bytes:
        val_bytes = val.to_bytes((val.bit_length() + 8) // 8, 'big')
        # Add leading zero if high bit is set (to prevent negative interpretation)
        if val_bytes[0] & 0x80:
            val_bytes = b'\x00' + val_bytes
        return b'\x02' + bytes([len(val_bytes)]) + val_bytes
    
    r_enc = encode_integer(r)
    s_enc = encode_integer(s)
    
    der_seq = b'\x30' + bytes([len(r_enc) + len(s_enc)]) + r_enc + s_enc
    
    # Add SIGHASH_ALL byte (0x01) at the end (common in Bitcoin)
    der_sig = der_seq.hex() + "01"
    
    return der_sig

def pubkey_to_address(pubkey_hex: str) -> str:
    """
    Converts a compressed pubkey hex to a Legacy P2PKH address (mock implementation)
    """
    # In a real implementation, this would do SHA256 + RIPEMD160 + Base58Check
    # For mock purposes, we just return a placeholder
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey_bytes).digest()).digest()
    # Simplified: just return hex for now
    return f"1{hashlib.sha256(h160).hexdigest()[:33]}"

if __name__ == "__main__":
    import os
    
    output_file = "/workspace/mock_absolute_bridge_state.csv"
    
    # Generate a smaller test dataset
    df = generate_mock_dataset(output_file, num_rows=5000, num_multi_sig_keys=100)
    
    print("\n📊 Sample of generated data:")
    print(df.head())
    
    # Verify multi-sig keys
    pk_counts = df['pubkey'].value_counts()
    multi_sig = pk_counts[pk_counts >= 3]
    print(f"\n✅ Verification: {len(multi_sig)} public keys have ≥3 signatures")
    print(f"   Max signatures for a single key: {pk_counts.max()}")
