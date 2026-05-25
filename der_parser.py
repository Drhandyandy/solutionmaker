"""
DER Signature Parser for Bitcoin ScriptSigs
Extracts R and S values from DER-encoded signatures found in Legacy P2PKH inputs.
"""

import re
from typing import Optional, Tuple

def decode_der_signature(sig_hex: str) -> Optional[Tuple[int, int]]:
    """
    Decodes a DER-encoded signature hex string into (r, s) integers.
    
    DER Format:
    0x30 [Total Length] 0x02 [R Length] [R] 0x02 [S Length] [S] [Optional Sighash Type]
    
    Args:
        sig_hex: Hex string of the signature (may include sighash byte at end)
        
    Returns:
        Tuple (r, s) if successful, None otherwise.
    """
    if not sig_hex or len(sig_hex) < 18: # Min DER sig is roughly 8 bytes + overhead
        return None
    
    try:
        # Remove any leading/trailing whitespace
        sig_hex = sig_hex.strip()
        
        # If the scriptSig contains both sig and pubkey, we often need to isolate the sig.
        # In Legacy P2PKH, scriptSig = <sig> <pubkey>. 
        # The sig usually comes first. If there are spaces, split and take first.
        if ' ' in sig_hex:
            parts = sig_hex.split()
            sig_hex = parts[0]
        
        # Ensure even length
        if len(sig_hex) % 2 != 0:
            sig_hex = sig_hex[:-1] # Drop trailing nibble if odd
            
        data = bytes.fromhex(sig_hex)
        
        if data[0] != 0x30:
            # Not a DER sequence, might be raw 64-byte r+s (rare in scriptSig but possible)
            # Or maybe it's just the raw bytes without DER wrapping? 
            # Standard Bitcoin is DER. Let's assume DER.
            return None
            
        total_len = data[1]
        # Check if the length matches (allowing for slight variations in padding)
        # Sometimes the sighash byte is appended outside the DER structure in the script representation
        # But usually inside the hex blob provided by explorers if it's the full input script.
        
        cursor = 2
        
        # Read R
        if data[cursor] != 0x02:
            return None
        cursor += 1
        
        r_len = data[cursor]
        cursor += 1
        
        r_bytes = data[cursor : cursor + r_len]
        r = int.from_bytes(r_bytes, 'big')
        cursor += r_len
        
        # Read S
        if cursor >= len(data) or data[cursor] != 0x02:
            return None
        cursor += 1
        
        s_len = data[cursor]
        cursor += 1
        
        s_bytes = data[cursor : cursor + s_len]
        s = int.from_bytes(s_bytes, 'big')
        cursor += s_len
        
        # Remaining bytes are usually the Sighash type (1 byte), which we ignore for R/S extraction
        return (r, s)
        
    except Exception as e:
        # print(f"DER Parse Error: {e}")
        return None

def extract_sig_and_pubkey(script_sig: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parses a standard Legacy P2PKH scriptSig (<signature> <pubkey>)
    Returns (sig_hex, pubkey_hex)
    """
    if not script_sig:
        return None, None
    
    # Clean up
    script_sig = script_sig.strip()
    
    # Split by space (standard representation)
    parts = script_sig.split()
    
    if len(parts) >= 2:
        # Usually: <sig> <pubkey>
        # Sometimes push opcodes precede them, but in hex dumps from APIs, 
        # it's often just the raw hex concatenated or space separated.
        # If space separated:
        sig = parts[0]
        pubkey = parts[-1] # Pubkey is usually last
        return sig, pubkey
    
    # If no spaces, we have to guess based on lengths.
    # Pubkey is 66 chars (compressed) or 130 chars (uncompressed).
    # Signature is variable length DER.
    # This is hard without delimiters. 
    # Heuristic: Look for 02/03 at the end for compressed pubkey.
    
    # Try finding pubkey pattern at the end
    pk_match = re.search(r'(0[23][a-fA-F0-9]{64})$', script_sig)
    if pk_match:
        pubkey = pk_match.group(1)
        sig = script_sig[: -len(pubkey)].strip()
        return sig, pubkey
        
    return None, None

if __name__ == "__main__":
    # Test vector (Dummy DER sig)
    # 3045022100...0220...01
    test_sig = "3045022100c12b4fdd04dcd18b8c6a5c760d69f56a5c760d69f56a5c760d69f56a5c760d6902205f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f01"
    r, s = decode_der_signature(test_sig)
    print(f"Test R: {hex(r)}")
    print(f"Test S: {hex(s)}")
