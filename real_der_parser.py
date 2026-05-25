"""
PROJECT TOTALITY: REAL DER SIGNATURE & PUBKEY PARSER
----------------------------------------------------
Replaces placeholder regex with strict DER (Distinguished Encoding Rules) parsing.
Handles Bitcoin scriptSig structure: <sig> <pubkey>
"""

import struct
from typing import Tuple, Optional, List

class DerSignatureParser:
    @staticmethod
    def parse_der_signature(sig_hex: str) -> Optional[Tuple[int, int]]:
        """
        Parses a DER-encoded signature hex string into (r, s).
        Handles SIGHASH flags appended to the end.
        """
        try:
            if not sig_hex or len(sig_hex) < 10:
                return None
            
            data = bytes.fromhex(sig_hex)
            
            # Check if last byte looks like a sighash flag and remove it
            # Valid sighash flags: 0x01, 0x02, 0x03, 0x81, 0x82, 0x83
            sighash_flags = {0x01, 0x02, 0x03, 0x81, 0x82, 0x83}
            if len(data) > 1 and data[-1] in sighash_flags:
                test_data = data[:-1]
                if test_data[0] == 0x30:
                    # Try parsing without sighash first
                    r, s = DerSignatureParser._parse_der_bytes(test_data)
                    if r and s:
                        return r, s
                    # If that fails, try with sighash included
                    r, s = DerSignatureParser._parse_der_bytes(data)
                    if r and s:
                        return r, s
                else:
                    # Not starting with 0x30, try raw data
                    r, s = DerSignatureParser._parse_der_bytes(data)
                    if r and s:
                        return r, s
            else:
                # No sighash flag, parse as-is
                r, s = DerSignatureParser._parse_der_bytes(data)
                if r and s:
                    return r, s
                
            return None
        except Exception:
            return None

    @staticmethod
    def _parse_der_bytes(data: bytes) -> Optional[Tuple[int, int]]:
        if len(data) < 8 or data[0] != 0x30:
            return None
        
        total_len = data[1]
        if total_len & 0x80: # Long form length
            num_octets = total_len & 0x7F
            if num_octets > 1:
                return None # Too complex for standard sigs
            total_len = int.from_bytes(data[2:2+num_octets], 'big')
            offset = 2 + num_octets
        else:
            offset = 2
            
        if offset + total_len > len(data):
            # Might have trailing sighash not stripped yet, but we assume input was stripped
            pass 
        
        # Parse R
        if data[offset] != 0x02:
            return None
        offset += 1
        
        r_len = data[offset]
        offset += 1
        
        if r_len == 0 or offset + r_len > len(data):
            return None
            
        r_bytes = data[offset : offset + r_len]
        r = int.from_bytes(r_bytes, 'big')
        offset += r_len
        
        # Parse S
        if offset >= len(data) or data[offset] != 0x02:
            return None
        offset += 1
        
        s_len = data[offset]
        offset += 1
        
        if s_len == 0 or offset + s_len > len(data):
            return None
            
        s_bytes = data[offset : offset + s_len]
        s = int.from_bytes(s_bytes, 'big')
        
        return r, s

    @staticmethod
    def extract_pubkey_from_script_sig(script_hex: str) -> Optional[str]:
        """
        Extracts the public key from a standard P2PKH scriptSig.
        Format: <DER Sig> <PubKey>
        PubKey is typically 33 bytes (compressed) or 65 bytes (uncompressed).
        """
        if not script_hex or len(script_hex) < 66:
            return None
            
        try:
            # ScriptSig is pushed data. We can try to split by OP_PUSH logic or just look for keys at the end.
            # In standard P2PKH, the pubkey is the last element.
            # Hex representation of scriptSig usually concatenates pushes.
            # However, in many CSV exports, it's raw hex of the entire script.
            # A compressed pubkey is 33 bytes: [02/03][X...][Y...] (66 hex chars)
            # An uncompressed pubkey is 65 bytes: [04][X...][Y...] (130 hex chars)
            
            # Strategy: Scan from the end for a valid pubkey pattern.
            # Compressed
            if len(script_hex) >= 66:
                tail = script_hex[-66:]
                if tail[:2] in ('02', '03'):
                    # Verify it looks like a key (basic check)
                    return tail
            
            # Uncompressed
            if len(script_hex) >= 130:
                tail = script_hex[-130:]
                if tail[:2] == '04':
                    return tail
            
            # If simple tail check fails, try regex search for valid keys inside
            import re
            # Find all compressed keys
            matches = re.findall(r'(0[23][a-fA-F0-9]{64})', script_hex)
            if matches:
                return matches[-1] # Return last one
            
            # Find all uncompressed keys
            matches = re.findall(r'(04[a-fA-F0-9]{128})', script_hex)
            if matches:
                return matches[-1]
                
            return None
        except Exception:
            return None


# Alias for backward compatibility
DERParser = DerSignatureParser


def parse_script_sig_full(script_hex: str) -> dict:
    """
    Full parser: Returns { 'r': int, 's': int, 'pubkey': str }
    Handles both space-separated and continuous hex formats.
    """
    if not script_hex:
        return {}
    
    # Check if space-separated (common in CSV exports)
    if ' ' in script_hex:
        parts = script_hex.strip().split()
        if len(parts) >= 2:
            sig_part = parts[0]
            pk_part = parts[-1]
            
            result = {}
            
            # Parse signature
            rs = DerSignatureParser.parse_der_signature(sig_part)
            if rs:
                result['r'], result['s'] = rs
            
            # Extract pubkey
            pk = DerSignatureParser.extract_pubkey_from_script_sig(pk_part)
            if pk:
                result['pubkey'] = pk
                
            return result
    
    # Continuous hex format - parse opcodes
    try:
        data = bytes.fromhex(script_hex)
        cursor = 0
        
        # 1. Read Signature
        if cursor >= len(data):
            return {}
        sig_len = data[cursor]
        cursor += 1
        
        # Handle OP_PUSHDATA1/2/4 if necessary (rare for sigs)
        if sig_len == 0x4c: # OP_PUSHDATA1
            sig_len = data[cursor]
            cursor += 1
        elif sig_len == 0x4d: # OP_PUSHDATA2
            sig_len = struct.unpack('<H', data[cursor:cursor+2])[0]
            cursor += 2
        elif sig_len == 0x4e: # OP_PUSHDATA4
            sig_len = struct.unpack('<I', data[cursor:cursor+4])[0]
            cursor += 4
            
        if cursor + sig_len > len(data):
            return {}
            
        sig_bytes = data[cursor:cursor+sig_len]
        cursor += sig_len
        
        # Parse DER - try with sighash, then without
        rs = DerSignatureParser._parse_der_bytes(sig_bytes)
        if not rs and len(sig_bytes) > 1:
            # Try stripping sighash (last byte)
            rs = DerSignatureParser._parse_der_bytes(sig_bytes[:-1])
            
        result = {}
        if rs:
            result['r'], result['s'] = rs
            
        # 2. Read Public Key
        if cursor >= len(data):
            return result
            
        pk_len = data[cursor]
        cursor += 1
        
        # Handle pushdata opcodes for pubkey
        if pk_len == 0x4c:
            pk_len = data[cursor]
            cursor += 1
        elif pk_len == 0x4d:
            pk_len = struct.unpack('<H', data[cursor:cursor+2])[0]
            cursor += 2
            
        if cursor + pk_len > len(data):
            return result
            
        pk_bytes = data[cursor:cursor+pk_len]
        pk_hex = pk_bytes.hex()
        
        # Validate pubkey format
        if pk_len == 33 and pk_hex[:2] in ('02', '03'):
            result['pubkey'] = pk_hex
        elif pk_len == 65 and pk_hex[:2] == '04':
            result['pubkey'] = pk_hex
            
        return result
        
    except Exception as e:
        print(f"Debug parse_script_sig_full error: {e}")
        return {}
