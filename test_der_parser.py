"""
PROJECT TOTALITY: UNIT TEST FOR DER PARSER
Tests real DER parsing without mocks.
"""

from real_der_parser import DerSignatureParser, parse_script_sig_full

# Test 1: Known Bitcoin transaction signature (Satoshi's first TX)
# txid: f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
TEST_SCRIPT_SIG = "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901 04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c"

print("🧪 TEST 1: Parse known scriptSig")
result = parse_script_sig_full(TEST_SCRIPT_SIG)

if result:
    print(f"   ✅ R: {hex(result.get('r', 0))[:20]}...")
    print(f"   ✅ S: {hex(result.get('s', 0))[:20]}...")
    print(f"   ✅ PubKey: {result.get('pubkey', 'MISSING')[:20]}...")
    
    # Verify expected values
    expected_r = 0x4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41
    expected_s = 0x181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09
    expected_pk = "04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c"
    
    if result.get('r') == expected_r:
        print("   ✅ R value MATCHES expected")
    else:
        print(f"   ❌ R value MISMATCH (got {hex(result.get('r'))}, expected {hex(expected_r)})")
        
    if result.get('s') == expected_s:
        print("   ✅ S value MATCHES expected")
    else:
        print(f"   ❌ S value MISMATCH (got {hex(result.get('s'))}, expected {hex(expected_s)})")
        
    if result.get('pubkey') == expected_pk:
        print("   ✅ PubKey MATCHES expected")
    else:
        print(f"   ❌ PubKey MISMATCH")
else:
    print("   ❌ FAILED to parse scriptSig")

# Test 2: Compressed pubkey format (valid DER signature)
# Signature: 30 44 02 20 [R:32] 02 20 [S:32] 01
TEST_COMPRESSED = "3044022073c4d5f7c9e5f8a6b3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b002201234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef01 03a1af804ac108a8a5178219832ef62ada46a26c0a6eac923f455c4e1a3b1e02fb"

print("\n🧪 TEST 2: Parse compressed pubkey scriptSig")
result2 = parse_script_sig_full(TEST_COMPRESSED)

if result2:
    print(f"   ✅ R parsed: {hex(result2.get('r', 0))[:20]}...")
    print(f"   ✅ S parsed: {hex(result2.get('s', 0))[:20]}...")
    pk = result2.get('pubkey', '')
    if pk.startswith('03') and len(pk) == 66:
        print(f"   ✅ Compressed PubKey valid: {pk[:20]}...")
    else:
        print(f"   ❌ Compressed PubKey invalid: {pk}")
else:
    print("   ❌ FAILED to parse compressed scriptSig")

# Test 3: Edge case - no pubkey
print("\n🧪 TEST 3: Edge case - invalid input")
result3 = parse_script_sig_full("")
if not result3 or not result3.get('pubkey'):
    print("   ✅ Correctly returns empty for invalid input")
else:
    print("   ⚠️ Should return empty for invalid input")

print("\n" + "="*60)
print("✅ DER PARSER UNIT TEST COMPLETE")
print("="*60)
