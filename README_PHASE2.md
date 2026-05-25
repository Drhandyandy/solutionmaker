# 🚀 PROJECT TOTALITY: API FETCHER IMPLEMENTATION

## ✅ FILES CREATED

| File | Purpose |
|------|---------|
| `blockchain_api_fetcher.py` | Core API fetcher with rate limiting, caching, R/S extraction |
| `enhanced_z_calculator.py` | Accurate Z (message hash) calculation using python-bitcoinlib |
| `phase2_complete_workflow.py` | End-to-end Phase 2 pipeline (CSV → Attack Chains) |
| `requirements.txt` | Python dependencies |

---

## 📦 INSTALLATION

```bash
# Install basic dependencies
pip install -r requirements.txt

# For accurate Z calculation (RECOMMENDED)
pip install python-bitcoinlib

# For Phase 3 (Lattice Attack) - requires conda/mamba
pip install condacolab
# Then in Python/notebook:
import condacolab
condacolab.install()
# After restart:
!mamba install -c conda-forge sage fpylll python=3.11
```

---

## 🔧 USAGE

### Option 1: Complete Workflow (Recommended)

Run the full Phase 2 pipeline:

```bash
python phase2_complete_workflow.py \
    --input /path/to/absolute_bridge_state.csv \
    --output-dir phase2_output \
    --min-sigs 3 \
    --rate-limit 0.5 \
    --limit 100
```

**Parameters:**
- `--input`: Path to your CSV file (required)
- `--output-dir`: Output directory (default: `phase2_output`)
- `--min-sigs`: Minimum signatures per pubkey for attack (default: 3)
- `--rate-limit`: API rate limit in seconds (default: 0.5)
- `--limit`: Max targets to process (default: all)

### Option 2: Programmatic Usage

```python
from phase2_complete_workflow import Phase2Workflow

# Initialize workflow
workflow = Phase2Workflow(
    csv_path='/path/to/absolute_bridge_state.csv',
    output_dir='phase2_output',
    min_sigs_per_key=3,
    api_rate_limit=0.5,
    max_targets=100  # Optional limit
)

# Run complete pipeline
success = workflow.run()

if success:
    print("✅ Phase 2 complete!")
    print(f"Attack chains: {len(workflow.attack_chains)}")
    print(f"Biased chains: {len(workflow.bias_results)}")
```

### Option 3: Standalone API Fetcher

```python
from blockchain_api_fetcher import BlockchainAPIFetcher

# Initialize fetcher
fetcher = BlockchainAPIFetcher(
    rate_limit=0.5,
    cache_file='my_cache.json'
)

# Fetch single transaction
tx_data = fetcher.fetch_transaction('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16')

# Fetch batch
txids = ['txid1', 'txid2', 'txid3']
results = fetcher.fetch_batch(txids)

# Extract and group into attack chains
from blockchain_api_fetcher import fetch_chains_for_attack
attack_chains = fetch_chains_for_attack(fetcher, txids, min_sigs_per_key=3)
```

### Option 4: Enhanced Z Calculator (Accurate Message Hash)

```python
from enhanced_z_calculator import EnhancedBlockchainFetcher

# Initialize enhanced fetcher (proper Z calculation)
fetcher = EnhancedBlockchainFetcher(
    rate_limit=0.5,
    cache_file='enhanced_cache.json'
)

# Fetch with accurate Z value
result = fetcher.fetch_transaction_with_z('txid_here')

if result:
    print(f"R: {result['r_hex']}")
    print(f"S: {result['s_hex']}")
    print(f"Z: {result['z_hex']}")
    print(f"Z Valid: {result['z_valid']}")  # True = cryptographically accurate
```

---

## 📊 OUTPUT FILES

After running Phase 2, you'll get:

| File | Description |
|------|-------------|
| `attack_chains_full.json` | Complete attack chains with all (R,S,Z) tuples |
| `attack_chains_summary.csv` | Summary table of all chains |
| `biased_chains_priority.json` | Prioritized list of biased chains |
| `workflow_metadata.json` | Execution metadata and statistics |
| `*_cache.json` | Transaction cache (resumable) |

---

## 🔍 KEY FEATURES

### 1. Rate Limiting & Caching
- Configurable rate limiting (default: 0.5s between requests)
- Persistent JSON cache (resumable after interruption)
- Automatic cache saves every N transactions

### 2. Robust Error Handling
- Retry logic with exponential backoff
- 429 (Rate Limit) handling
- Timeout handling
- 404 detection

### 3. Signature Extraction
- DER signature parsing
- SIGHASH flag removal
- Compressed public key extraction
- SegWit witness support

### 4. Z (Message Hash) Calculation
- **Accurate**: Uses `python-bitcoinlib` for proper sighash
- **Fallback**: Simplified hash if library unavailable
- **Validation**: Flags placeholder vs. real Z values

### 5. Bias Detection
- Small R value detection (k < 2^128)
- Upper bit repetition analysis
- Lower bit repetition analysis
- Composite bias score (0-1)

---

## ⚠️ CRITICAL NOTES

### Z Value Accuracy
The message hash (Z) **MUST** be calculated correctly for HNP lattice attacks to work. 

**With python-bitcoinlib:**
```python
✅ Accurate BIP143/BIP340 sighash calculation
✅ Handles SIGHASH types correctly
✅ Works for Legacy P2PKH and SegWit
```

**Without python-bitcoinlib:**
```python
⚠️ Fallback uses simplified double-SHA256
⚠️ May be inaccurate for complex transactions
⚠️ Lattice attack may fail with incorrect Z
```

**Recommendation:** Always install `python-bitcoinlib` for production use.

### API Rate Limits
- mempool.space free tier: ~1 request/second
- Adjust `--rate-limit` parameter accordingly
- Consider running a local ElectrumX or bitcoind for high-volume needs

### Security Warning
⚠️ **DO NOT PRINT PRIVATE KEYS TO CONSOLE** ⚠️

When you implement Phase 3 (lattice attack), ensure recovered private keys are:
1. Written to encrypted local files only
2. Never printed to stdout/logs
3. Deleted securely after use

---

## 🎯 NEXT STEPS

### Phase 3: Lattice Attack
Once you have `attack_chains_full.json`:

1. Install lattice libraries:
   ```bash
   pip install condacolab
   # In notebook:
   import condacolab; condacolab.install()
   !mamba install -c conda-forge sage fpylll python=3.11
   ```

2. Implement BKZ reduction attack on biased chains

3. Recover private keys from lattice output

4. Verify recovered keys against blockchain

### Immediate Testing
Test with a small sample first:

```bash
python phase2_complete_workflow.py \
    --input absolute_bridge_state.csv \
    --limit 10 \
    --rate-limit 1.0
```

This processes 10 transactions with conservative rate limiting.

---

## 📞 TROUBLESHOOTING

### "ModuleNotFoundError: No module named 'bitcoin'"
```bash
pip install python-bitcoinlib
```

### "Rate limited by API"
Increase rate limit:
```bash
python phase2_complete_workflow.py --rate-limit 2.0
```

### "No attack chains found"
- Lower `--min-sigs` to 2
- Increase `--limit` to process more targets
- Check if CSV has valid scriptSig data

### "Z Valid: False"
- Install `python-bitcoinlib` for accurate calculation
- Without it, Z values are placeholders (not attack-ready)

---

## 📈 PERFORMANCE ESTIMATES

| Targets | Rate Limit | Est. Time | Cache Size |
|---------|------------|-----------|------------|
| 100 | 0.5s | ~1 min | ~50 KB |
| 1,000 | 0.5s | ~8 min | ~500 KB |
| 5,166 | 0.5s | ~43 min | ~2.5 MB |
| 5,166 | 1.0s | ~86 min | ~2.5 MB |

*Times are approximate and depend on network conditions.*

---

**Status:** ✅ Phase 2 Implementation Complete  
**Next:** Ready for execution on your dataset
