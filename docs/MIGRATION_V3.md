# MXD Protocol V3 Migration Guide

## Overview

This guide describes how to migrate your MXD node from protocol v2 to v3. Protocol v3 introduces smart contract state root tracking in the blockchain, which is required for the upcoming bridge functionality.

## Version History

| Version | Features | Activation Heights |
|---------|----------|-------------------|
| **v1** | Initial blockchain with SHA-512 and Ed25519 | Genesis |
| **v2** | Hybrid cryptography (Ed25519 + Dilithium5) | Mainnet: 10,000<br>Testnet: 1,000 |
| **v3** | Smart contracts with state root tracking | **Mainnet: 100,000**<br>**Testnet: 5,000**<br>Devnet: 0 |

## What Changes in V3?

### Database Schema
- **New Column**: `contracts_state_root` (64 bytes) added to `blocks` table
- Stores SHA-512 Merkle root of all contract states in each block
- Required for validating smart contract execution across nodes

### Block Structure
```c
typedef struct {
    // ... existing fields ...
    uint8_t contracts_state_root[64];  // NEW: State root for v3+
    // ... rest of fields ...
} mxd_block_t;
```

### Block Hash Calculation
- V3 blocks include `contracts_state_root` in the block hash
- This creates a different hash than v1/v2 blocks with same transaction set
- **Ensures fork protection** during protocol upgrade

## Pre-Migration Checklist

Before migrating, ensure:

- [ ] You have **sufficient disk space** (at least 2x current database size for backup)
- [ ] **Stop your MXD node** completely before migration
- [ ] **Backup your database** manually (recommended in addition to automatic backup)
- [ ] Your node is **fully synced** with the network
- [ ] You have **read/write permissions** on the database directory
- [ ] **Note your current block height** for reference

## Migration Methods

### Method 1: Automatic Migration Tool (Recommended)

The migration tool handles everything automatically:

```bash
# Check migration status (dry run)
./migrate_to_v3 --dry-run

# Perform migration with verification
./migrate_to_v3 --verify

# Perform migration with custom backup path
./migrate_to_v3 --backup-path /path/to/backup/mxd_pre_v3.db --verify
```

**Expected Output:**
```
MXD Blockchain Migration Tool
==============================

Current database schema version: v2

Migration Required:
  From: v2
  To:   v3

Starting migration...

✓ Backup created: mxd_blockchain_backup_1234567890.db
✓ Schema updated to v3
✓ Migration completed successfully!

Verifying migration...
✓ Migration verification passed
```

### Method 2: Manual Migration (Advanced)

If you prefer manual control or need to customize the process:

#### Step 1: Create Backup
```bash
# Stop MXD node
systemctl stop mxd

# Create backup
cp /path/to/mxd_blockchain.db /backup/mxd_blockchain_pre_v3.db
```

#### Step 2: Apply Schema Changes
```sql
-- Connect to database
sqlite3 /path/to/mxd_blockchain.db

-- Add new column
ALTER TABLE blocks ADD COLUMN contracts_state_root BLOB;

-- Create schema_version table if not exists
CREATE TABLE IF NOT EXISTS schema_version (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version INTEGER NOT NULL,
    migrated_at INTEGER NOT NULL
);

-- Update schema version
INSERT INTO schema_version (version, migrated_at)
VALUES (3, strftime('%s', 'now'));

-- Verify
SELECT version FROM schema_version ORDER BY id DESC LIMIT 1;
-- Should return: 3
```

#### Step 3: Verify Migration
```bash
# Run verification
./migrate_to_v3 --verify
```

#### Step 4: Restart Node
```bash
systemctl start mxd
```

## Activation Heights

Protocol v3 will automatically activate at these heights:

| Network | Activation Height | Estimated Date |
|---------|------------------|----------------|
| **Mainnet** | 100,000 | TBD (coordinate with network) |
| **Testnet** | 5,000 | TBD (for testing) |
| **Devnet** | 0 | Immediate (genesis) |

### Before Activation
- Blocks continue using v2 format
- `contracts_state_root` is set to zero
- No smart contracts can execute

### At Activation
- **All new blocks MUST use v3 format**
- Nodes automatically switch to v3 block creation
- Smart contracts become enabled
- Bridge functionality becomes available

### After Activation
- V2 blocks are **rejected** by the network
- All nodes must have migrated database schema
- Unmigrated nodes will **stop syncing** and fall out of consensus

## Rollback Procedure

If you need to rollback (e.g., migration failed):

### Before Activation Height
```bash
# Stop node
systemctl stop mxd

# Restore from backup
mv /backup/mxd_blockchain_pre_v3.db /path/to/mxd_blockchain.db

# Restart node
systemctl start mxd
```

### After Activation Height
**⚠️ WARNING**: Rolling back after activation is **NOT RECOMMENDED** as:
- You will be incompatible with the network
- Cannot sync new v3 blocks
- Will be on a different fork

If absolutely necessary:
1. Restore from backup (as above)
2. **Do not restart** - you'll be out of sync
3. Wait for network coordination or consider re-syncing from scratch

## Verification Steps

After migration, verify success:

### 1. Check Schema Version
```bash
sqlite3 /path/to/mxd_blockchain.db \
  "SELECT version FROM schema_version ORDER BY id DESC LIMIT 1"
```
Expected output: `3`

### 2. Check Column Exists
```bash
sqlite3 /path/to/mxd_blockchain.db \
  "PRAGMA table_info(blocks)" | grep contracts_state_root
```
Expected output: `contracts_state_root|BLOB|0||0`

### 3. Check Node Logs
```bash
tail -f /var/log/mxd/node.log | grep -i "protocol\|version"
```
Expected: `Initialized block at height XXXXX with protocol v3`

### 4. Check Block Creation
```bash
# After activation height, check latest block
mxd-cli getblock latest --verbose
```
Expected output includes: `"version": 3`

## Troubleshooting

### Issue: "Database is locked"
**Cause**: MXD node is still running
**Solution**: Stop the node completely before migration
```bash
systemctl stop mxd
# Wait 10 seconds
./migrate_to_v3 --verify
```

### Issue: "Failed to create backup"
**Cause**: Insufficient disk space
**Solution**: Free up space or use custom backup path on different drive
```bash
./migrate_to_v3 --backup-path /mnt/backup/mxd_pre_v3.db
```

### Issue: "Migration verification failed"
**Cause**: Corrupted database or interrupted migration
**Solution**: Restore from backup and retry
```bash
systemctl stop mxd
mv /backup/mxd_blockchain_pre_v3.db /path/to/mxd_blockchain.db
./migrate_to_v3 --verify
```

### Issue: "Node stops syncing after migration"
**Cause**: Migration done too early (before activation height)
**Solution**: This is expected behavior. Node will resume syncing at activation height when network switches to v3.

### Issue: "contracts_state_root is always zero"
**Cause**: No contract transactions in blocks (expected before bridge deployment)
**Solution**: This is normal. State root will be non-zero only for blocks with contract executions.

## Timeline & Coordination

### Testnet Migration
1. **Week 1**: Announce migration schedule
2. **Week 2**: Node operators migrate databases
3. **Week 3**: V3 activates at height 5,000
4. **Week 4**: Monitor and verify all nodes synced

### Mainnet Migration
1. **Week 1-2**: Finalize and test on testnet
2. **Week 3**: Announce mainnet schedule (2 week notice)
3. **Week 4-5**: Node operators migrate databases
4. **Week 6**: V3 activates at height 100,000
5. **Week 7+**: Bridge contracts deployed

## FAQ

**Q: Can I migrate before the activation height?**
A: Yes! Migration only changes the database schema. Your node will continue creating v2 blocks until activation height.

**Q: What happens if I don't migrate?**
A: After activation, your node will be unable to sync v3 blocks and will stop updating. You'll fall out of consensus.

**Q: Do I need to re-sync the entire blockchain?**
A: No! Migration is in-place and only updates the schema. Existing blocks remain unchanged.

**Q: How long does migration take?**
A: Usually < 1 minute for databases under 10GB. Larger databases may take 5-10 minutes.

**Q: Can I run multiple nodes from one database?**
A: Not recommended. Each node should have its own database. Migrate each separately.

**Q: What if I'm using Docker?**
A: Stop the container, run migration on the mounted volume, restart container:
```bash
docker stop mxd-node
./migrate_to_v3 --verify
docker start mxd-node
```

## Support

If you encounter issues during migration:

1. **Check logs**: `/var/log/mxd/node.log`
2. **Verify backup exists** before attempting rollback
3. **Ask for help**:
   - Discord: https://discord.gg/mxdnetwork
   - GitHub Issues: https://github.com/mxdnetwork/mxd/issues
   - Email: support@mxdnetwork.com

## Post-Migration

After successful migration:

- ✅ Node continues operating normally until activation
- ✅ Automatic switch to v3 at activation height
- ✅ Smart contracts become enabled
- ✅ Bridge functionality available
- ✅ No further action required

**Congratulations!** Your node is ready for protocol v3 🎉
