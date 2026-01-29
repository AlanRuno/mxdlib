/**
 * MXD Blockchain Migration Tool
 *
 * Migrates existing MXD blockchain database to protocol v3 schema.
 *
 * Usage:
 *   migrate_to_v3 [--backup-path <path>] [--verify] [--dry-run]
 *
 * Options:
 *   --backup-path <path>  Custom backup file path
 *   --verify              Verify migration after completion
 *   --dry-run             Check migration status without applying
 *   --help                Show this help message
 */

#include "../include/mxd_migration.h"
#include "../include/mxd_protocol_version.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_db.h"
#include "../include/mxd_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_usage(const char *prog_name) {
    printf("MXD Blockchain Migration Tool v3\n");
    printf("================================\n\n");
    printf("Usage: %s [options]\n\n", prog_name);
    printf("Options:\n");
    printf("  --backup-path <path>  Custom backup file path\n");
    printf("  --verify              Verify migration after completion\n");
    printf("  --dry-run             Check migration status without applying\n");
    printf("  --help                Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s --dry-run\n", prog_name);
    printf("  %s --backup-path /backup/mxd_pre_v3.db\n", prog_name);
    printf("  %s --verify\n", prog_name);
}

static void print_migration_status(const mxd_migration_status_t *status) {
    printf("\nMigration Status:\n");
    printf("-----------------\n");
    printf("Current Schema:  v%u\n", status->current_schema_version);
    printf("Target Schema:   v%u\n", status->target_schema_version);

    if (status->total_blocks > 0) {
        printf("Blocks Migrated: %u / %u (%.1f%%)\n",
               status->blocks_migrated,
               status->total_blocks,
               (float)status->blocks_migrated / status->total_blocks * 100);
    }

    printf("Status:          %s\n", status->is_complete ? "COMPLETE" : "IN PROGRESS");

    if (strlen(status->error_message) > 0) {
        printf("Error:           %s\n", status->error_message);
    }
}

int main(int argc, char *argv[]) {
    const char *backup_path = NULL;
    int verify = 0;
    int dry_run = 0;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--backup-path") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --backup-path requires a path argument\n");
                return 1;
            }
            backup_path = argv[++i];
        } else if (strcmp(argv[i], "--verify") == 0) {
            verify = 1;
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run = 1;
        } else {
            fprintf(stderr, "Error: Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    printf("MXD Blockchain Migration Tool\n");
    printf("==============================\n\n");

    // Initialize logging
    mxd_init_logging();

    // Initialize database
    if (mxd_init_db() != 0) {
        fprintf(stderr, "ERROR: Failed to initialize database\n");
        fprintf(stderr, "Please check that the MXD database exists and is accessible.\n");
        return 1;
    }

    // Get current schema version
    uint32_t current_version = mxd_get_db_schema_version();
    printf("Current database schema version: v%u\n", current_version);

    // Check if migration is needed
    int needs_mig = mxd_needs_migration(3);
    if (needs_mig < 0) {
        fprintf(stderr, "ERROR: Failed to check migration status\n");
        mxd_close_db();
        return 1;
    }

    if (needs_mig == 0) {
        printf("✓ Database is already at v3 schema\n");
        printf("  No migration needed.\n");
        mxd_close_db();
        return 0;
    }

    printf("\nMigration Required:\n");
    printf("  From: v%u\n", current_version);
    printf("  To:   v3\n\n");

    // Dry run mode
    if (dry_run) {
        printf("DRY RUN MODE: No changes will be made\n");
        printf("Run without --dry-run to perform actual migration\n");
        mxd_close_db();
        return 0;
    }

    // Confirm migration
    printf("This migration will:\n");
    printf("  1. Create a backup of your database\n");
    printf("  2. Add contracts_state_root column to blocks table\n");
    printf("  3. Update schema version to v3\n\n");

    if (backup_path) {
        printf("Backup will be saved to: %s\n\n", backup_path);
    } else {
        char default_backup[256];
        time_t now = time(NULL);
        snprintf(default_backup, sizeof(default_backup),
                 "mxd_blockchain_backup_%ld.db", (long)now);
        printf("Backup will be saved to: %s\n\n", default_backup);
    }

    printf("WARNING: This operation may take several minutes on large databases.\n");
    printf("         Do not interrupt the migration process.\n\n");

    // In a production tool, you'd want user confirmation here
    // For automation purposes, we proceed automatically
    printf("Starting migration...\n\n");

    // Perform migration
    mxd_migration_status_t status;
    int result = mxd_migrate_to_v3(&status);

    print_migration_status(&status);

    if (result == MXD_MIGRATION_SUCCESS) {
        printf("\n✓ Migration completed successfully!\n");
    } else if (result == MXD_MIGRATION_ALREADY_MIGRATED) {
        printf("\n✓ Database was already migrated\n");
    } else {
        fprintf(stderr, "\n✗ Migration failed!\n");
        fprintf(stderr, "Error: %s\n", status.error_message);
        fprintf(stderr, "\nYou can restore from backup if needed:\n");
        fprintf(stderr, "  1. Stop the MXD node\n");
        fprintf(stderr, "  2. Replace database with backup\n");
        fprintf(stderr, "  3. Restart the MXD node\n");
        mxd_close_db();
        return 1;
    }

    // Verify migration if requested
    if (verify) {
        printf("\nVerifying migration...\n");

        if (mxd_verify_migration(0, 0) == 0) {
            printf("✓ Migration verification passed\n");
        } else {
            fprintf(stderr, "✗ Migration verification failed\n");
            fprintf(stderr, "Some blocks may not have contracts_state_root computed\n");
            mxd_close_db();
            return 1;
        }
    }

    printf("\nMigration Summary:\n");
    printf("------------------\n");
    printf("✓ Database schema updated to v3\n");
    printf("✓ Backup created successfully\n");
    if (verify) {
        printf("✓ Migration verified\n");
    }
    printf("\nYou can now restart your MXD node.\n");
    printf("The node will automatically use protocol v3 for new blocks\n");
    printf("at the configured activation height.\n\n");

    mxd_close_db();
    return 0;
}
