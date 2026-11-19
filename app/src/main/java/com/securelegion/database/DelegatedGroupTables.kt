package com.securelegion.database

import androidx.sqlite.db.SupportSQLiteDatabase

/** SQLCipher owned storage for the canonical mixed-history group host. */
internal object DelegatedGroupTables {
    fun create(db: SupportSQLiteDatabase) {
        val statements = arrayOf(
            "CREATE TABLE IF NOT EXISTS delegated_group_states (group_id TEXT NOT NULL PRIMARY KEY, state_hash TEXT NOT NULL, op_count INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, FOREIGN KEY(group_id) REFERENCES groups(groupId) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS delegated_group_acceptance (op_id TEXT NOT NULL PRIMARY KEY, group_id TEXT NOT NULL, operation_hash TEXT NOT NULL, accepted_at_ms INTEGER NOT NULL, UNIQUE(group_id,operation_hash), FOREIGN KEY(op_id) REFERENCES crdt_op_log(opId) ON DELETE CASCADE, FOREIGN KEY(group_id) REFERENCES groups(groupId) ON DELETE CASCADE)",
            "CREATE INDEX IF NOT EXISTS idx_delegated_group_acceptance_group ON delegated_group_acceptance(group_id)",
            "CREATE TABLE IF NOT EXISTS delegated_group_keys (group_id TEXT NOT NULL, epoch TEXT NOT NULL, secret BLOB NOT NULL CHECK(length(secret)=32), eligible INTEGER NOT NULL CHECK(eligible IN (0,1)), PRIMARY KEY(group_id,epoch), FOREIGN KEY(group_id) REFERENCES groups(groupId) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS delegated_group_ratifications (operation_hash TEXT NOT NULL PRIMARY KEY, group_id TEXT NOT NULL, proof BLOB NOT NULL, FOREIGN KEY(group_id) REFERENCES groups(groupId) ON DELETE CASCADE)",
            "CREATE INDEX IF NOT EXISTS idx_delegated_group_ratifications_group ON delegated_group_ratifications(group_id)",
            "CREATE TABLE IF NOT EXISTS delegated_group_origins (op_id TEXT NOT NULL PRIMARY KEY, group_id TEXT NOT NULL, local_device TEXT NOT NULL, created_at_ms INTEGER NOT NULL, FOREIGN KEY(op_id) REFERENCES crdt_op_log(opId) ON DELETE CASCADE, FOREIGN KEY(group_id) REFERENCES groups(groupId) ON DELETE CASCADE)",
            "CREATE INDEX IF NOT EXISTS idx_delegated_group_origins_group ON delegated_group_origins(group_id,created_at_ms)",
            "CREATE TABLE IF NOT EXISTS delegated_group_targets (op_id TEXT NOT NULL, target_account TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN ('live','invite')), PRIMARY KEY(op_id,target_account), FOREIGN KEY(op_id) REFERENCES delegated_group_origins(op_id) ON DELETE CASCADE)",
            "CREATE INDEX IF NOT EXISTS idx_delegated_group_targets_account ON delegated_group_targets(target_account)",
            "CREATE TABLE IF NOT EXISTS delegated_group_delivery_batches (id TEXT NOT NULL PRIMARY KEY, op_id TEXT NOT NULL, group_id TEXT NOT NULL, local_device TEXT NOT NULL, target_account TEXT NOT NULL, target_device TEXT NOT NULL, first_wire BLOB NOT NULL, operation_hashes TEXT NOT NULL, final_batch INTEGER NOT NULL CHECK(final_batch IN (0,1)), plan_signature BLOB NOT NULL, created_at_ms INTEGER NOT NULL, next_try_at_ms INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, UNIQUE(op_id,target_account,target_device), FOREIGN KEY(op_id,target_account) REFERENCES delegated_group_targets(op_id,target_account) ON DELETE CASCADE)",
            "CREATE INDEX IF NOT EXISTS idx_delegated_group_batches_due ON delegated_group_delivery_batches(next_try_at_ms,created_at_ms)",
            "CREATE TABLE IF NOT EXISTS delegated_group_delivery_chunks (batch_id TEXT NOT NULL, chunk_index INTEGER NOT NULL, wire BLOB NOT NULL, PRIMARY KEY(batch_id,chunk_index), FOREIGN KEY(batch_id) REFERENCES delegated_group_delivery_batches(id) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS delegated_group_delivery_progress (group_id TEXT NOT NULL, local_device TEXT NOT NULL, target_account TEXT NOT NULL, target_device TEXT NOT NULL, acknowledged TEXT NOT NULL, updated_at_ms INTEGER NOT NULL, PRIMARY KEY(group_id,local_device,target_account,target_device), FOREIGN KEY(group_id) REFERENCES groups(groupId) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS delegated_group_account_progress (group_id TEXT NOT NULL, local_device TEXT NOT NULL, target_account TEXT NOT NULL, acknowledged TEXT NOT NULL, updated_at_ms INTEGER NOT NULL, PRIMARY KEY(group_id,local_device,target_account), FOREIGN KEY(group_id) REFERENCES groups(groupId) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS delegated_group_delivery_completed (op_id TEXT NOT NULL, target_account TEXT NOT NULL, target_device TEXT NOT NULL, PRIMARY KEY(op_id,target_account,target_device), FOREIGN KEY(op_id,target_account) REFERENCES delegated_group_targets(op_id,target_account) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS delegated_group_inbox (id TEXT NOT NULL PRIMARY KEY, local_device TEXT NOT NULL, group_id TEXT NOT NULL, sender_account TEXT NOT NULL, sender_device TEXT NOT NULL, bundle_id BLOB NOT NULL, bundle_hash BLOB NOT NULL CHECK(length(bundle_hash)=32), bundle_length INTEGER NOT NULL, chunk_count INTEGER NOT NULL, first_wire BLOB NOT NULL, first_received_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_delegated_group_inbox_expiry ON delegated_group_inbox(expires_at_ms)",
            "CREATE TABLE IF NOT EXISTS delegated_group_inbox_chunks (transfer_id TEXT NOT NULL, chunk_index INTEGER NOT NULL, plaintext BLOB NOT NULL, chunk_hash TEXT NOT NULL, wire_hash TEXT NOT NULL, PRIMARY KEY(transfer_id,chunk_index), FOREIGN KEY(transfer_id) REFERENCES delegated_group_inbox(id) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS delegated_group_inbound_receipts (id TEXT NOT NULL PRIMARY KEY, local_device TEXT NOT NULL, group_id TEXT NOT NULL, sender_account TEXT NOT NULL, sender_device TEXT NOT NULL, bundle_hash BLOB NOT NULL CHECK(length(bundle_hash)=32), bundle_length INTEGER NOT NULL, chunk_count INTEGER NOT NULL, ack BLOB NOT NULL, accepted_at_ms INTEGER NOT NULL, account_ack_sent_at_ms INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(group_id) REFERENCES groups(groupId) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS delegated_group_trusted_rosters (account_ed TEXT NOT NULL PRIMARY KEY, roster BLOB NOT NULL, epoch INTEGER NOT NULL, roster_hash BLOB NOT NULL CHECK(length(roster_hash)=32), accepted_at_ms INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS delegated_group_principals (group_id TEXT NOT NULL, account_ed TEXT NOT NULL, PRIMARY KEY(group_id,account_ed), FOREIGN KEY(group_id) REFERENCES groups(groupId) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS delegated_group_message_outbox (id TEXT NOT NULL PRIMARY KEY, group_id TEXT NOT NULL, local_device TEXT NOT NULL, text TEXT NOT NULL CHECK(length(CAST(text AS BLOB)) BETWEEN 1 AND 30720), created_at_ms INTEGER NOT NULL, next_try_at_ms INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(group_id) REFERENCES groups(groupId) ON DELETE CASCADE)",
            "CREATE INDEX IF NOT EXISTS idx_delegated_group_message_due ON delegated_group_message_outbox(next_try_at_ms,created_at_ms)"
        )
        statements.forEach(db::execSQL)
    }
}
