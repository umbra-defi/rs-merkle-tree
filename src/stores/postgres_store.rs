// Copyright 2025 Bilinear Labs - MIT License

//! PostgreSQL store implementation.

#[cfg(feature = "postgres_store")]
use crate::{MerkleError, Node, Store};
#[cfg(feature = "postgres_store")]
use super::store::MultiTreeStore;
#[cfg(feature = "postgres_store")]
use postgres::{Client, NoTls};
#[cfg(feature = "postgres_store")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "postgres_store")]
use std::sync::Mutex;

#[cfg(feature = "postgres_store")]
pub struct PostgresStore {
    inner: Mutex<Client>,
    tree_index: i64,
    // Keeping an in-memory counter to avoid querying on every access.
    num_leaves: AtomicU64,
}

#[cfg(feature = "postgres_store")]
const MAX_PARAMS: usize = 256;

#[cfg(feature = "postgres_store")]
impl PostgresStore {
    const KEY_NUM_LEAVES: &'static str = "NUM_LEAVES";

    /// Convert postgres::Error into a detailed MerkleError (message + detail).
    fn postgres_error(err: postgres::Error) -> MerkleError {
        let msg = err
            .as_db_error()
            .map(|db| {
                let mut s = db.message().to_string();
                if let Some(d) = db.detail() {
                    s.push_str("; ");
                    s.push_str(d);
                }
                s
            })
            .unwrap_or_else(|| err.to_string());
        MerkleError::StoreError(msg)
    }

    fn decode_node(bytes: &[u8]) -> Result<Node, MerkleError> {
        let arr: [u8; Node::LEN] = bytes
            .try_into()
            .map_err(|_| MerkleError::StoreError("invalid node length".into()))?;
        Ok(Node::from(arr))
    }

    /// Creates a new PostgresStore for tree index 0.
    /// Use [MultiTreeStore::for_tree](crate::stores::MultiTreeStore::for_tree) for other tree indexes.
    ///
    /// # Arguments
    /// * `connection_string` - PostgreSQL connection string (e.g., "host=localhost user=postgres dbname=merkle")
    ///
    /// # Panics
    /// Panics if unable to connect to the database or create the required tables.
    pub fn new(connection_string: &str) -> Self {
        Self::new_with_tree_index(connection_string, 0)
    }

    /// Creates a new PostgresStore for tree index 0 with all data for that tree cleared.
    /// Use [MultiTreeStore::for_tree_clean](crate::stores::MultiTreeStore::for_tree_clean) for other tree indexes.
    pub fn new_clean(connection_string: &str) -> Self {
        Self::new_clean_with_tree_index(connection_string, 0)
    }

    /// Returns a store for the given tree index (loads existing state).
    /// See [MultiTreeStore::for_tree](crate::stores::MultiTreeStore::for_tree).
    pub fn for_tree(connection: &str, tree_index: i64) -> Self {
        Self::new_with_tree_index(connection, tree_index)
    }

    /// Returns a store for the given tree index with all data for that tree cleared.
    /// See [MultiTreeStore::for_tree_clean](crate::stores::MultiTreeStore::for_tree_clean).
    pub fn for_tree_clean(connection: &str, tree_index: i64) -> Self {
        Self::new_clean_with_tree_index(connection, tree_index)
    }

    fn new_with_tree_index(connection_string: &str, tree_index: i64) -> Self {
        let mut client =
            Client::connect(connection_string, NoTls).expect("failed to connect to PostgreSQL");

        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS merkle_nodes (
                    tree_index BIGINT NOT NULL,
                    level      INTEGER NOT NULL,
                    idx        BIGINT NOT NULL,
                    node       BYTEA NOT NULL CHECK(octet_length(node) = 32),
                    PRIMARY KEY(tree_index, level, idx)
                );
                CREATE TABLE IF NOT EXISTS merkle_metadata (
                    tree_index BIGINT NOT NULL,
                    key        TEXT NOT NULL,
                    value      BYTEA NOT NULL,
                    PRIMARY KEY(tree_index, key)
                );",
            )
            .expect("failed to create tables");

        let num_leaves: u64 = client
            .query_opt(
                "SELECT value FROM merkle_metadata WHERE tree_index = $1 AND key = $2",
                &[&tree_index, &Self::KEY_NUM_LEAVES],
            )
            .expect("failed to query num leaves")
            .map(|row| {
                let bytes: Vec<u8> = row.get(0);
                let arr: [u8; 8] = bytes
                    .as_slice()
                    .try_into()
                    .expect("invalid num_leaves length");
                u64::from_be_bytes(arr)
            })
            .unwrap_or(0);

        if num_leaves == 0 {
            client
                .execute(
                    "DELETE FROM merkle_nodes WHERE tree_index = $1",
                    &[&tree_index],
                )
                .expect("failed to clear inconsistent DB state");
            client
                .execute(
                    "DELETE FROM merkle_metadata WHERE tree_index = $1",
                    &[&tree_index],
                )
                .expect("failed to clear inconsistent DB state");
        }

        Self {
            inner: Mutex::new(client),
            tree_index,
            num_leaves: AtomicU64::new(num_leaves),
        }
    }

    fn new_clean_with_tree_index(connection_string: &str, tree_index: i64) -> Self {
        let mut client =
            Client::connect(connection_string, NoTls).expect("failed to connect to PostgreSQL");

        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS merkle_nodes (
                    tree_index BIGINT NOT NULL,
                    level      INTEGER NOT NULL,
                    idx        BIGINT NOT NULL,
                    node       BYTEA NOT NULL CHECK(octet_length(node) = 32),
                    PRIMARY KEY(tree_index, level, idx)
                );
                CREATE TABLE IF NOT EXISTS merkle_metadata (
                    tree_index BIGINT NOT NULL,
                    key        TEXT NOT NULL,
                    value      BYTEA NOT NULL,
                    PRIMARY KEY(tree_index, key)
                );",
            )
            .expect("failed to create tables");

        client
            .execute("DELETE FROM merkle_nodes WHERE tree_index = $1", &[&tree_index])
            .expect("failed to clear nodes");
        client
            .execute("DELETE FROM merkle_metadata WHERE tree_index = $1", &[&tree_index])
            .expect("failed to clear metadata");

        Self {
            inner: Mutex::new(client),
            tree_index,
            num_leaves: AtomicU64::new(0),
        }
    }
}

#[cfg(feature = "postgres_store")]
impl Store for PostgresStore {
    fn get(&self, levels: &[u32], indices: &[u64]) -> Result<Vec<Option<Node>>, MerkleError> {
        if levels.len() != indices.len() {
            return Err(MerkleError::LengthMismatch {
                levels: levels.len(),
                indices: indices.len(),
            });
        }

        if levels.is_empty() {
            return Ok(Vec::new());
        }

        // Restrict to 256 elements to avoid hitting parameter limits.
        if levels.len() > MAX_PARAMS {
            return Err(MerkleError::StoreError(format!(
                "levels length must be less than {}",
                MAX_PARAMS
            )));
        }

        let mut params: Vec<Box<dyn postgres::types::ToSql + Sync>> =
            Vec::with_capacity(levels.len() * 3);
        let mut values_parts: Vec<String> = Vec::with_capacity(levels.len());

        for (ord, (&lvl, &idx)) in levels.iter().zip(indices).enumerate() {
            let base = ord * 3;
            values_parts.push(format!(
                "(${}::bigint, ${}::integer, ${}::bigint, {}::integer)",
                base + 1,
                base + 2,
                base + 3,
                ord
            ));
            params.push(Box::new(self.tree_index));
            params.push(Box::new(lvl as i32));
            params.push(Box::new(idx as i64));
        }

        let values_sql = values_parts.join(",");

        let sql = format!(
            "WITH req(tree_index, level, idx, ord) AS (VALUES {values}) \
             SELECT merkle_nodes.node FROM req LEFT JOIN merkle_nodes ON req.tree_index = merkle_nodes.tree_index AND req.level = merkle_nodes.level AND req.idx = merkle_nodes.idx ORDER BY req.ord",
            values = values_sql
        );

        let params_refs: Vec<&(dyn postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref()).collect();

        let mut guard = self.inner.lock().expect("postgres store lock");
        let rows = guard
            .query(&sql, &params_refs[..])
            .map_err(Self::postgres_error)?;

        rows.iter()
            .map(|row| {
                let opt_blob: Option<Vec<u8>> = row.get(0);
                match opt_blob {
                    Some(blob) => Self::decode_node(&blob).map(Some),
                    None => Ok(None),
                }
            })
            .collect::<Result<Vec<_>, _>>()
    }

    fn put(&mut self, items: &[(u32, u64, Node)]) -> Result<(), MerkleError> {
        let mut guard = self.inner.lock().expect("postgres store lock");
        let mut tx = guard.transaction().map_err(Self::postgres_error)?;

        let insert_node_stmt = tx
            .prepare(
                "INSERT INTO merkle_nodes (tree_index, level, idx, node) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (tree_index, level, idx) DO UPDATE SET node = EXCLUDED.node",
            )
            .map_err(Self::postgres_error)?;
        let upsert_metadata_stmt = tx
            .prepare(
                "INSERT INTO merkle_metadata (tree_index, key, value) VALUES ($1, $2, $3) \
                 ON CONFLICT (tree_index, key) DO UPDATE SET value = EXCLUDED.value",
            )
            .map_err(Self::postgres_error)?;

        for (level, index, node) in items {
            tx.execute(
                &insert_node_stmt,
                &[
                    &self.tree_index,
                    &(*level as i32),
                    &(*index as i64),
                    &node.as_ref(),
                ],
            )
            .map_err(Self::postgres_error)?;
        }

        let counter = items.iter().filter(|(level, _, _)| *level == 0).count() as u64;
        if counter > 0 {
            let new_leaves = self.num_leaves.load(Ordering::SeqCst) + counter;
            tx.execute(
                &upsert_metadata_stmt,
                &[
                    &self.tree_index,
                    &Self::KEY_NUM_LEAVES,
                    &new_leaves.to_be_bytes().to_vec(),
                ],
            )
            .map_err(Self::postgres_error)?;

            self.num_leaves.store(new_leaves, Ordering::SeqCst);
        }

        tx.commit().map_err(Self::postgres_error)?;
        Ok(())
    }

    fn get_num_leaves(&self) -> u64 {
        self.num_leaves.load(Ordering::SeqCst)
    }
}

#[cfg(feature = "postgres_store")]
impl MultiTreeStore for PostgresStore {
    type Store = PostgresStore;

    fn for_tree(connection: &str, tree_index: i64) -> Self::Store {
        Self::new_with_tree_index(connection, tree_index)
    }

    fn for_tree_clean(connection: &str, tree_index: i64) -> Self::Store {
        Self::new_clean_with_tree_index(connection, tree_index)
    }
}
