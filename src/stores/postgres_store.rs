// Copyright 2025 Bilinear Labs - MIT License

//! PostgreSQL store implementation.

#[cfg(feature = "postgres_store")]
use crate::{MerkleError, Node, Store};
#[cfg(feature = "postgres_store")]
use postgres::{Client, NoTls, Statement};

#[cfg(feature = "postgres_store")]
pub struct PostgresStore {
    client: Client,
    // Keeping an in-memory counter to avoid querying on every access.
    num_leaves: u64,
    insert_node_stmt: Statement,
    upsert_metadata_stmt: Statement,
}

#[cfg(feature = "postgres_store")]
const MAX_PARAMS: usize = 256;

#[cfg(feature = "postgres_store")]
impl PostgresStore {
    const KEY_NUM_LEAVES: &'static str = "NUM_LEAVES";

    fn db_error<E: std::fmt::Display>(err: E) -> MerkleError {
        MerkleError::StoreError(err.to_string())
    }

    fn decode_node(bytes: &[u8]) -> Result<Node, MerkleError> {
        let arr: [u8; Node::LEN] = bytes
            .try_into()
            .map_err(|_| MerkleError::StoreError("invalid node length".into()))?;
        Ok(Node::from(arr))
    }

    /// Creates a new PostgresStore.
    ///
    /// # Arguments
    /// * `connection_string` - PostgreSQL connection string (e.g., "host=localhost user=postgres dbname=merkle")
    ///
    /// # Panics
    /// Panics if unable to connect to the database or create the required tables.
    pub fn new(connection_string: &str) -> Self {
        let mut client = Client::connect(connection_string, NoTls).expect("failed to connect to PostgreSQL");

        // Create schema if not exists.
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS nodes (
                    level INTEGER NOT NULL,
                    idx   BIGINT NOT NULL,
                    node  BYTEA NOT NULL CHECK(octet_length(node) = 32),
                    PRIMARY KEY(level, idx)
                );
                CREATE TABLE IF NOT EXISTS metadata (
                    key   TEXT PRIMARY KEY,
                    value BYTEA NOT NULL
                );",
            )
            .expect("failed to create tables");

        // Load persisted leaf count
        let num_leaves: u64 = client
            .query_opt(
                "SELECT value FROM metadata WHERE key = $1",
                &[&Self::KEY_NUM_LEAVES],
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

        // If the count is 0, clear the db, just in case.
        if num_leaves == 0 {
            client
                .batch_execute("DELETE FROM nodes; DELETE FROM metadata;")
                .expect("failed to clear inconsistent DB state");
        }

        // Pre-prepare statements for reuse (similar to SQLite's prepare_cached).
        let insert_node_stmt = client
            .prepare(
                "INSERT INTO nodes (level, idx, node) VALUES ($1, $2, $3) \
                 ON CONFLICT (level, idx) DO UPDATE SET node = EXCLUDED.node",
            )
            .expect("failed to prepare insert_node statement");

        let upsert_metadata_stmt = client
            .prepare(
                "INSERT INTO metadata (key, value) VALUES ($1, $2) \
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            )
            .expect("failed to prepare upsert_metadata statement");

        Self {
            client,
            num_leaves,
            insert_node_stmt,
            upsert_metadata_stmt,
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

        let mut params: Vec<Box<dyn postgres::types::ToSql + Sync>> = Vec::with_capacity(levels.len() * 3);
        let mut values_parts: Vec<String> = Vec::with_capacity(levels.len());

        for (ord, (&lvl, &idx)) in levels.iter().zip(indices).enumerate() {
            let base = ord * 3;
            values_parts.push(format!("(${}, ${}, ${})", base + 1, base + 2, base + 3));
            params.push(Box::new(lvl as i32));
            params.push(Box::new(idx as i64));
            params.push(Box::new(ord as i32));
        }

        let values_sql = values_parts.join(",");

        let sql = format!(
            "WITH req(level, idx, ord) AS (VALUES {values}) \
             SELECT nodes.node FROM req LEFT JOIN nodes ON req.level = nodes.level AND req.idx = nodes.idx ORDER BY req.ord",
            values = values_sql
        );

        let params_refs: Vec<&(dyn postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref()).collect();

        let rows = self.client.query(&sql, &params_refs[..]).map_err(Self::db_error)?;

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
        let tx = self.client.transaction().map_err(Self::db_error)?;

        for (level, index, node) in items {
            tx.execute(
                &self.insert_node_stmt,
                &[&(*level as i32), &(*index as i64), &node.as_ref()],
            )
            .map_err(Self::db_error)?;
        }

        let counter = items.iter().filter(|(level, _, _)| *level == 0).count() as u64;
        if counter > 0 {
            let new_leaves = self.num_leaves + counter;
            // Use cached prepared statement for metadata upsert.
            tx.execute(
                &self.upsert_metadata_stmt,
                &[&Self::KEY_NUM_LEAVES, &new_leaves.to_be_bytes().to_vec()],
            )
            .map_err(Self::db_error)?;

            self.num_leaves = new_leaves;
        }

        tx.commit().map_err(Self::db_error)?;
        Ok(())
    }

    fn get_num_leaves(&self) -> u64 {
        self.num_leaves
    }
}