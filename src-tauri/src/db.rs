//! Local SQLite store for custom domains and blocker settings.

use parking_lot::Mutex;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomDomain {
    pub id: i64,
    pub domain: String,
    pub created_at: String,
}

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS custom_blocks (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              domain TEXT NOT NULL UNIQUE COLLATE NOCASE,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS settings (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            ",
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn list_custom(&self) -> Result<Vec<CustomDomain>, String> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, domain, created_at FROM custom_blocks ORDER BY created_at DESC, id DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(CustomDomain {
                    id: row.get(0)?,
                    domain: row.get(1)?,
                    created_at: row.get(2)?,
                })
            })
            .map_err(|e| e.to_string())?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn add_custom(&self, domain: &str) -> Result<CustomDomain, String> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO custom_blocks (domain) VALUES (?1)
             ON CONFLICT(domain) DO UPDATE SET domain = excluded.domain",
            params![domain],
        )
        .map_err(|e| e.to_string())?;

        conn.query_row(
            "SELECT id, domain, created_at FROM custom_blocks WHERE domain = ?1 COLLATE NOCASE",
            params![domain],
            |row| {
                Ok(CustomDomain {
                    id: row.get(0)?,
                    domain: row.get(1)?,
                    created_at: row.get(2)?,
                })
            },
        )
        .map_err(|e| e.to_string())
    }

    pub fn remove_custom(&self, id: i64) -> Result<(), String> {
        let conn = self.conn.lock();
        let changed = conn
            .execute("DELETE FROM custom_blocks WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err("domain not found".into());
        }
        Ok(())
    }

    pub fn contains_custom_exact(&self, domain: &str) -> Result<bool, String> {
        let conn = self.conn.lock();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM custom_blocks WHERE domain = ?1 COLLATE NOCASE",
                params![domain],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        Ok(count > 0)
    }

    pub fn custom_count(&self) -> Result<u64, String> {
        let conn = self.conn.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(1) FROM custom_blocks", [], |row| row.get(0))
            .map_err(|e| e.to_string())?;
        Ok(count as u64)
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>, String> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT value FROM settings WHERE key = ?1")
            .map_err(|e| e.to_string())?;
        let mut rows = stmt.query(params![key]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            Ok(Some(row.get(0).map_err(|e| e.to_string())?))
        } else {
            Ok(None)
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}
