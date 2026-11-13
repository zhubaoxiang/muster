// Package store SQLite 存储层：单文件库，资产批量 upsert。
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // 纯 Go 驱动，无需 CGO

	"dianbing/internal/model"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS assets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host TEXT NOT NULL,
			port INTEGER NOT NULL,
			scheme TEXT NOT NULL DEFAULT '',
			status INTEGER NOT NULL DEFAULT 0,
			title TEXT NOT NULL DEFAULT '',
			server TEXT NOT NULL DEFAULT '',
			fingerprint TEXT NOT NULL DEFAULT '[]',
			task_id TEXT NOT NULL DEFAULT '',
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			UNIQUE(host, port, scheme)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_assets_task ON assets(task_id)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS tasks (
			task_id TEXT PRIMARY KEY,
			mode TEXT NOT NULL DEFAULT '',
			full_range INTEGER NOT NULL DEFAULT 0,
			port_count INTEGER NOT NULL DEFAULT 0,
			hosts_alive INTEGER NOT NULL DEFAULT 0,
			ports_open INTEGER NOT NULL DEFAULT -1,
			assets_found INTEGER NOT NULL DEFAULT 0,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL DEFAULT ''
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("建表失败: %w", err)
		}
	}
	return nil
}

// UpsertAssets 批量写入（同一事务，500 条/批）。重复资产只更新 last_seen 与内容。
func (s *Store) UpsertAssets(assets []model.Asset) error {
	if len(assets) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT INTO assets
		(host, port, scheme, status, title, server, fingerprint, task_id, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host, port, scheme) DO UPDATE SET
			status = excluded.status,
			title = excluded.title,
			server = excluded.server,
			fingerprint = excluded.fingerprint,
			task_id = excluded.task_id,
			last_seen = excluded.last_seen`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().Format(time.RFC3339)
	for _, a := range assets {
		fp, err := json.Marshal(a.Fingerprint)
		if err != nil {
			fp = []byte("[]")
		}
		if _, err := stmt.Exec(a.Host, a.Port, a.Scheme, a.Status, a.Title, a.Server,
			string(fp), a.TaskID, now, now); err != nil {
			return fmt.Errorf("写入资产 %s:%d 失败: %w", a.Host, a.Port, err)
		}
	}
	return tx.Commit()
}

func (s *Store) ListAssets(limit int) ([]model.Asset, error) {
	rows, err := s.db.Query(`SELECT id, host, port, scheme, status, title, server,
		fingerprint, task_id, first_seen, last_seen
		FROM assets ORDER BY last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Asset
	for rows.Next() {
		var a model.Asset
		var fp, fs, ls string
		// modernc/sqlite 返回 TEXT 为 string，手动解析为 time.Time
		if err := rows.Scan(&a.ID, &a.Host, &a.Port, &a.Scheme, &a.Status, &a.Title,
			&a.Server, &fp, &a.TaskID, &fs, &ls); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(fp), &a.Fingerprint)
		a.FirstSeen = parseTime(fs)
		a.LastSeen = parseTime(ls)
		out = append(out, a)
	}
	return out, rows.Err()
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// SaveTask 保存/更新任务审计记录（任务结束时调一次）
func (s *Store) SaveTask(t model.TaskMeta) error {
	fin := ""
	if !t.FinishedAt.IsZero() {
		fin = t.FinishedAt.Format(time.RFC3339)
	}
	_, err := s.db.Exec(`INSERT INTO tasks
		(task_id, mode, full_range, port_count, hosts_alive, ports_open, assets_found, started_at, finished_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(task_id) DO UPDATE SET
			mode = excluded.mode, full_range = excluded.full_range,
			port_count = excluded.port_count, hosts_alive = excluded.hosts_alive,
			ports_open = excluded.ports_open, assets_found = excluded.assets_found,
			finished_at = excluded.finished_at`,
		t.TaskID, t.Mode, boolToInt(t.FullRange), t.PortCount, t.HostsAlive,
		t.PortsOpen, t.AssetsFound, t.StartedAt.Format(time.RFC3339), fin)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) GetSettings() (model.Settings, error) {
	var out model.Settings
	row := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'main'`)
	var raw string
	if err := row.Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return model.Settings{MaxRate: 200}, nil // 默认值
		}
		return out, err
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return model.Settings{MaxRate: 200}, nil
	}
	return out, nil
}

func (s *Store) SaveSettings(v model.Settings) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO settings(key, value) VALUES ('main', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, string(raw))
	return err
}

func (s *Store) Close() error { return s.db.Close() }
