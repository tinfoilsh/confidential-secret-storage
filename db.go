package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store interface {
	PutItem(ctx context.Context, id, userID string, metadata json.RawMessage) error
	AllItems(ctx context.Context) ([]item, error)
	Close() error
}

type item struct {
	ID        string          `json:"id"`
	UserID    string          `json:"user_id"`
	Metadata  json.RawMessage `json:"metadata"`
	CreatedAt time.Time       `json:"created_at"`
}

type pgStore struct {
	pool *pgxpool.Pool
}

func NewStore(ctx context.Context, databaseURL string) (Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connecting to db: %w", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS secret_storage_items (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			metadata   TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_secret_storage_user ON secret_storage_items(user_id);
	`); err != nil {
		return nil, fmt.Errorf("creating schema: %w", err)
	}
	return &pgStore{pool: pool}, nil
}

func (s *pgStore) PutItem(ctx context.Context, id, userID string, metadata json.RawMessage) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO secret_storage_items (id, user_id, metadata) VALUES ($1, $2, $3)`,
		id, userID, string(metadata),
	)
	return err
}

func (s *pgStore) AllItems(ctx context.Context) ([]item, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, user_id, metadata, created_at FROM secret_storage_items ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []item
	for rows.Next() {
		var it item
		var meta *string
		if err := rows.Scan(&it.ID, &it.UserID, &meta, &it.CreatedAt); err != nil {
			return nil, err
		}
		if meta != nil {
			it.Metadata = json.RawMessage(*meta)
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

func (s *pgStore) Close() error {
	s.pool.Close()
	return nil
}
