package database

import (
	"context"
	"fmt"

	"github.com/kcansari/mixo/ent"
	"github.com/kcansari/mixo/internal/config"
	_ "github.com/lib/pq"
)

func New(cfg config.DBConfig) (*ent.Client, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.PG.Host, cfg.PG.Port, cfg.PG.User, cfg.PG.Password, cfg.PG.Name)

	client, err := ent.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("database: open failed: %w", err)
	}
	return client, nil
}

func Migrate(ctx context.Context, client *ent.Client) error {
	if err := client.Schema.Create(ctx); err != nil {
		return fmt.Errorf("database: migrate failed: %w", err)
	}
	return nil
}
