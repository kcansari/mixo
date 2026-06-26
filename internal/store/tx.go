package store

import (
	"context"
	"fmt"

	"github.com/kcansari/mixo/ent"
)

type txKey struct{}

type Transactor struct {
	client *ent.Client
}

func NewTransactor(client *ent.Client) *Transactor {
	return &Transactor{client: client}
}

func (t *Transactor) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	tx, err := t.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("store.tx.WithTx: starting tx: %w", err)
	}

	ctx = context.WithValue(ctx, txKey{}, tx.Client())

	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback()
			panic(r)
		}
	}()

	if err := fn(ctx); err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}
