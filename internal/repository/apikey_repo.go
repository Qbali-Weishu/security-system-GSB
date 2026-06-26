package repository

import (
	"database/sql"
	"errors"
	"security-platform/internal/model"
	"time"

	"github.com/lib/pq"
)

type APIKeyRepository struct{ db *sql.DB }

func NewAPIKeyRepository(db *sql.DB) *APIKeyRepository { return &APIKeyRepository{db: db} }

func (r *APIKeyRepository) Create(k *model.APIKey) error {
	return r.db.QueryRow(
		`INSERT INTO api_keys(name,key_hash,key_prefix,owner_id,scopes,is_active,expires_at,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		k.Name, k.KeyHash, k.KeyPrefix, k.OwnerID,
		pq.Array(k.Scopes), k.IsActive, k.ExpiresAt, time.Now(),
	).Scan(&k.ID)
}

func (r *APIKeyRepository) FindByKeyHash(hash string) (*model.APIKey, error) {
	k := &model.APIKey{}
	err := r.db.QueryRow(
		`SELECT id,name,key_hash,key_prefix,owner_id,scopes,is_active,expires_at,last_used_at,created_at
		 FROM api_keys WHERE key_hash=$1`, hash,
	).Scan(&k.ID, &k.Name, &k.KeyHash, &k.KeyPrefix, &k.OwnerID,
		pq.Array(&k.Scopes), &k.IsActive, &k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return k, err
}

func (r *APIKeyRepository) ListByOwner(ownerID int64) ([]*model.APIKey, error) {
	rows, err := r.db.Query(
		`SELECT id,name,key_prefix,owner_id,scopes,is_active,expires_at,last_used_at,created_at
		 FROM api_keys WHERE owner_id=$1 ORDER BY created_at DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.APIKey
	for rows.Next() {
		k := &model.APIKey{}
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.OwnerID,
			pq.Array(&k.Scopes), &k.IsActive, &k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (r *APIKeyRepository) Revoke(id, ownerID int64) error {
	res, err := r.db.Exec(`UPDATE api_keys SET is_active=false WHERE id=$1 AND owner_id=$2`, id, ownerID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *APIKeyRepository) UpdateLastUsed(id int64) {
	// 最后使用时间更新失败不影响主流程，忽略错误
	now := time.Now()
	_, _ = r.db.Exec(`UPDATE api_keys SET last_used_at=$1 WHERE id=$2`, now, id)
}
