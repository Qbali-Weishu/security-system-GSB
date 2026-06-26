package repository

import (
	"database/sql"
	"errors"
	"security-platform/internal/model"
	"time"
)

type SessionRepository struct{ db *sql.DB }

func NewSessionRepository(db *sql.DB) *SessionRepository { return &SessionRepository{db: db} }

// Create 写入新会话记录
func (r *SessionRepository) Create(s *model.Session) error {
	return r.db.QueryRow(
		`INSERT INTO sessions(user_id,refresh_token,user_agent,ip_address,expires_at,created_at)
		 VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
		s.UserID, s.RefreshToken, s.UserAgent, s.IPAddress, s.ExpiresAt, time.Now(),
	).Scan(&s.ID)
}

// UpdateRefreshToken 回填会话的刷新令牌字段
// 刷新令牌的生成依赖会话ID，因此需要先建会话再回填令牌
func (r *SessionRepository) UpdateRefreshToken(sessionID int64, token string) error {
	_, err := r.db.Exec(
		`UPDATE sessions SET refresh_token=$1 WHERE id=$2`, token, sessionID)
	return err
}

// FindByRefreshToken 根据刷新令牌字符串查找对应的会话记录
func (r *SessionRepository) FindByRefreshToken(token string) (*model.Session, error) {
	s := &model.Session{}
	err := r.db.QueryRow(
		`SELECT id,user_id,refresh_token,user_agent,ip_address,is_revoked,expires_at,revoked_at,created_at
		 FROM sessions WHERE refresh_token=$1`, token,
	).Scan(&s.ID, &s.UserID, &s.RefreshToken, &s.UserAgent, &s.IPAddress,
		&s.IsRevoked, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return s, err
}

// Revoke 将指定会话标记为已吊销
func (r *SessionRepository) Revoke(sessionID int64) error {
	now := time.Now()
	_, err := r.db.Exec(
		`UPDATE sessions SET is_revoked=true,revoked_at=$1 WHERE id=$2`,
		now, sessionID)
	return err
}

// RevokeAllByUser 吊销某个用户的全部有效会话，用于强制下线场景
func (r *SessionRepository) RevokeAllByUser(userID int64) error {
	now := time.Now()
	_, err := r.db.Exec(
		`UPDATE sessions SET is_revoked=true,revoked_at=$1
		 WHERE user_id=$2 AND is_revoked=false AND expires_at > $1`,
		now, userID)
	return err
}

// ListActiveByUser 查询某用户当前全部有效会话
func (r *SessionRepository) ListActiveByUser(userID int64) ([]*model.Session, error) {
	rows, err := r.db.Query(
		`SELECT id,user_id,user_agent,ip_address,is_revoked,expires_at,created_at
		 FROM sessions
		 WHERE user_id=$1 AND is_revoked=false AND expires_at > NOW()
		 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Session
	for rows.Next() {
		s := &model.Session{}
		if err := rows.Scan(&s.ID, &s.UserID, &s.UserAgent, &s.IPAddress,
			&s.IsRevoked, &s.ExpiresAt, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
