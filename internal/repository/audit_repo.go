package repository

import (
	"database/sql"
	"security-platform/internal/model"
	"time"
)

type AuditRepository struct{ db *sql.DB }

func NewAuditRepository(db *sql.DB) *AuditRepository { return &AuditRepository{db: db} }

// Create 写入一条审计日志
func (r *AuditRepository) Create(l *model.AuditLog) error {
	return r.db.QueryRow(
		`INSERT INTO audit_logs
		  (user_id,username,action,resource,resource_id,detail,ip_address,user_agent,result,prev_hash,hash,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		l.UserID, l.Username, l.Action, l.Resource, l.ResourceID,
		l.Detail, l.IPAddress, l.UserAgent, l.Result,
		l.PrevHash, l.Hash, time.Now(),
	).Scan(&l.ID)
}

// GetLastHash 获取最近一条审计日志的哈希值，用于构建哈希链
// 若审计表为空则返回初始哈希值
func (r *AuditRepository) GetLastHash() (string, error) {
	var hash string
	err := r.db.QueryRow(
		`SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1`,
	).Scan(&hash)
	if err == sql.ErrNoRows {
		return "0000000000000000000000000000000000000000000000000000000000000000", nil
	}
	return hash, err
}

// List 分页查询审计日志，支持按用户、操作、资源、结果等字段筛选
func (r *AuditRepository) List(q *model.AuditQueryParams) ([]*model.AuditLog, int, error) {
	where := "WHERE 1=1"
	args := []interface{}{}
	idx := 1
	if q.UserID > 0 {
		where += " AND user_id=$" + itoa(idx)
		args = append(args, q.UserID)
		idx++
	}
	if q.Action != "" {
		where += " AND action LIKE $" + itoa(idx)
		args = append(args, q.Action+"%")
		idx++
	}
	if q.Resource != "" {
		where += " AND resource=$" + itoa(idx)
		args = append(args, q.Resource)
		idx++
	}
	if q.Result != "" {
		where += " AND result=$" + itoa(idx)
		args = append(args, q.Result)
		idx++
	}
	var total int
	_ = r.db.QueryRow("SELECT COUNT(*) FROM audit_logs "+where, args...).Scan(&total)

	if q.PageSize <= 0 || q.PageSize > 200 {
		q.PageSize = 50
	}
	if q.Page <= 0 {
		q.Page = 1
	}
	args = append(args, q.PageSize, (q.Page-1)*q.PageSize)
	rows, err := r.db.Query(
		`SELECT id,user_id,username,action,resource,resource_id,detail,
		        ip_address,user_agent,result,hash,created_at
		 FROM audit_logs `+where+
			` ORDER BY id DESC LIMIT $`+itoa(idx)+` OFFSET $`+itoa(idx+1),
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*model.AuditLog
	for rows.Next() {
		l := &model.AuditLog{}
		if err := rows.Scan(&l.ID, &l.UserID, &l.Username, &l.Action,
			&l.Resource, &l.ResourceID, &l.Detail,
			&l.IPAddress, &l.UserAgent, &l.Result,
			&l.Hash, &l.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, l)
	}
	return out, total, rows.Err()
}

// VerifyChain 验证最近N条审计日志的哈希链完整性
// 返回第一条哈希不匹配的日志ID，若链条完整则返回0
func (r *AuditRepository) VerifyChain(lastN int) (int64, error) {
	rows, err := r.db.Query(
		`SELECT id,prev_hash,hash FROM audit_logs ORDER BY id DESC LIMIT $1`, lastN)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type entry struct {
		id       int64
		prevHash string
		hash     string
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.prevHash, &e.hash); err != nil {
			return 0, err
		}
		entries = append(entries, e)
	}
	// 从最旧的记录开始顺向验证
	for i := len(entries) - 1; i > 0; i-- {
		if entries[i-1].prevHash != entries[i].hash {
			return entries[i-1].id, nil
		}
	}
	return 0, nil
}
