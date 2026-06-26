package repository

import (
	"database/sql"
	"errors"
	"security-platform/internal/model"
	"strings"
	"time"
)

var ErrNotFound = errors.New("记录不存在")

type UserRepository struct{ db *sql.DB }

func NewUserRepository(db *sql.DB) *UserRepository { return &UserRepository{db: db} }

func (r *UserRepository) FindByID(id int64) (*model.User, error) {
	u := &model.User{}
	err := r.db.QueryRow(
		`SELECT id,username,password_hash,email,role_id,status,is_probation,failed_login_count,
		        locked_until,last_login_at,created_at,updated_at
		 FROM users WHERE id=$1`, id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Email, &u.RoleID, &u.Status, &u.IsProbation,
		&u.FailedLoginCount, &u.LockedUntil, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (r *UserRepository) FindByUsername(username string) (*model.User, error) {
	u := &model.User{}
	err := r.db.QueryRow(
		`SELECT id,username,password_hash,email,role_id,status,is_probation,failed_login_count,
		        locked_until,last_login_at,created_at,updated_at
		 FROM users WHERE username=$1`, username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Email, &u.RoleID, &u.Status, &u.IsProbation,
		&u.FailedLoginCount, &u.LockedUntil, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (r *UserRepository) Create(u *model.User) error {
	return r.db.QueryRow(
		`INSERT INTO users(username,password_hash,email,role_id,status,is_probation,created_at,updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		u.Username, u.PasswordHash, u.Email, u.RoleID,
		model.UserStatusEnabled, u.IsProbation, time.Now(), time.Now(),
	).Scan(&u.ID)
}

func (r *UserRepository) List(offset, limit int) ([]*model.User, int, error) {
	var total int
	_ = r.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&total)
	rows, err := r.db.Query(
		`SELECT id,username,email,role_id,status,is_probation,last_login_at,created_at,updated_at
		 FROM users ORDER BY id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*model.User
	for rows.Next() {
		u := &model.User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.RoleID, &u.Status, &u.IsProbation,
			&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

func (r *UserRepository) Update(id int64, req *model.UpdateUserRequest) error {
	sets := []string{"updated_at=$1"}
	args := []interface{}{time.Now()}
	i := 2
	if req.Email != "" {
		sets = append(sets, "email=$"+strings.Repeat("0", i-1))
		sets[len(sets)-1] = "email=$" + string(rune('0'+i))
		args = append(args, req.Email)
		i++
	}
	if req.RoleID > 0 {
		sets = append(sets, "role_id=$" + string(rune('0'+i)))
		args = append(args, req.RoleID)
		i++
	}
	if req.Status >= 0 {
		sets = append(sets, "status=$" + string(rune('0'+i)))
		args = append(args, req.Status)
		i++
	}
	args = append(args, id)
	_, err := r.db.Exec(
		`UPDATE users SET `+strings.Join(sets, ",")+` WHERE id=$`+string(rune('0'+i)),
		args...,
	)
	return err
}

// RecordLoginSuccess 更新最后登录时间并清除失败计数
func (r *UserRepository) RecordLoginSuccess(id int64) error {
	_, err := r.db.Exec(
		`UPDATE users SET last_login_at=$1,failed_login_count=0,locked_until=NULL,
		                  status=CASE WHEN status=2 THEN 1 ELSE status END,updated_at=$1
		 WHERE id=$2`, time.Now(), id)
	return err
}

// RecordLoginFailure 累加失败次数，达到阈值后锁定账号30分钟
func (r *UserRepository) RecordLoginFailure(username string, maxAttempts int) error {
	lockDuration := 30 * time.Minute
	_, err := r.db.Exec(
		`UPDATE users
		 SET failed_login_count = failed_login_count + 1,
		     locked_until = CASE WHEN failed_login_count + 1 >= $1
		                         THEN $2 ELSE locked_until END,
		     status = CASE WHEN failed_login_count + 1 >= $1
		                   THEN 2 ELSE status END,
		     updated_at = NOW()
		 WHERE username = $3`,
		maxAttempts, time.Now().Add(lockDuration), username)
	return err
}

func (r *UserRepository) UpdatePassword(id int64, hash string) error {
	_, err := r.db.Exec(
		`UPDATE users SET password_hash=$1,updated_at=$2 WHERE id=$3`,
		hash, time.Now(), id)
	return err
}
