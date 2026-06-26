package repository

import (
	"database/sql"
	"errors"
	"security-platform/internal/model"
	"time"

	"github.com/lib/pq"
)

type RoleRepository struct{ db *sql.DB }

func NewRoleRepository(db *sql.DB) *RoleRepository { return &RoleRepository{db: db} }

func (r *RoleRepository) FindByID(id int64) (*model.Role, error) {
	role := &model.Role{}
	err := r.db.QueryRow(
		`SELECT id,name,display_name,parent_id,created_at FROM roles WHERE id=$1`, id,
	).Scan(&role.ID, &role.Name, &role.DisplayName, &role.ParentID, &role.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return role, err
}

func (r *RoleRepository) FindByName(name string) (*model.Role, error) {
	role := &model.Role{}
	err := r.db.QueryRow(
		`SELECT id,name,display_name,parent_id,created_at FROM roles WHERE name=$1`, name,
	).Scan(&role.ID, &role.Name, &role.DisplayName, &role.ParentID, &role.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return role, err
}

func (r *RoleRepository) ListAll() ([]*model.Role, error) {
	rows, err := r.db.Query(`SELECT id,name,display_name,parent_id,created_at FROM roles ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Role
	for rows.Next() {
		role := &model.Role{}
		if err := rows.Scan(&role.ID, &role.Name, &role.DisplayName, &role.ParentID, &role.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func (r *RoleRepository) Create(req *model.CreateRoleRequest) (*model.Role, error) {
	role := &model.Role{Name: req.Name, DisplayName: req.DisplayName, ParentID: req.ParentID}
	err := r.db.QueryRow(
		`INSERT INTO roles(name,display_name,parent_id,created_at) VALUES($1,$2,$3,$4) RETURNING id,created_at`,
		req.Name, req.DisplayName, req.ParentID, time.Now(),
	).Scan(&role.ID, &role.CreatedAt)
	return role, err
}

// GetPermissions 获取角色自身直接拥有的权限列表，不含继承的权限
func (r *RoleRepository) GetPermissions(roleID int64) ([]*model.Permission, error) {
	rows, err := r.db.Query(
		`SELECT p.id,p.name,p.description
		 FROM permissions p
		 JOIN role_permissions rp ON rp.permission_id = p.id
		 WHERE rp.role_id = $1`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Permission
	for rows.Next() {
		p := &model.Permission{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Description); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SavePermissions 覆盖写入角色权限，先清空再批量插入
func (r *RoleRepository) SavePermissions(roleID int64, permIDs []int64) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM role_permissions WHERE role_id=$1`, roleID); err != nil {
		return err
	}
	if len(permIDs) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO role_permissions(role_id,permission_id) VALUES($1,$2)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, pid := range permIDs {
			if _, err := stmt.Exec(roleID, pid); err != nil {
				if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
					continue
				}
				return err
			}
		}
	}
	return tx.Commit()
}

// ListPermissions 列出系统内所有已注册权限
func (r *RoleRepository) ListPermissions() ([]*model.Permission, error) {
	rows, err := r.db.Query(`SELECT id,name,description FROM permissions ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Permission
	for rows.Next() {
		p := &model.Permission{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Description); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// FindUsersWithRole 查询持有指定角色的所有用户ID列表
func (r *RoleRepository) FindUsersWithRole(roleID int64) ([]int64, error) {
	rows, err := r.db.Query(`SELECT id FROM users WHERE role_id=$1`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
