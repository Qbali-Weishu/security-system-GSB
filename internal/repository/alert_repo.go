package repository

import (
	"database/sql"
	"errors"
	"security-platform/internal/model"
	"time"

	"github.com/lib/pq"
)

type AlertRepository struct{ db *sql.DB }

func NewAlertRepository(db *sql.DB) *AlertRepository { return &AlertRepository{db: db} }

func (r *AlertRepository) Create(a *model.SecurityAlert) error {
	return r.db.QueryRow(
		`INSERT INTO security_alerts
		  (title,description,source,severity,status,creator_id,sla_deadline,created_at,updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8) RETURNING id`,
		a.Title, a.Description, a.Source, a.Severity,
		a.Status, a.CreatorID, a.SLADeadline, time.Now(),
	).Scan(&a.ID)
}

func (r *AlertRepository) FindByID(id int64) (*model.SecurityAlert, error) {
	a := &model.SecurityAlert{}
	err := r.db.QueryRow(
		`SELECT id,title,description,source,severity,status,assignee_id,creator_id,
		        sla_deadline,sla_breached,escalation_count,resolved_at,closed_at,created_at,updated_at
		 FROM security_alerts WHERE id=$1`, id,
	).Scan(&a.ID, &a.Title, &a.Description, &a.Source, &a.Severity, &a.Status,
		&a.AssigneeID, &a.CreatorID, &a.SLADeadline, &a.SLABreached,
		&a.EscalationCount, &a.ResolvedAt, &a.ClosedAt, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (r *AlertRepository) List(q *model.AlertQueryParams) ([]*model.SecurityAlert, int, error) {
	// 基础查询条件动态拼接
	where := `WHERE 1=1`
	args := []interface{}{}
	idx := 1
	if q.Severity > 0 {
		where += " AND severity=$" + itoa(idx)
		args = append(args, q.Severity)
		idx++
	}
	if q.Status > 0 {
		where += " AND status=$" + itoa(idx)
		args = append(args, q.Status)
		idx++
	}
	if q.AssigneeID > 0 {
		where += " AND assignee_id=$" + itoa(idx)
		args = append(args, q.AssigneeID)
		idx++
	}
	if q.Source != "" {
		where += " AND source=$" + itoa(idx)
		args = append(args, q.Source)
		idx++
	}
	if q.SLABreached != nil {
		where += " AND sla_breached=$" + itoa(idx)
		args = append(args, *q.SLABreached)
		idx++
	}
	var total int
	_ = r.db.QueryRow("SELECT COUNT(*) FROM security_alerts "+where, args...).Scan(&total)

	if q.PageSize <= 0 || q.PageSize > 100 {
		q.PageSize = 20
	}
	if q.Page <= 0 {
		q.Page = 1
	}
	offset := (q.Page - 1) * q.PageSize
	args = append(args, q.PageSize, offset)
	rows, err := r.db.Query(
		`SELECT id,title,source,severity,status,assignee_id,creator_id,
		        sla_deadline,sla_breached,escalation_count,created_at,updated_at
		 FROM security_alerts `+where+
			` ORDER BY severity DESC,created_at DESC LIMIT $`+itoa(idx)+` OFFSET $`+itoa(idx+1),
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*model.SecurityAlert
	for rows.Next() {
		a := &model.SecurityAlert{}
		if err := rows.Scan(&a.ID, &a.Title, &a.Source, &a.Severity, &a.Status,
			&a.AssigneeID, &a.CreatorID, &a.SLADeadline, &a.SLABreached,
			&a.EscalationCount, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (r *AlertRepository) Update(id int64, a *model.SecurityAlert) error {
	_, err := r.db.Exec(
		`UPDATE security_alerts
		 SET title=$1,description=$2,severity=$3,status=$4,assignee_id=$5,
		     sla_breached=$6,escalation_count=$7,resolved_at=$8,closed_at=$9,updated_at=$10
		 WHERE id=$11`,
		a.Title, a.Description, a.Severity, a.Status, a.AssigneeID,
		a.SLABreached, a.EscalationCount, a.ResolvedAt, a.ClosedAt, time.Now(), id)
	return err
}

// CheckAndMarkSLABreaches 检查所有超时未处置的告警并标记为已违反SLA
func (r *AlertRepository) CheckAndMarkSLABreaches() (int64, error) {
	res, err := r.db.Exec(
		`UPDATE security_alerts
		 SET sla_breached=true, updated_at=NOW()
		 WHERE sla_deadline < NOW()
		   AND sla_breached = false
		   AND status NOT IN ($1,$2)`,
		model.AlertStatusResolved, model.AlertStatusClosed)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// FindSLABreachedUnnotified 查询已违反SLA但尚未完成上报操作的告警
func (r *AlertRepository) FindSLABreachedUnnotified() ([]*model.SecurityAlert, error) {
	rows, err := r.db.Query(
		`SELECT id,title,severity,status,assignee_id,creator_id,sla_deadline,escalation_count,created_at
		 FROM security_alerts
		 WHERE sla_breached=true AND status NOT IN ($1,$2)
		 ORDER BY severity DESC`,
		model.AlertStatusResolved, model.AlertStatusClosed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.SecurityAlert
	for rows.Next() {
		a := &model.SecurityAlert{}
		if err := rows.Scan(&a.ID, &a.Title, &a.Severity, &a.Status,
			&a.AssigneeID, &a.CreatorID, &a.SLADeadline,
			&a.EscalationCount, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *AlertRepository) AddComment(c *model.AlertComment) error {
	return r.db.QueryRow(
		`INSERT INTO alert_comments(alert_id,author_id,content,created_at)
		 VALUES($1,$2,$3,$4) RETURNING id`,
		c.AlertID, c.AuthorID, c.Content, time.Now(),
	).Scan(&c.ID)
}

func (r *AlertRepository) ListComments(alertID int64) ([]*model.AlertComment, error) {
	rows, err := r.db.Query(
		`SELECT id,alert_id,author_id,content,created_at
		 FROM alert_comments WHERE alert_id=$1 ORDER BY created_at`, alertID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AlertComment
	for rows.Next() {
		c := &model.AlertComment{}
		if err := rows.Scan(&c.ID, &c.AlertID, &c.AuthorID, &c.Content, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddTags 为告警批量追加标签，使用PostgreSQL数组操作
func (r *AlertRepository) AddTags(alertID int64, tags []string) error {
	_, err := r.db.Exec(
		`UPDATE security_alerts
		 SET tags = array(SELECT DISTINCT unnest(tags || $1::varchar[])),
		     updated_at = NOW()
		 WHERE id=$2`,
		pq.Array(tags), alertID)
	return err
}

func itoa(i int) string {
	if i <= 0 {
		return "1"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}
