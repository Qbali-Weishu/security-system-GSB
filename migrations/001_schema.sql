-- 角色表
CREATE TABLE IF NOT EXISTS roles (
    id           BIGSERIAL PRIMARY KEY,
    name         VARCHAR(64) UNIQUE NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    parent_id    BIGINT REFERENCES roles(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 权限表
CREATE TABLE IF NOT EXISTS permissions (
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(128) UNIQUE NOT NULL,
    description VARCHAR(256)
);

-- 角色权限关联表
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id                 BIGSERIAL PRIMARY KEY,
    username           VARCHAR(64) UNIQUE NOT NULL,
    password_hash      VARCHAR(256) NOT NULL,
    email              VARCHAR(128) UNIQUE NOT NULL,
    role_id            BIGINT NOT NULL REFERENCES roles(id),
    status             SMALLINT NOT NULL DEFAULT 1,
    is_probation       BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_count INT NOT NULL DEFAULT 0,
    locked_until       TIMESTAMPTZ,
    last_login_at      TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 会话表（刷新令牌）
CREATE TABLE IF NOT EXISTS sessions (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token TEXT UNIQUE NOT NULL,
    user_agent    VARCHAR(512),
    ip_address    VARCHAR(64),
    is_revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(refresh_token);
CREATE INDEX IF NOT EXISTS idx_sessions_user  ON sessions(user_id, is_revoked);

-- 安全告警表
CREATE TABLE IF NOT EXISTS security_alerts (
    id               BIGSERIAL PRIMARY KEY,
    title            VARCHAR(256) NOT NULL,
    description      TEXT,
    source           VARCHAR(128) NOT NULL,
    severity         SMALLINT NOT NULL DEFAULT 3,
    status           SMALLINT NOT NULL DEFAULT 1,
    assignee_id      BIGINT REFERENCES users(id),
    creator_id       BIGINT NOT NULL REFERENCES users(id),
    sla_deadline     TIMESTAMPTZ NOT NULL,
    sla_breached     BOOLEAN NOT NULL DEFAULT FALSE,
    escalation_count INT NOT NULL DEFAULT 0,
    resolved_at      TIMESTAMPTZ,
    closed_at        TIMESTAMPTZ,
    tags             VARCHAR(64)[] NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alerts_status   ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_sla      ON security_alerts(sla_deadline, sla_breached);

-- 告警处置记录表
CREATE TABLE IF NOT EXISTS alert_comments (
    id         BIGSERIAL PRIMARY KEY,
    alert_id   BIGINT NOT NULL REFERENCES security_alerts(id) ON DELETE CASCADE,
    author_id  BIGINT NOT NULL REFERENCES users(id),
    content    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 审计日志表（含哈希链字段）
CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL DEFAULT 0,
    username    VARCHAR(64) NOT NULL,
    action      VARCHAR(64) NOT NULL,
    resource    VARCHAR(64) NOT NULL,
    resource_id VARCHAR(64),
    detail      TEXT,
    ip_address  VARCHAR(64),
    user_agent  VARCHAR(512),
    result      VARCHAR(16) NOT NULL,
    prev_hash   CHAR(64) NOT NULL,
    hash        CHAR(64) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_user     ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action   ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(resource);

-- API密钥表
CREATE TABLE IF NOT EXISTS api_keys (
    id           BIGSERIAL PRIMARY KEY,
    name         VARCHAR(128) NOT NULL,
    key_hash     CHAR(64) UNIQUE NOT NULL,
    key_prefix   VARCHAR(16) NOT NULL,
    owner_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes       VARCHAR(64)[] NOT NULL DEFAULT '{}',
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 初始化权限数据
INSERT INTO permissions (name, description) VALUES
    ('alert:read',    '查看安全告警'),
    ('alert:write',   '创建和修改安全告警'),
    ('alert:delete',  '删除安全告警'),
    ('alert:assign',  '指派告警处置人'),
    ('user:read',     '查看用户信息'),
    ('user:write',    '创建和修改用户'),
    ('user:delete',   '删除用户'),
    ('role:read',     '查看角色和权限'),
    ('role:write',    '管理角色和权限'),
    ('config:read',   '查看系统配置'),
    ('config:write',  '修改系统配置'),
    ('audit:read',    '查看审计日志'),
    ('apikey:manage', '管理API密钥'),
    ('report:read',   '查看报表'),
    ('report:write',  '生成报表')
ON CONFLICT DO NOTHING;

-- 初始化角色（viewer -> analyst -> security_officer -> admin 四级继承）
INSERT INTO roles (name, display_name) VALUES ('viewer', '观察员') ON CONFLICT DO NOTHING;
INSERT INTO roles (name, display_name, parent_id)
    VALUES ('analyst', '分析师', (SELECT id FROM roles WHERE name='viewer'))
    ON CONFLICT DO NOTHING;
INSERT INTO roles (name, display_name, parent_id)
    VALUES ('security_officer', '安全官', (SELECT id FROM roles WHERE name='analyst'))
    ON CONFLICT DO NOTHING;
INSERT INTO roles (name, display_name, parent_id)
    VALUES ('admin', '管理员', (SELECT id FROM roles WHERE name='security_officer'))
    ON CONFLICT DO NOTHING;

-- viewer 权限
INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id FROM roles r, permissions p
    WHERE r.name='viewer' AND p.name IN ('alert:read','report:read')
ON CONFLICT DO NOTHING;

-- analyst 增量权限
INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id FROM roles r, permissions p
    WHERE r.name='analyst' AND p.name IN ('alert:write','report:write','apikey:manage')
ON CONFLICT DO NOTHING;

-- security_officer 增量权限
INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id FROM roles r, permissions p
    WHERE r.name='security_officer' AND p.name IN ('alert:assign','alert:delete','user:read','config:read','audit:read')
ON CONFLICT DO NOTHING;

-- admin 增量权限
INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id FROM roles r, permissions p
    WHERE r.name='admin' AND p.name IN ('user:write','user:delete','role:read','role:write','config:write')
ON CONFLICT DO NOTHING;

-- 初始管理员账号，密码为 Admin@123456 （bcrypt cost=12）
INSERT INTO users (username, password_hash, email, role_id)
    SELECT 'admin',
           '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQyCMc8JKZ9g5FNGFnuaFvW2a',
           'admin@example.com',
           r.id
    FROM roles r WHERE r.name='admin'
ON CONFLICT DO NOTHING;
