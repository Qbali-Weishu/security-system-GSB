package service

import (
	"fmt"
	"security-platform/internal/model"
	"security-platform/internal/repository"
	"sync"
)

// permCache 以用户ID为键的权限缓存，线程安全
type permCache struct {
	mu    sync.RWMutex
	store map[int64][]string
}

func (c *permCache) get(userID int64) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.store[userID]
	return v, ok
}

func (c *permCache) set(userID int64, perms []string) {
	c.mu.Lock()
	c.store[userID] = perms
	c.mu.Unlock()
}

func (c *permCache) invalidate(userID int64) {
	c.mu.Lock()
	delete(c.store, userID)
	c.mu.Unlock()
}

func (c *permCache) invalidateAll() {
	c.mu.Lock()
	c.store = make(map[int64][]string)
	c.mu.Unlock()
}

// RBACService 权限检查服务，通过角色继承递归解析用户的完整权限集合
type RBACService struct {
	roleRepo *repository.RoleRepository
	cache    *permCache
}

func NewRBACService(roleRepo *repository.RoleRepository) *RBACService {
	return &RBACService{
		roleRepo: roleRepo,
		cache:    &permCache{store: make(map[int64][]string)},
	}
}

// HasPermission 检查指定用户角色是否拥有某项权限，优先查缓存
func (s *RBACService) HasPermission(roleID int64, userID int64, perm string) bool {
	perms := s.getEffectivePermissions(roleID, userID)
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

// GetEffectivePermissions 对外暴露的权限查询接口
func (s *RBACService) GetEffectivePermissions(roleID, userID int64) []string {
	return s.getEffectivePermissions(roleID, userID)
}

func (s *RBACService) getEffectivePermissions(roleID, userID int64) []string {
	if cached, ok := s.cache.get(userID); ok {
		return cached
	}
	perms := s.resolveInheritedPerms(roleID, map[int64]bool{})
	s.cache.set(userID, perms)
	return perms
}

// resolveInheritedPerms 深度优先遍历角色继承链，合并所有权限
// visited 记录已访问的角色，防止继承关系成环导致无限递归
func (s *RBACService) resolveInheritedPerms(roleID int64, visited map[int64]bool) []string {
	if visited[roleID] {
		return nil
	}
	visited[roleID] = true

	role, err := s.roleRepo.FindByID(roleID)
	if err != nil {
		return nil
	}
	directs, err := s.roleRepo.GetPermissions(roleID)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var result []string
	for _, p := range directs {
		if !seen[p.Name] {
			seen[p.Name] = true
			result = append(result, p.Name)
		}
	}
	if role.ParentID != nil {
		for _, p := range s.resolveInheritedPerms(*role.ParentID, visited) {
			if !seen[p] {
				seen[p] = true
				result = append(result, p)
			}
		}
	}
	return result
}

// RoleRank 返回角色在继承链中的层级，根角色为0，每向下一级加1
// 数值越大代表权限越高，用于防止用户授予或操作不低于自身等级的角色
func (s *RBACService) RoleRank(roleID int64) int {
	rank := 0
	visited := map[int64]bool{}
	cur := roleID
	for {
		if visited[cur] {
			break
		}
		visited[cur] = true
		role, err := s.roleRepo.FindByID(cur)
		if err != nil || role.ParentID == nil {
			break
		}
		rank++
		cur = *role.ParentID
	}
	return rank
}

// UpdateRolePermissions 更新角色权限集合，并清除所有受影响用户的缓存
// 受影响范围包括直接持有该角色的用户，以及持有其子孙角色的用户，
// 因为子孙角色通过继承获得了该角色的权限
func (s *RBACService) UpdateRolePermissions(roleID int64, permIDs []int64) error {
	if err := s.roleRepo.SavePermissions(roleID, permIDs); err != nil {
		return err
	}
	affectedRoles := s.collectDescendantRoles(roleID)
	for _, rid := range affectedRoles {
		userIDs, err := s.roleRepo.FindUsersWithRole(rid)
		if err != nil {
			continue
		}
		for _, uid := range userIDs {
			s.cache.invalidate(uid)
		}
	}
	return nil
}

// collectDescendantRoles 返回指定角色自身及其所有子孙角色的ID集合
func (s *RBACService) collectDescendantRoles(roleID int64) []int64 {
	all, err := s.roleRepo.ListAll()
	if err != nil {
		return []int64{roleID}
	}
	childMap := map[int64][]int64{}
	for _, r := range all {
		if r.ParentID != nil {
			childMap[*r.ParentID] = append(childMap[*r.ParentID], r.ID)
		}
	}
	result := []int64{}
	queue := []int64{roleID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		result = append(result, cur)
		queue = append(queue, childMap[cur]...)
	}
	return result
}

// InvalidateUserCache 手动清除指定用户的权限缓存
func (s *RBACService) InvalidateUserCache(userID int64) {
	s.cache.invalidate(userID)
}

// CreateRole 创建新角色
func (s *RBACService) CreateRole(req *model.CreateRoleRequest) (*model.Role, error) {
	if req.ParentID != nil {
		if _, err := s.roleRepo.FindByID(*req.ParentID); err != nil {
			return nil, fmt.Errorf("父角色不存在: %w", err)
		}
	}
	return s.roleRepo.Create(req)
}

// ListRoles 获取所有角色列表
func (s *RBACService) ListRoles() ([]*model.Role, error) {
	return s.roleRepo.ListAll()
}

// ListPermissions 获取系统所有已注册权限
func (s *RBACService) ListPermissions() ([]*model.Permission, error) {
	return s.roleRepo.ListPermissions()
}

// GetRolePermissions 获取角色的直接权限，不含继承
func (s *RBACService) GetRolePermissions(roleID int64) ([]*model.Permission, error) {
	return s.roleRepo.GetPermissions(roleID)
}

// GetRoleByName 按名称查找角色
func (s *RBACService) GetRoleByName(name string) (*model.Role, error) {
	return s.roleRepo.FindByName(name)
}
