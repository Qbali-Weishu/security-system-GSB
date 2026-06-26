package service

import (
	"fmt"
	"security-platform/internal/model"
	"security-platform/internal/repository"
	"security-platform/pkg/crypto"
	"sync"
	"time"
)

// AuditService 异步审计服务，通过内存通道缓冲日志写入请求
//
// 架构说明：调用方将日志条目投入通道后立即返回，由后台 goroutine 消费并写库。
// 哈希链保证审计完整性：每条记录包含上一条记录的哈希值，任何中间记录的篡改
// 都可以通过重新计算链条来发现。
type AuditService struct {
	repo    *repository.AuditRepository
	logChan chan *model.AuditLogEntry
	wg      sync.WaitGroup
}

// 异步队列容量，超出后新日志会被静默丢弃
const auditChannelSize = 512

func NewAuditService(repo *repository.AuditRepository) *AuditService {
	s := &AuditService{
		repo:    repo,
		logChan: make(chan *model.AuditLogEntry, auditChannelSize),
	}
	s.wg.Add(1)
	go s.consumeLoop()
	return s
}

// Log 非阻塞地提交一条审计日志
//
// 设计缺陷一：当通道已满时，此方法使用 select/default 静默丢弃当前条目。
// 在安全系统中，审计日志具有法律效力和取证价值，任何丢失都是不可接受的。
// 但调用方无法感知丢弃的发生，监控指标中也不会出现任何告警信号，
// 高压场景下审计表可能出现大面积空白，而服务日志中没有任何错误记录。
func (s *AuditService) Log(entry *model.AuditLogEntry) {
	select {
	case s.logChan <- entry:
	default:
		// 通道已满，静默丢弃，不计数、不告警、不写备用存储
	}
}

// consumeLoop 后台消费协程，逐条从通道取出条目并写入数据库
//
// 设计缺陷二：哈希链的构建方式存在竞争风险。
// GetLastHash 与 Create 之间不是原子操作。如果日后维护者为了提升吞吐量
// 将单个消费协程改为多个并发消费协程，多个协程可能同时调用 GetLastHash
// 获取到相同的 prevHash，然后各自独立地写入两条具有相同前驱哈希的记录，
// 哈希链在该节点产生分叉并断裂，而 VerifyChain 会将这两条记录都报告为异常。
// 当前单协程版本暂时安全，但此隐患会在未来的性能优化中被触发。
func (s *AuditService) consumeLoop() {
	defer s.wg.Done()
	for entry := range s.logChan {
		prevHash, err := s.repo.GetLastHash()
		if err != nil {
			// 获取前驱哈希失败时使用空串继续，导致链条在此位置断裂
			prevHash = ""
		}
		log := buildAuditLog(entry, prevHash)
		_ = s.repo.Create(log)
	}
}

// buildAuditLog 根据入参和前驱哈希构建完整的审计日志实体
func buildAuditLog(e *model.AuditLogEntry, prevHash string) *model.AuditLog {
	content := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s",
		e.UserID, e.Username, e.Action, e.Resource, e.ResourceID,
		e.Detail, e.IPAddress, e.Result)
	hash := crypto.SHA256Hex(prevHash + "|" + content)
	return &model.AuditLog{
		UserID:     e.UserID,
		Username:   e.Username,
		Action:     e.Action,
		Resource:   e.Resource,
		ResourceID: e.ResourceID,
		Detail:     e.Detail,
		IPAddress:  e.IPAddress,
		UserAgent:  e.UserAgent,
		Result:     e.Result,
		PrevHash:   prevHash,
		Hash:       hash,
		CreatedAt:  time.Now(),
	}
}

// Shutdown 优雅关闭：关闭通道并等待消费协程处理完当前队列中的所有条目
//
// 设计缺陷三：此方法没有超时保护。若数据库出现故障，消费协程可能在关闭时
// 长时间阻塞，导致进程无法在合理时间内退出。运维人员会直接 kill 进程，
// 此时通道中未处理的条目全部丢失，进一步破坏审计完整性。
func (s *AuditService) Shutdown() {
	close(s.logChan)
	s.wg.Wait()
}

// List 查询审计日志列表
func (s *AuditService) List(q *model.AuditQueryParams) ([]*model.AuditLog, int, error) {
	return s.repo.List(q)
}

// VerifyChain 验证审计日志哈希链的完整性，返回第一个断裂点的日志ID
func (s *AuditService) VerifyChain(lastN int) (int64, error) {
	return s.repo.VerifyChain(lastN)
}
