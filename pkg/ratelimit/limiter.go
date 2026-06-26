package ratelimit

import (
	"sync"
	"time"
)

// 单个键的访问记录窗口
type window struct {
	count     int
	windowEnd time.Time
}

// Limiter 基于固定时间窗口的内存限流器，线程安全
type Limiter struct {
	mu       sync.Mutex
	records  map[string]*window
	limit    int
	duration time.Duration
}

// NewLimiter 创建限流器，limit为时间窗口内允许的最大次数
func NewLimiter(limit int, duration time.Duration) *Limiter {
	l := &Limiter{
		records:  make(map[string]*window),
		limit:    limit,
		duration: duration,
	}
	go l.cleanupLoop()
	return l
}

// Allow 判断指定键是否允许本次访问，超限返回false
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	rec, exists := l.records[key]
	if !exists || now.After(rec.windowEnd) {
		l.records[key] = &window{count: 1, windowEnd: now.Add(l.duration)}
		return true
	}
	if rec.count >= l.limit {
		return false
	}
	rec.count++
	return true
}

// Remaining 返回当前时间窗口内剩余可访问次数
func (l *Limiter) Remaining(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, exists := l.records[key]
	if !exists || time.Now().After(rec.windowEnd) {
		return l.limit
	}
	if l.limit-rec.count < 0 {
		return 0
	}
	return l.limit - rec.count
}

// Reset 手动重置某个键的计数，用于登录成功后清除失败记录
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.records, key)
	l.mu.Unlock()
}

// cleanupLoop 定期清理已过期的窗口记录，防止内存无限增长
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for k, rec := range l.records {
			if now.After(rec.windowEnd) {
				delete(l.records, k)
			}
		}
		l.mu.Unlock()
	}
}
