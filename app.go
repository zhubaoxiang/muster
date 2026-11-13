package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"muster/internal/engine"
	"muster/internal/guard"
	"muster/internal/model"
	"muster/internal/store"
)

// App Wails 绑定层：所有暴露给前端的方法都挂在这里。
// 引擎跑在独立 goroutine，任何 panic 都在 Engine 内部 recover，不会带崩 UI。
type App struct {
	ctx    context.Context
	store  *store.Store
	mu     sync.Mutex
	cancel context.CancelFunc
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	dbPath := dbFile()
	st, err := store.Open(dbPath)
	if err != nil {
		runtime.LogErrorf(ctx, "打开数据库失败: %v", err)
		return
	}
	a.store = st
}

func (a *App) shutdown(ctx context.Context) {
	if a.store != nil {
		_ = a.store.Close()
	}
}

func dbFile() string {
	dir, err := os.UserConfigDir()
	if err == nil {
		p := filepath.Join(dir, "muster")
		if err := os.MkdirAll(p, 0o755); err == nil {
			dst := filepath.Join(p, "muster.db")
			// 历史库名按「新 → 旧」排列：dianbing 最近一版，aiasset 更早
			migrateOldDB(dst,
				filepath.Join(dir, "dianbing", "dianbing.db"),
				filepath.Join(dir, "aiasset", "aiasset.db"),
			)
			return dst
		}
	}
	return "muster.db"
}

// migrateOldDB 兼容历史版本库名：首次以新名字运行时，把旧库整体复制过来，资产记录不丢。
// olds 按「新 → 旧」排序，命中第一个存在的就迁移后返回，避免拿更老的库覆盖新数据。
func migrateOldDB(dst string, olds ...string) {
	if _, err := os.Stat(dst); err == nil {
		return // 新库已存在，不迁移
	}
	for _, old := range olds {
		if _, err := os.Stat(old); err != nil {
			continue // 该旧库不存在，看下一个
		}
		// -wal 一并复制，保留尚未 checkpoint 的已提交数据；
		// -shm 只是共享内存索引，由 SQLite 自行重建，复制反而可能引入不一致
		for _, suffix := range []string{"", "-wal"} {
			if data, err := os.ReadFile(old + suffix); err == nil {
				_ = os.WriteFile(dst+suffix, data, 0o644)
			}
		}
		return
	}
}

// StartScan 启动一次探测任务。返回 taskID。
func (a *App) StartScan(req model.ScanRequest) (string, error) {
	if a.store == nil {
		return "", fmt.Errorf("存储未初始化")
	}
	a.mu.Lock()
	if a.cancel != nil {
		a.mu.Unlock()
		return "", fmt.Errorf("已有任务在运行，请先停止")
	}

	// 护栏：从设置读白名单 + 本次请求参数做硬校验
	settings, err := a.store.GetSettings()
	if err != nil {
		a.mu.Unlock()
		return "", err
	}
	g, err := guard.New(settings, req.AllowPublic)
	if err != nil {
		a.mu.Unlock()
		return "", err
	}
	if err := g.AddTargets(req.Targets); err != nil {
		a.mu.Unlock()
		return "", err
	}
	if g.Count() == 0 {
		a.mu.Unlock()
		return "", fmt.Errorf("没有可探测的目标")
	}

	taskID := fmt.Sprintf("t%d", timeNowUnixMilli())
	ctx, cancel := context.WithCancel(a.ctx)
	a.cancel = cancel
	a.mu.Unlock()

	eng := engine.New(g, a.store, settings.MaxRate)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				runtime.EventsEmit(a.ctx, "scan:progress", model.Progress{
					TaskID: taskID, Stage: "crashed", Error: fmt.Sprintf("%v", r),
				})
			}
			a.mu.Lock()
			a.cancel = nil
			a.mu.Unlock()
		}()
		eng.Run(ctx, taskID, req, func(p model.Progress) {
			runtime.EventsEmit(a.ctx, "scan:progress", p)
		})
	}()
	return taskID, nil
}

// StopScan 停止当前任务
func (a *App) StopScan() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel == nil {
		return fmt.Errorf("没有正在运行的任务")
	}
	a.cancel()
	return nil
}

// GetAssets 查询资产列表
func (a *App) GetAssets(limit int) ([]model.Asset, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	return a.store.ListAssets(limit)
}

// GetSettings 读取设置
func (a *App) GetSettings() (model.Settings, error) {
	if a.store == nil {
		return model.Settings{}, fmt.Errorf("存储未初始化")
	}
	s, err := a.store.GetSettings()
	if s.MaxRate <= 0 {
		s.MaxRate = 200
	}
	return s, err
}

// SaveSettings 保存设置（白名单 / 公网开关 / 并发硬顶）
func (a *App) SaveSettings(s model.Settings) error {
	if a.store == nil {
		return fmt.Errorf("存储未初始化")
	}
	if s.MaxRate <= 0 || s.MaxRate > 200 {
		s.MaxRate = 200
	}
	return a.store.SaveSettings(s)
}
