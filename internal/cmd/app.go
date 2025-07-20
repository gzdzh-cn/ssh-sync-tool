package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"ssh-sync-tool/internal/config"
	"ssh-sync-tool/internal/logger"
	"ssh-sync-tool/internal/ssh"
	syncmod "ssh-sync-tool/internal/sync"

	"crypto/md5"
	"io/ioutil"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
)

type App struct {
	config *config.Config
}

func NewApp(configPath string) (*App, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("加载配置文件失败: %v", err)
	}

	// 初始化日志，支持日志等级
	if err := logger.InitLogger(cfg.LogFile, cfg.LogLevel); err != nil {
		return nil, fmt.Errorf("初始化日志失败: %v", err)
	}

	return &App{
		config: cfg,
	}, nil
}

func (a *App) ShowHelp() {
	version := getVersionFromFile()
	fmt.Println("SSH远程到本地单向同步工具")
	fmt.Println("")
	fmt.Printf("版本: %s\n", version)
	fmt.Println("")
	fmt.Println("用法: ssh-sync-tool [命令] [参数]")
	fmt.Println("")
	fmt.Println("常用命令:")
	fmt.Println("  sync, s                执行同步 (默认)")
	fmt.Println("  test, t                测试SSH连接")
	fmt.Println("  conf, config           显示当前配置")
	fmt.Println("  ver, version           显示版本信息")
	fmt.Println("  w, watch               本地目录监听自动同步")
	fmt.Println("  wr, watch-remote       远程目录轮询自动同步")
	fmt.Println("  wrh, watch-remote-hash 远程hash监听自动同步")
	fmt.Println("  help, h                显示帮助信息")
	fmt.Println("")
	fmt.Println("参数:")
	fmt.Println("  -c, --config <文件>    指定配置文件 (默认: config.yaml)")
	fmt.Println("  --config=xxx.yaml      同上")
	fmt.Println("  -q, --quiet            静默模式")
	fmt.Println("  -v, --verbose          详细模式")
	fmt.Println("")
	fmt.Println("示例:")
	fmt.Println("  ssh-sync-tool sync -c my.yaml")
	fmt.Println("  ssh-sync-tool test")
	fmt.Println("  ssh-sync-tool wrh --config=prod.yaml")
	fmt.Println("  ssh-sync-tool -q")
	fmt.Println("  ssh-sync-tool w")
}

func (a *App) ShowConfig() {
	fmt.Println("当前配置:")
	fmt.Printf("  远程用户: %s\n", a.config.RemoteUser)
	fmt.Printf("  远程主机: %s\n", a.config.RemoteHost)
	fmt.Printf("  SSH端口: %s\n", a.config.SSHPort)
	fmt.Printf("  远程路径: %s\n", a.config.RemotePath)
	fmt.Printf("  本地路径: %s\n", a.config.LocalPath)
	fmt.Printf("  日志文件: %s\n", a.config.LogFile)
	fmt.Printf("  备份目录: %s\n", a.config.BackupDir)
	fmt.Printf("  SSH密钥: %s\n", a.config.SSHKey)
	fmt.Printf("  进度显示: %t\n", a.config.ShowProgress)
	fmt.Printf("  带宽限制: %s KB/s\n", a.config.BandwidthLimit)
	fmt.Printf("  启用删除: %t\n", a.config.EnableDelete)
	fmt.Printf("  连接超时: %d 秒\n", a.config.ConnectTimeout)
	fmt.Printf("  备份保留: %d 天\n", a.config.BackupRetention)
}

func (a *App) ShowVersion() {
	fmt.Println("SSH同步工具 v1.0.0")
	fmt.Println("基于 GoFrame 框架开发")
}

func (a *App) TestConnection(ctx context.Context) error {
	logger.Info(ctx, "=== 开始连接测试 ===")

	sshClient := ssh.NewClient(a.config)

	// 检查网络连接
	if err := sshClient.CheckNetwork(ctx); err != nil {
		return err
	}

	// 测试SSH连接
	if err := sshClient.TestConnection(ctx); err != nil {
		logger.Error(ctx, "请检查SSH配置：")
		logger.Error(ctx, "1. 确保SSH密钥正确配置")
		logger.Error(ctx, "2. 检查远程主机防火墙设置")
		logger.Error(ctx, "3. 验证用户名和主机地址")
		return err
	}

	// 检查远程路径
	if err := sshClient.CheckRemotePath(ctx); err != nil {
		logger.Error(ctx, "请检查远程路径配置")
		return err
	}

	logger.Info(ctx, "=== 连接测试完成 ===")
	return nil
}

func (a *App) Sync(ctx context.Context) error {
	logger.Info(ctx, "=== SSH远程到本地同步开始 ===")

	syncer := syncmod.NewSyncer(a.config)

	if err := syncer.Sync(ctx); err != nil {
		logger.Error(ctx, "=== 同步失败 ===")
		return err
	}

	syncer.RemoveLock(ctx, "sync") // 同步结束后主动删除同步锁文件

	logger.Info(ctx, "=== 同步成功完成 ===")
	return nil
}

func (a *App) WatchAndSync(ctx context.Context) error {
	logger.Info(ctx, "=== 启动hash监听与抢占式自动同步 ===")

	syncer := syncmod.NewSyncer(a.config)
	hashFile := a.config.HashFile
	interval := time.Duration(a.config.RemoteWatchInterval) * time.Second
	var lastHash [16]byte

	// 读取本地hash
	data, err := os.ReadFile(hashFile)
	if err != nil || len(data) != 32 {
		logger.Info(ctx, "未检测到本地hash，正在计算本地目录hash...")
		cmd := fmt.Sprintf("ls -lR --time-style=full-iso '%s' 2>/dev/null", a.config.LocalPath)
		out, err := exec.Command("bash", "-c", cmd).Output()
		if err == nil {
			localHash := md5.Sum(out)
			logger.Info(ctx, "本地目录hash已生成")
			var buf []byte
			buf = fmt.Appendf(buf, "%x", localHash)
			os.WriteFile(hashFile, buf, 0644)
			lastHash = localHash
		} else {
			logger.Error(ctx, "本地目录hash计算失败: %v", err)
		}
	} else {
		var tmp [16]byte
		fmt.Sscanf(string(data), "%x", &tmp)
		lastHash = tmp
	}

	// 同步任务管理
	syncCtx, syncCancel := context.WithCancel(ctx)
	var syncWg sync.WaitGroup
	var syncLock sync.Mutex
	isSyncing := false

	// 启动监听协程
	go func() {
		for {
			// 计算当前hash
			cmd := fmt.Sprintf("ls -lR --time-style=full-iso '%s' 2>/dev/null", a.config.LocalPath)
			out, err := exec.Command("bash", "-c", cmd).Output()
			if err != nil {
				logger.Error(ctx, "监听hash计算失败: %v", err)
				time.Sleep(interval)
				continue
			}
			hash := md5.Sum(out)
			logger.Info(ctx, "远程目录当前hash: %x", hash) // 每次都打印
			if lastHash != hash {
				logger.Info(ctx, "监听到本地hash变化，准备抢占式同步...")
				syncLock.Lock()
				if isSyncing {
					logger.Info(ctx, "已有同步任务在进行，取消旧同步...")
					syncCancel()  // 取消上一个同步
					syncWg.Wait() // 等待上一个同步完全退出
				}
				// 启动新同步
				syncCtx, syncCancel = context.WithCancel(ctx)
				isSyncing = true
				syncWg.Add(1)
				go func(myCtx context.Context, myHash [16]byte) {
					defer syncWg.Done()
					if err := syncer.SyncPaths(myCtx, []string{a.config.LocalPath}); err != nil {
						logger.Error(ctx, "自动同步失败: %v", err)
					} else {
						logger.Info(ctx, "自动同步完成，重新计算并保存本地hash")
						// 同步完成后重新计算本地hash
						cmd := fmt.Sprintf("ls -lR --time-style=full-iso '%s' 2>/dev/null", a.config.LocalPath)
						out, _ := exec.Command("bash", "-c", cmd).Output()
						newHash := md5.Sum(out)
						var buf []byte
						buf = fmt.Appendf(buf, "%x", newHash)
						os.WriteFile(hashFile, buf, 0644)
						lastHash = newHash
						logger.Info(ctx, "本地目录最新hash: %x", newHash)
					}
					syncLock.Lock()
					isSyncing = false
					syncLock.Unlock()
				}(syncCtx, hash)
				syncLock.Unlock()
			}
			time.Sleep(interval)
		}
	}()

	// 主线程阻塞，直到ctx被取消
	<-ctx.Done()
	logger.Info(ctx, "监听主循环退出")
	return nil
}

func (a *App) WatchRemoteAndSync(ctx context.Context) error {
	logger.Info(ctx, "=== 启动远程目录变动监听与自动同步 ===")
	syncer := syncmod.NewSyncer(a.config)
	sshClient := ssh.NewClient(a.config)

	hashFile := a.config.HashFile // hash文件路径从配置读取
	var lastHash [16]byte
	interval := time.Duration(a.config.RemoteWatchInterval) * time.Second // 轮询间隔

	// 读取本地hash
	data, err := os.ReadFile(hashFile)
	if err != nil || len(data) != 32 {
		// 没有本地hash文件，先计算本地目录hash
		logger.Info(ctx, "未检测到本地hash，正在计算本地目录hash...")
		cmd := fmt.Sprintf("ls -lR --time-style=full-iso '%s' 2>/dev/null", a.config.LocalPath)
		out, err := exec.Command("bash", "-c", cmd).Output()
		if err == nil {
			localHash := md5.Sum(out)
			logger.Info(ctx, "本地目录hash已生成")
			var buf []byte
			buf = fmt.Appendf(buf, "%x", localHash)
			os.WriteFile(hashFile, buf, 0644)
			lastHash = localHash
		} else {
			logger.Error(ctx, "本地目录hash计算失败: %v", err)
		}
	} else {
		var tmp [16]byte
		fmt.Sscanf(string(data), "%x", &tmp)
		lastHash = tmp
	}

	if err := sshClient.Connect(ctx); err != nil {
		logger.Error(ctx, "SSH连接失败: %v", err)
		return err
	}
	defer sshClient.Close()

	for {
		// 1. 检查连接是否可用
		if sshClient.Client() == nil {
			err := sshClient.Connect(ctx)
			if err != nil {
				logger.Error(ctx, "SSH重连失败: %v", err)
				time.Sleep(interval)
				continue
			}
			logger.Info(ctx, "SSH重连成功")
		}

		// 2. 创建session
		session, err := sshClient.Client().NewSession()
		if err != nil {
			logger.Error(ctx, "创建SSH会话失败: %v，尝试重连", err)
			sshClient.Close()
			continue // 下次循环会自动重连
		}

		// 4. 正常执行命令
		cmd := fmt.Sprintf("ls -lR --time-style=full-iso '%s' 2>/dev/null", a.config.RemotePath)
		var outBuf strings.Builder
		session.Stdout = &outBuf
		err = session.Run(cmd)
		session.Close()
		if err != nil {
			logger.Error(ctx, "获取远程目录快照失败: %v", err)
			time.Sleep(interval)
			continue
		}
		// 计算快照hash
		hash := md5.Sum([]byte(outBuf.String()))
		if lastHash != hash {
			logger.Info(ctx, "本地与远程hash不一致，开始自动同步...")
			if err := syncer.Sync(ctx); err != nil {
				logger.Error(ctx, "自动同步失败: %v", err)
			} else {
				logger.Info(ctx, "自动同步完成，重新计算并保存本地hash")
				// 同步完成后重新计算本地hash
				cmd := fmt.Sprintf("ls -lR --time-style=full-iso '%s' 2>/dev/null", a.config.LocalPath)
				out, _ := exec.Command("bash", "-c", cmd).Output()
				newHash := md5.Sum(out)
				var buf []byte
				buf = fmt.Appendf(buf, "%x", newHash)
				os.WriteFile(hashFile, buf, 0644)
				lastHash = newHash
				logger.Info(ctx, "本地目录最新hash: %x", newHash)
			}
			syncer.RemoveLock(ctx, "sync") // 每次同步后主动删除同步锁文件
		}
		time.Sleep(interval)
	}
}

func (a *App) WatchRemoteHashAndSync(ctx context.Context) error {
	logger.Info(ctx, "=== 启动远程hash监听与抢占式自动同步 ===")

	syncer := syncmod.NewSyncer(a.config)
	hashFile := a.config.HashFile
	watchInterval := time.Duration(a.config.RemoteWatchInterval) * time.Second
	var lastRemoteHash [16]byte
	var lastLocalHash [16]byte

	if _, err := os.Stat(a.config.LocalPath); os.IsNotExist(err) {
		if mkErr := os.MkdirAll(a.config.LocalPath, 0755); mkErr != nil {
			logger.Error(ctx, "自动创建本地目录失败: %v", mkErr)
			return mkErr
		}
	}

	logger.Info(ctx, "建立SSH连接...")
	sshClient := ssh.NewClient(a.config)
	if err := sshClient.Connect(ctx); err != nil {
		logger.Error(ctx, "SSH连接失败: %v", err)
		return err
	}
	defer sshClient.Close()
	logger.Info(ctx, "SSH连接建立成功，将复用此连接")

	lastLocalHash, err := a.CalculateHash(ctx, a.config.LocalPath, false, nil)
	if err != nil {
		logger.Error(ctx, "初始化本地hash失败: %v", err)
		return err
	}
	logger.Info(ctx, "本地目录初始hash: %x", lastLocalHash)

	var syncCtx context.Context
	var syncCancel context.CancelFunc
	var syncWg sync.WaitGroup
	var syncLock sync.Mutex
	isSyncing := false

	logger.Info(ctx, "启动首次hash对比协程")
	go a.StartInitialHashCompare(ctx, sshClient, syncer, hashFile, &lastRemoteHash, &lastLocalHash, &syncLock, &isSyncing, &syncCtx, &syncCancel, &syncWg)

	logger.Info(ctx, "启动远程hash监听协程，间隔: %v", watchInterval)
	go a.StartRemoteHashWatcher(ctx, sshClient, syncer, hashFile, &lastRemoteHash, &lastLocalHash, &syncLock, &isSyncing, &syncCtx, &syncCancel, &syncWg, watchInterval)

	<-ctx.Done()
	logger.Info(ctx, "远程监听主循环退出")
	if syncCancel != nil {
		syncCancel()
	}
	return nil
}

// 首次hash对比协程
func (a *App) StartInitialHashCompare(ctx context.Context, sshClient *ssh.Client, syncer *syncmod.Syncer, hashFile string, lastRemoteHash *[16]byte, lastLocalHash *[16]byte, syncLock *sync.Mutex, isSyncing *bool, syncCtx *context.Context, syncCancel *context.CancelFunc, syncWg *sync.WaitGroup) {
	// 检查远程目录是否存在
	checkDirCmd := fmt.Sprintf("test -d '%s'", a.config.RemotePath)
	if _, err := a.RunRemoteCmd(ctx, sshClient, checkDirCmd); err != nil {
		logger.Warning(ctx, "远程目录不存在，跳过首次同步: %s", a.config.RemotePath)
		return
	}

	remoteHash, err := a.CalculateHash(ctx, a.config.RemotePath, true, sshClient)
	if err != nil {
		logger.Error(ctx, "首次远程hash计算失败: %v", err)
		return
	}
	localHash, err := a.CalculateHash(ctx, a.config.LocalPath, false, nil)
	if err != nil {
		logger.Error(ctx, "首次本地hash计算失败: %v", err)
		return
	}
	logger.Info(ctx, "首次对比 - 远程目录hash: %x, 本地目录hash: %x", remoteHash, localHash)
	if remoteHash != localHash {
		logger.Info(ctx, "首次对比发现hash不一致，启动同步协程...")
		syncLock.Lock()
		if !*isSyncing {
			*syncCtx, *syncCancel = context.WithCancel(ctx)
			*isSyncing = true
			syncWg.Add(1)
			logger.Info(ctx, "启动首次同步任务，目标hash: %x", remoteHash)
			go func(myCtx context.Context, myHash [16]byte) {
				defer syncWg.Done()
				defer func() {
					if r := recover(); r != nil {
						logger.Error(ctx, "同步协程发生panic: %v", r)
					}
					syncLock.Lock()
					*isSyncing = false
					logger.Debug(ctx, "同步协程结束，isSyncing已复位")
					syncLock.Unlock()
				}()
				logger.Info(ctx, "同步任务开始执行，目标hash: %x", myHash)
				if err := syncer.SyncPull(myCtx); err != nil {
					if myCtx.Err() == context.Canceled {
						logger.Info(ctx, "同步被取消，这是正常行为")
						return
					}
					logger.Error(ctx, "同步失败: %v", err)
					return
				} else {
					logger.Info(ctx, "同步完成，重新计算并保存本地hash")
					newHash, err := a.CalculateHash(ctx, a.config.LocalPath, false, nil)
					if err != nil {
						logger.Error(ctx, "重新计算本地hash失败: %v", err)
					} else {
						var buf []byte
						buf = fmt.Appendf(buf, "%x", newHash)
						os.WriteFile(hashFile, buf, 0644)
						*lastLocalHash = newHash
						logger.Info(ctx, "本地目录最新hash: %x", newHash)
						remoteHashAfterSync, err := a.CalculateHash(ctx, a.config.RemotePath, true, sshClient)
						if err != nil {
							logger.Error(ctx, "验证远程hash失败: %v", err)
						} else if newHash != remoteHashAfterSync {
							logger.Warning(ctx, "同步后hash不一致！本地: %x, 远程: %x", newHash, remoteHashAfterSync)
							return
						} else {
							logger.Info(ctx, "✅ 同步验证成功，本地和远程hash一致: %x", newHash)
							*lastRemoteHash = myHash
							logger.Debug(ctx, "同步协程完成，lastRemoteHash已更新: %x", *lastRemoteHash)
						}
					}
				}
			}(*syncCtx, remoteHash)
		}
		syncLock.Unlock()
		logger.Info(ctx, "首次同步任务已启动")
	} else {
		logger.Info(ctx, "首次对比 - 远程/本地hash一致，无需同步")
	}
}

// 远程hash监听协程
func (a *App) StartRemoteHashWatcher(ctx context.Context, sshClient *ssh.Client, syncer *syncmod.Syncer, hashFile string, lastRemoteHash *[16]byte, lastLocalHash *[16]byte, syncLock *sync.Mutex, isSyncing *bool, syncCtx *context.Context, syncCancel *context.CancelFunc, syncWg *sync.WaitGroup, watchInterval time.Duration) {

	for {
		logger.Debug(ctx, "监听循环开始: isSyncing=%v", *isSyncing)
		select {
		case <-ctx.Done():
			logger.Info(ctx, "监听协程收到退出信号")
			return
		default:
			checkDirCmd := fmt.Sprintf("test -d '%s'", a.config.RemotePath)
			if _, err := a.RunRemoteCmd(ctx, sshClient, checkDirCmd); err != nil {
				logger.Warning(ctx, "远程目录不存在: %s", a.config.RemotePath)
				syncLock.Lock()
				if *isSyncing {
					if *syncCancel != nil {
						(*syncCancel)()
					}
					*isSyncing = false
					logger.Info(ctx, "远程目录不存在，已停止当前同步协程，isSyncing已复位")
				}
				syncLock.Unlock()
				time.Sleep(watchInterval)
				continue
			}
			currentRemoteHash, err := a.CalculateHash(ctx, a.config.RemotePath, true, sshClient)
			if err != nil {
				logger.Error(ctx, "监听协程远程hash计算失败: %v", err)
				time.Sleep(watchInterval)
				continue
			}
			logger.Debug(ctx, "监听协程 - 当前远程hash: %x, 上次远程hash: %x", currentRemoteHash, *lastRemoteHash)
			if currentRemoteHash != *lastRemoteHash {
				logger.Info(ctx, "检测到远程hash变化，停止当前同步协程并启动新同步协程")
				syncLock.Lock()
				if *isSyncing {
					if *syncCancel != nil {
						(*syncCancel)()
					}
					*isSyncing = false
					logger.Info(ctx, "已停止当前同步协程")
				}
				syncLock.Unlock()
				logger.Info(ctx, "等待旧同步协程完全退出...")
				syncWg.Wait()
				logger.Info(ctx, "旧同步协程已完全退出")
				syncLock.Lock()
				*lastRemoteHash = currentRemoteHash // 先更新，防止重复触发
				*syncCtx, *syncCancel = context.WithCancel(ctx)
				*isSyncing = true
				syncWg.Add(1)
				logger.Info(ctx, "启动新同步任务，目标hash: %x", currentRemoteHash)

				go func(myCtx context.Context, myHash [16]byte) {
					defer syncWg.Done()
					defer func() {
						if r := recover(); r != nil {
							logger.Error(ctx, "同步协程发生panic: %v", r)
						}
						syncLock.Lock()
						*isSyncing = false
						logger.Debug(ctx, "同步协程结束，isSyncing已复位")
						syncLock.Unlock()
					}()
					logger.Info(ctx, "同步任务开始执行，目标hash: %x", myHash)
					if err := syncer.SyncPull(myCtx); err != nil {
						if myCtx.Err() == context.Canceled {
							logger.Info(ctx, "同步被取消，这是正常行为")
							return
						}
						logger.Error(ctx, "同步失败: %v", err)
						return
					} else {
						logger.Info(ctx, "同步完成，重新计算并保存本地hash")
						newHash, err := a.CalculateHash(ctx, a.config.LocalPath, false, nil)
						if err != nil {
							logger.Error(ctx, "重新计算本地hash失败: %v", err)
						} else {
							var buf []byte
							buf = fmt.Appendf(buf, "%x", newHash)
							os.WriteFile(hashFile, buf, 0644)
							*lastLocalHash = newHash
							logger.Info(ctx, "本地目录最新hash: %x", newHash)
							remoteHashAfterSync, err := a.CalculateHash(ctx, a.config.RemotePath, true, sshClient)
							if err != nil {
								logger.Error(ctx, "验证远程hash失败: %v", err)
							} else if newHash != remoteHashAfterSync {
								logger.Warning(ctx, "同步后hash不一致！本地: %x, 远程: %x", newHash, remoteHashAfterSync)
								return
							} else {
								logger.Info(ctx, "✅ 同步验证成功，本地和远程hash一致: %x", newHash)
								*lastRemoteHash = myHash
								logger.Debug(ctx, "同步协程完成，lastRemoteHash已更新: %x", *lastRemoteHash)
							}
						}
					}
				}(*syncCtx, currentRemoteHash)
				syncLock.Unlock()
				logger.Info(ctx, "新同步任务已启动")
			} else {
				logger.Debug(ctx, "远程hash无变化，继续监听")
			}
			time.Sleep(watchInterval)
		}
	}
}

// 新增：App方法，复用ssh连接执行远程命令
func (a *App) RunRemoteCmd(ctx context.Context, sshClient *ssh.Client, cmd string) ([]byte, error) {
	sess := sshClient.Client()
	if sess == nil {
		return nil, fmt.Errorf("SSH未连接")
	}
	sshSession, err := sess.NewSession()
	if err != nil {
		return nil, err
	}
	defer sshSession.Close()
	return sshSession.Output(cmd)
}

// 新增：App方法，统一本地/远程hash计算
func (a *App) CalculateHash(ctx context.Context, path string, isRemote bool, sshClient *ssh.Client) ([16]byte, error) {
	var cmd string
	if isRemote {
		cmd = fmt.Sprintf("cd '%s' && find . -type f -exec stat -c '%%n %%s' {} \\; | sort", path)
	} else {
		cmd = fmt.Sprintf("cd '%s' && find . -type f -exec stat -f '%%N %%z' {} \\; | sort", path)
	}
	var out []byte
	var err error
	if isRemote {
		out, err = a.RunRemoteCmd(ctx, sshClient, cmd)
	} else {
		out, err = exec.Command("bash", "-c", cmd).Output()
	}
	if err != nil {
		return [16]byte{}, err
	}
	logger.Debug(ctx, "Hash计算命令: %s", cmd)
	logger.Debug(ctx, "Hash计算输出长度: %d", len(out))
	if len(out) < 200 {
		logger.Debug(ctx, "Hash计算输出: %s", string(out))
	}
	hash := md5.Sum(out)
	logger.Debug(ctx, "计算出的hash: %x", hash)
	return hash, nil
}

func (a *App) SetQuietMode() {
	a.config.ShowProgress = false
}

func (a *App) SetVerboseMode() {
	a.config.ShowProgress = true
}

// 新增：命令别名映射
var commandAlias = map[string]string{
	"sync":              "sync",
	"s":                 "sync",
	"test":              "test",
	"t":                 "test",
	"conf":              "show-config",
	"config":            "show-config",
	"show-config":       "show-config",
	"ver":               "version",
	"v":                 "version",
	"version":           "version",
	"w":                 "watch",
	"watch":             "watch",
	"wr":                "watch-remote",
	"watch-remote":      "watch-remote",
	"wrh":               "watch-remote-hash",
	"watch-remote-hash": "watch-remote-hash",
	"help":              "help",
	"h":                 "help",
}

// 优化参数解析，支持主命令+子命令风格和原有参数
func ParseArgs(args []string) (action string, configPath string, err error) {
	action = "sync"            // 默认动作
	configPath = "config.yaml" // 默认配置文件

	// 先查找主命令
	for i, arg := range args {
		// 支持 --config=xxx.yaml
		if strings.HasPrefix(arg, "--config=") {
			configPath = strings.TrimPrefix(arg, "--config=")
			continue
		}
		if strings.HasPrefix(arg, "-c=") {
			configPath = strings.TrimPrefix(arg, "-c=")
			continue
		}
		if arg == "-c" || arg == "--config" {
			if i+1 < len(args) {
				configPath = args[i+1]
			}
			continue
		}
		// 命令别名
		if v, ok := commandAlias[strings.TrimLeft(arg, "-")]; ok {
			action = v
			continue
		}
		// 兼容原有参数
		switch arg {
		case "-q", "--quiet":
			action = "quiet-sync"
		case "-v", "--verbose":
			action = "verbose-sync"
		}
	}
	return action, configPath, nil
}

// 新增：读取 version.go 里的 Version 变量
func getVersionFromFile() string {
	path := filepath.Join("version.go")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "var Version") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				ver := strings.Trim(parts[1], " \"'")
				return ver
			}
		}
	}
	return "unknown"
}

func Run() {
	ctx := context.Background()
	args := os.Args[1:]

	action, configPath, err := ParseArgs(args)
	if err != nil {
		fmt.Printf("参数解析错误: %v\n", err)
		os.Exit(1)
	}

	if action == "help" {
		app := &App{}
		app.ShowHelp()
		return
	}

	if action == "version" {
		app := &App{}
		app.ShowVersion()
		return
	}

	app, err := NewApp(configPath)
	if err != nil {
		fmt.Printf("初始化应用失败: %v\n", err)
		os.Exit(1)
	}

	// 只在需要同步的模式下加实例锁
	var syncer *syncmod.Syncer
	if action == "sync" || action == "watch" || action == "watch-remote" || action == "quiet-sync" || action == "verbose-sync" || action == "watch-remote-hash" {
		syncer = syncmod.NewSyncer(app.config)
		if err := syncer.CreateLock(ctx, "instance"); err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		// 信号监听，优雅清理锁
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-c
			fmt.Printf("\n收到信号 %v，正在清理实例锁和同步锁并退出...\n", sig)
			syncer.RemoveLock(ctx, "instance")
			syncer.RemoveLock(ctx, "sync") // 新增：退出时一并清理同步锁
			os.Exit(0)
		}()
		defer syncer.RemoveLock(ctx, "instance")
	}

	switch action {
	case "show-config":
		app.ShowConfig()
	case "test":
		if err := app.TestConnection(ctx); err != nil {
			logger.Error(ctx, "连接测试失败: %v", err)
			os.Exit(1)
		}
	case "quiet-sync":
		app.SetQuietMode()
		if err := app.Sync(ctx); err != nil {
			logger.Error(ctx, "同步失败: %v", err)
			os.Exit(1)
		}
	case "verbose-sync":
		app.SetVerboseMode()
		if err := app.Sync(ctx); err != nil {
			logger.Error(ctx, "同步失败: %v", err)
			os.Exit(1)
		}
	case "watch":
		if err := app.WatchAndSync(ctx); err != nil {
			logger.Error(ctx, "监听与同步失败: %v", err)
			os.Exit(1)
		}
	case "watch-remote":
		if err := app.WatchRemoteAndSync(ctx); err != nil {
			logger.Error(ctx, "远程监听与同步失败: %v", err)
			os.Exit(1)
		}
	case "watch-remote-hash":
		if err := app.WatchRemoteHashAndSync(ctx); err != nil {
			logger.Error(ctx, "远程hash监听同步失败: %v", err)
			os.Exit(1)
		}
	default: // "sync"
		if err := app.Sync(ctx); err != nil {
			logger.Error(ctx, "同步失败: %v", err)
			os.Exit(1)
		}
	}
}
