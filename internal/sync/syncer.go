package sync

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"ssh-sync-tool/internal/config"
	"ssh-sync-tool/internal/ssh"

	"io"
	"strconv"
	"syscall"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gfile"
)

type Syncer struct {
	config       *config.Config
	sshClient    *ssh.Client
	instanceLock string
	syncLock     string
}

func NewSyncer(cfg *config.Config) *Syncer {
	return &Syncer{
		config:       cfg,
		sshClient:    ssh.NewClient(cfg),
		instanceLock: cfg.InstanceLockFile,
		syncLock:     cfg.SyncLockFile,
	}
}

func (s *Syncer) createLock(ctx context.Context, lockType string) error {
	var lockFile string
	if lockType == "instance" {
		lockFile = s.instanceLock
	} else {
		lockFile = s.syncLock
	}
	if gfile.Exists(lockFile) {
		pidStr := gfile.GetContents(lockFile)
		pid, _ := strconv.Atoi(pidStr)
		if processExists(pid) {
			return fmt.Errorf("同步已在运行中，PID: %d", pid)
		}
		// 死锁清理
		gfile.Remove(lockFile)
	}
	pid := fmt.Sprintf("%d", os.Getpid())
	if err := gfile.PutContents(lockFile, pid); err != nil {
		return fmt.Errorf("创建锁文件失败: %v", err)
	}
	g.Log().Info(ctx, "创建锁文件: %s, PID: %s", lockFile, pid)
	return nil
}

func (s *Syncer) removeLock(ctx context.Context, lockType string) {
	var lockFile string
	if lockType == "instance" {
		lockFile = s.instanceLock
	} else {
		lockFile = s.syncLock
	}
	if gfile.Exists(lockFile) {
		gfile.Remove(lockFile)
		g.Log().Info(ctx, "清理锁文件: %s", lockFile)
	}
}

func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// 信号0仅检测进程是否存在
	return p.Signal(syscall.Signal(0)) == nil
}

func (s *Syncer) CheckLocalSafety(ctx context.Context) error {
	if !gfile.Exists(s.config.LocalPath) {
		g.Log().Info(ctx, "本地目录不存在，将创建: %s", s.config.LocalPath)
		return nil
	}

	// 统计本地文件
	fileCount := 0
	err := filepath.Walk(s.config.LocalPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileCount++
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("统计本地文件失败: %v", err)
	}

	dirSize := s.getDirSize(s.config.LocalPath)

	g.Log().Info(ctx, "本地目录已存在: %s", s.config.LocalPath)
	g.Log().Info(ctx, "现有文件数量: %d", fileCount)
	g.Log().Info(ctx, "目录大小: %s", dirSize)

	if fileCount > 0 {
		g.Log().Warning(ctx, "⚠️  警告: 本地目录中已有 %d 个文件", fileCount)
		g.Log().Warning(ctx, "目录大小: %s", dirSize)
	}

	return nil
}

func (s *Syncer) getDirSize(path string) string {
	cmd := exec.Command("du", "-sh", path)
	output, err := cmd.Output()
	if err != nil {
		return "未知"
	}
	parts := strings.Fields(string(output))
	if len(parts) > 0 {
		return parts[0]
	}
	return "未知"
}

func (s *Syncer) buildRsyncOptions() []string {
	options := []string{
		"--recursive",      // 递归同步
		"--links",          // 保持符号链接
		"--times",          // 保持时间戳
		"--group",          // 保持组信息
		"--owner",          // 保持所有者信息
		"--devices",        // 保持设备文件
		"--specials",       // 保持特殊文件
		"--compress",       // 压缩传输
		"--backup",         // 备份被覆盖的文件
		"--stats",          // 显示传输统计信息
		"--no-perms",       // 不同步权限
		"--no-acls",        // 不同步ACL
		"-vv",              // 更详细日志
		"--progress",       // 显示单文件进度
		"--info=progress2", // 显示总进度
	}

	// 按天生成备份目录（使用绝对路径）
	backupDir := filepath.Join(s.config.BackupDir, time.Now().Format("20060102"))
	absBackupDir, err := filepath.Abs(backupDir)
	if err != nil {
		// 无法获取绝对路径，使用相对路径
		absBackupDir = backupDir
	}
	options = append(options, "--backup-dir="+absBackupDir)

	// 带宽限制
	if s.config.BandwidthLimit != "" {
		options = append(options, "--bwlimit="+s.config.BandwidthLimit)
	}

	// 删除选项（谨慎使用）
	if s.config.EnableDelete {
		options = append(options, "--delete")
	}

	// 排除备份目录
	options = append(options, "--exclude=backup")

	return options
}

func (s *Syncer) buildSSHOptions() []string {
	options := []string{}

	// SSH端口
	if s.config.SSHPort != "22" && s.config.SSHPort != "" {
		options = append(options, "-p", s.config.SSHPort)
	}

	// SSH私钥
	sshKeyPath := s.config.SSHKey
	if strings.HasPrefix(sshKeyPath, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			// 无法获取用户主目录，使用原始路径
		} else {
			sshKeyPath = filepath.Join(homeDir, sshKeyPath[1:])
		}
	}

	if sshKeyPath != "" && gfile.Exists(sshKeyPath) {
		options = append(options, "-i", sshKeyPath)
	}

	// 连接超时
	options = append(options, "-o", fmt.Sprintf("ConnectTimeout=%d", s.config.ConnectTimeout))
	options = append(options, "-o", "BatchMode=yes")

	return options
}

func (s *Syncer) PerformSync(ctx context.Context) error {
	g.Log().Info(ctx, "开始从远程同步数据到本地...")

	// 创建必要的目录
	if err := os.MkdirAll(s.config.LocalPath, 0755); err != nil {
		return fmt.Errorf("创建本地目录失败: %v", err)
	}
	if err := os.MkdirAll(s.config.BackupDir, 0755); err != nil {
		return fmt.Errorf("创建备份目录失败: %v", err)
	}

	// 显示同步前统计
	g.Log().Info(ctx, "同步前统计:")
	g.Log().Info(ctx, "远程路径: %s", s.config.RemotePath)
	g.Log().Info(ctx, "本地路径: %s", s.config.LocalPath)

	// 获取远程统计信息
	if err := s.sshClient.Connect(ctx); err != nil {
		return fmt.Errorf("连接SSH失败: %v", err)
	}
	defer s.sshClient.Close()

	fileCount, dirSize, err := s.sshClient.GetRemoteStats(ctx)
	if err == nil {
		g.Log().Info(ctx, "远程文件数量: %d", fileCount)
		g.Log().Info(ctx, "远程目录大小: %s", dirSize)
	}

	// 构建rsync命令
	rsyncOptions := s.buildRsyncOptions()
	sshOptions := s.buildSSHOptions()

	sshCmd := "ssh " + strings.Join(sshOptions, " ")
	args := append(rsyncOptions, "-e", sshCmd)

	remotePath := fmt.Sprintf("%s@%s:%s/", s.config.RemoteUser, s.config.RemoteHost, s.config.RemotePath)
	localPath := filepath.Clean(s.config.LocalPath) + string(os.PathSeparator)
	args = append(args, remotePath, localPath)

	g.Log().Info(ctx, "执行rsync命令: rsync %s", strings.Join(args, " "))

	// 执行rsync命令
	rsyncPath := "rsync"
	if gfile.Exists("/usr/local/bin/rsync") {
		rsyncPath = "/usr/local/bin/rsync"
	}

	cmd := exec.CommandContext(ctx, rsyncPath, args...)

	// 实时读取输出
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动rsync失败: %v", err)
	}

	// 合并输出流，按字节处理，捕获进度条百分比
	go func() {
		reader := io.MultiReader(stdout, stderr)
		buf := make([]byte, 4096)
		var lineBuf []byte
		var currentFile string
		filePercentMap := make(map[string]int)
		fileNameRegex := regexp.MustCompile(`^[\p{Han}\w./\-\(\)\[\]\s]+$`)
		percentRegex := regexp.MustCompile(`(\d+)%`)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				for _, b := range chunk {
					if b == '\n' || b == '\r' {
						if len(lineBuf) > 0 {
							line := strings.TrimSpace(string(lineBuf))
							// 1. 文件名行（不含百分比、不含速度等）
							if fileNameRegex.MatchString(line) && !percentRegex.MatchString(line) && !strings.Contains(line, "kB/s") && !strings.Contains(line, "MB/s") && len(line) > 0 {
								currentFile = line
								if _, ok := filePercentMap[currentFile]; !ok {
									filePercentMap[currentFile] = -1 // -1表示未输出过
								}
							} else if percentRegex.MatchString(line) && currentFile != "" {
								matches := percentRegex.FindStringSubmatch(line)
								if len(matches) > 1 {
									percent, _ := strconv.Atoi(matches[1])
									if percent > filePercentMap[currentFile] {
										filePercentMap[currentFile] = percent
										g.Log().Info(ctx, "%s: %d%%", currentFile, percent)
									}
								}
							}
							lineBuf = lineBuf[:0]
						}
					} else {
						lineBuf = append(lineBuf, b)
					}
				}
			}
			if err != nil {
				break
			}
		}
		if len(lineBuf) > 0 {
			line := strings.TrimSpace(string(lineBuf))
			if fileNameRegex.MatchString(line) && !percentRegex.MatchString(line) && !strings.Contains(line, "kB/s") && !strings.Contains(line, "MB/s") && len(line) > 0 {
				currentFile = line
				if _, ok := filePercentMap[currentFile]; !ok {
					filePercentMap[currentFile] = -1
				}
			} else if percentRegex.MatchString(line) && currentFile != "" {
				matches := percentRegex.FindStringSubmatch(line)
				if len(matches) > 1 {
					percent, _ := strconv.Atoi(matches[1])
					if percent > filePercentMap[currentFile] {
						filePercentMap[currentFile] = percent
						g.Log().Info(ctx, "%s: %d%%", currentFile, percent)
					}
				}
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("同步失败: %v", err)
	}

	g.Log().Info(ctx, "同步成功完成")

	// 显示同步后统计
	s.showPostSyncStats(ctx)

	// 清理旧备份
	s.cleanupOldBackups(ctx)

	return nil
}

func (s *Syncer) showPostSyncStats(ctx context.Context) {
	g.Log().Info(ctx, "同步后统计:")

	if gfile.Exists(s.config.LocalPath) {
		fileCount := 0
		filepath.Walk(s.config.LocalPath, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				fileCount++
			}
			return nil
		})

		dirSize := s.getDirSize(s.config.LocalPath)
		g.Log().Info(ctx, "本地文件数量: %d", fileCount)
		g.Log().Info(ctx, "本地目录大小: %s", dirSize)
	}
}

func (s *Syncer) cleanupOldBackups(ctx context.Context) {
	if !gfile.Exists(s.config.BackupDir) {
		return
	}

	g.Log().Info(ctx, "清理旧备份文件...")

	cutoffTime := time.Now().AddDate(0, 0, -s.config.BackupRetention)
	cleanedCount := 0

	err := filepath.Walk(s.config.BackupDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() && path != s.config.BackupDir {
			if info.ModTime().Before(cutoffTime) {
				if err := os.RemoveAll(path); err == nil {
					cleanedCount++
				}
			}
		}
		return nil
	})

	if err == nil && cleanedCount > 0 {
		g.Log().Info(ctx, "已清理 %d 个旧备份目录", cleanedCount)
	}
}

func (s *Syncer) Sync(ctx context.Context) error {
	// 创建锁文件
	if err := s.createLock(ctx, "sync"); err != nil {
		return err
	}
	// defer s.removeLock(ctx) // 由主流程负责进程退出时解锁

	defer s.sshClient.Close() // 统一关闭ssh连接

	// 检查网络连接
	if err := s.sshClient.CheckNetwork(ctx); err != nil {
		return err
	}

	// 测试SSH连接
	if err := s.sshClient.TestConnection(ctx); err != nil {
		return err
	}

	// 检查远程路径
	if err := s.sshClient.CheckRemotePath(ctx); err != nil {
		return err
	}

	// 检查本地目录安全
	if err := s.CheckLocalSafety(ctx); err != nil {
		return err
	}

	// 执行同步
	return s.PerformSync(ctx)
}

func (s *Syncer) CreateLock(ctx context.Context, lockType string) error {
	return s.createLock(ctx, lockType)
}

func (s *Syncer) RemoveLock(ctx context.Context, lockType string) {
	s.removeLock(ctx, lockType)
}

// SyncPaths 只同步指定的本地文件或目录
func (s *Syncer) SyncPaths(ctx context.Context, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	if err := s.createLock(ctx, "sync"); err != nil {
		return err
	}
	defer s.sshClient.Close()
	defer s.removeLock(ctx, "sync") // 保证异常时也能清理锁

	if err := s.sshClient.CheckNetwork(ctx); err != nil {
		return err
	}
	if err := s.sshClient.TestConnection(ctx); err != nil {
		return err
	}

	// 新增：同步前检查远程目录是否存在
	if err := s.sshClient.CheckRemotePath(ctx); err != nil {
		g.Log().Warning(ctx, "远程目录不存在或不可访问，终止本次同步: %v", err)
		return nil
	}

	// 再次检查所有路径是否存在
	validPaths := make([]string, 0, len(paths))
	for _, p := range paths {
		if gfile.Exists(p) {
			validPaths = append(validPaths, p)
		} else {
			g.Log().Warning(ctx, "变动路径不存在，已跳过: %s", p)
		}
	}
	if len(validPaths) == 0 {
		g.Log().Info(ctx, "无有效变动路径，跳过本次同步")
		return nil
	}

	rs := s.buildRsyncOptions()
	sshOpts := s.buildSSHOptions()
	sshCmd := "ssh " + strings.Join(sshOpts, " ")
	rs = append(rs, "-e", sshCmd)

	remoteBase := fmt.Sprintf("%s@%s:%s/", s.config.RemoteUser, s.config.RemoteHost, s.config.RemotePath)
	for _, p := range validPaths {
		rs = append(rs, p)
	}
	rs = append(rs, remoteBase)

	g.Log().Info(ctx, "执行rsync命令: rsync %s", strings.Join(rs, " "))

	// 设置超时机制
	timeout := 60 * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rsyncPath := "rsync"
	if gfile.Exists("/usr/local/bin/rsync") {
		rsyncPath = "/usr/local/bin/rsync"
	}
	cmd := exec.CommandContext(timeoutCtx, rsyncPath, rs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动rsync失败: %v", err)
	}
	closePipes := func() {
		if stdout != nil {
			_ = stdout.Close()
		}
		if stderr != nil {
			_ = stderr.Close()
		}
	}

	// 新增：监听ctx.Done()，收到cancel信号立即强杀rsync
	cancelledByContext := false
	stopChan := make(chan struct{})
	killedByWatcher := false
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-timeoutCtx.Done():
				return
			case <-ctx.Done():
				g.Log().Warning(ctx, "同步任务收到外部中断信号，立即终止rsync进程组")
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				closePipes()
				cancelledByContext = true
				// 新增：kill后异步Wait和超时保护
				waitCh := make(chan error, 1)
				go func() {
					waitCh <- cmd.Wait()
				}()
				select {
				case err := <-waitCh:
					g.Log().Warning(ctx, "kill后Wait返回: %v", err)
				case <-time.After(2 * time.Second):
					g.Log().Warning(ctx, "kill后Wait超时，可能存在僵尸进程")
				}
				return
			case <-ticker.C:
				// 检查本地目录
				for _, p := range validPaths {
					if !gfile.Exists(p) {
						g.Log().Warning(ctx, "同步过程中本地目录消失，立即终止rsync: %s", p)
						_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
						closePipes()
						killedByWatcher = true
						return
					}
				}
				// 检查远程目录
				if err := s.sshClient.CheckRemotePath(ctx); err != nil {
					g.Log().Warning(ctx, "同步过程中远程目录消失，立即终止rsync: %v", err)
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					closePipes()
					killedByWatcher = true
					return
				}
			}
		}
	}()

	go func() {
		reader := io.MultiReader(stdout, stderr)
		buf := make([]byte, 4096)
		var lineBuf []byte
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				for _, b := range chunk {
					if b == '\n' || b == '\r' {
						if len(lineBuf) > 0 {
							g.Log().Info(ctx, string(lineBuf))
							lineBuf = lineBuf[:0]
						}
					} else {
						lineBuf = append(lineBuf, b)
					}
				}
			}
			if err != nil {
				break
			}
		}
		if len(lineBuf) > 0 {
			g.Log().Info(ctx, string(lineBuf))
		}
	}()
	waitErr := cmd.Wait()
	close(stopChan)
	if cancelledByContext {
		g.Log().Warning(ctx, "同步任务被外部中断，协程已立即退出")
		return nil
	}
	if killedByWatcher {
		g.Log().Warning(ctx, "同步过程中本地或远程目录消失，rsync已被立即终止，主循环恢复监听")
		return nil
	}
	if timeoutCtx.Err() == context.DeadlineExceeded {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		closePipes()
		g.Log().Error(ctx, "同步超时（%v），rsync进程组已被强制终止，建议检查目录状态！", timeout)
		return nil // 不中断主循环
	}
	if waitErr != nil {
		errStr := waitErr.Error()
		if strings.Contains(errStr, "No such file or directory") || strings.Contains(errStr, "没有那个文件或目录") {
			g.Log().Warning(ctx, "同步过程中有目录被重命名或删除，rsync报错: %v", waitErr)
			return nil // 不中断主循环
		}
		g.Log().Error(ctx, "同步失败: %v", waitErr)
		return waitErr
	}
	g.Log().Info(ctx, "同步成功完成")
	return nil
}

// SyncPull: 远程目录同步到本地
func (s *Syncer) SyncPull(ctx context.Context) error {
	g.Log().Info(ctx, "开始拉取远程目录到本地...")

	if err := s.createLock(ctx, "sync"); err != nil {
		g.Log().Error(ctx, "createLock失败: %v", err)
		return err
	}
	defer s.removeLock(ctx, "sync")

	if err := os.MkdirAll(s.config.LocalPath, 0755); err != nil {
		g.Log().Error(ctx, "创建本地目录失败: %v", err)
		return fmt.Errorf("创建本地目录失败: %v", err)
	}
	if err := os.MkdirAll(s.config.BackupDir, 0755); err != nil {
		g.Log().Error(ctx, "创建备份目录失败: %v", err)
		return fmt.Errorf("创建备份目录失败: %v", err)
	}

	if err := s.sshClient.Connect(ctx); err != nil {
		g.Log().Error(ctx, "连接SSH失败: %v", err)
		return fmt.Errorf("连接SSH失败: %v", err)
	}
	defer s.sshClient.Close()

	// 检查远程目录是否存在
	if err := s.checkRemoteDirectoryExists(ctx); err != nil {
		g.Log().Warning(ctx, "远程目录不存在或无法访问: %v", err)
		return nil // 协程优雅退出
	}

	// 默认同步整个远程目录
	rsOpts := s.buildRsyncOptions()
	sshOpts := s.buildSSHOptions()
	sshCmd := "ssh " + strings.Join(sshOpts, " ")
	args := append(rsOpts, "-e", sshCmd)

	remote := fmt.Sprintf("%s@%s:%s/", s.config.RemoteUser, s.config.RemoteHost, s.config.RemotePath)
	local := filepath.Clean(s.config.LocalPath) + string(os.PathSeparator)
	args = append(args, remote, local)

	g.Log().Info(ctx, "执行rsync命令: rsync %s", strings.Join(args, " "))

	rsyncPath := "rsync"
	if gfile.Exists("/usr/local/bin/rsync") {
		rsyncPath = "/usr/local/bin/rsync"
	}

	cmd := exec.CommandContext(ctx, rsyncPath, args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		g.Log().Error(ctx, "启动rsync失败: %v", err)
		return fmt.Errorf("启动rsync失败: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		reader := io.MultiReader(stdout, stderr)
		buf := make([]byte, 4096)
		var lineBuf []byte
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				for _, b := range chunk {
					if b == '\n' || b == '\r' {
						if len(lineBuf) > 0 {
							g.Log().Info(ctx, string(lineBuf))
							lineBuf = lineBuf[:0]
						}
					} else {
						lineBuf = append(lineBuf, b)
					}
				}
			}
			if err != nil {
				break
			}
		}
		if len(lineBuf) > 0 {
			g.Log().Info(ctx, string(lineBuf))
		}
	}()

	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		g.Log().Warning(ctx, "SyncPull收到context取消信号，尝试杀死rsync进程")
		_ = cmd.Process.Kill()
		return nil
	case err := <-done:
		if err != nil {
			if strings.Contains(err.Error(), "No such file or directory") ||
				strings.Contains(err.Error(), "没有那个文件或目录") {
				g.Log().Warning(ctx, "远程目录不存在，rsync报错: %v", err)
				return nil // 协程优雅退出
			}
			g.Log().Error(ctx, "rsync拉取失败: %v", err)
			return fmt.Errorf("rsync拉取失败: %v", err)
		}
	}

	g.Log().Info(ctx, "拉取远程目录到本地完成")
	return nil
}

// checkRemoteDirectoryExists 检查远程目录是否存在
func (s *Syncer) checkRemoteDirectoryExists(ctx context.Context) error {
	// 使用多种方法检查远程目录是否存在
	checkCommands := []string{
		fmt.Sprintf("test -d '%s'", s.config.RemotePath),
		fmt.Sprintf("ls -ld '%s' 2>/dev/null", s.config.RemotePath),
		fmt.Sprintf("stat '%s' 2>/dev/null", s.config.RemotePath),
	}

	for i, cmd := range checkCommands {
		session, err := s.sshClient.Client().NewSession()
		if err != nil {
			g.Log().Debug(ctx, "创建SSH会话失败，尝试下一种检查方法: %v", err)
			continue
		}

		err = session.Run(cmd)
		session.Close()

		if err == nil {
			g.Log().Info(ctx, "远程目录存在: %s", s.config.RemotePath)
			return nil
		}

		g.Log().Debug(ctx, "检查方法%d失败: %v", i+1, err)
	}

	return fmt.Errorf("远程目录不存在或无法访问: %s", s.config.RemotePath)
}

// RunRemoteShell 通过ssh执行远程命令并返回输出
func RunRemoteShell(cfg *config.Config, cmd string) ([]byte, error) {
	client := ssh.NewClient(cfg)
	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		return nil, err
	}
	defer client.Close()

	sess := client.Client()
	if sess == nil {
		return nil, fmt.Errorf("SSH未连接")
	}
	sshSession, err := sess.NewSession()
	if err != nil {
		return nil, err
	}
	defer sshSession.Close()

	out, err := sshSession.Output(cmd)
	return out, err
}
