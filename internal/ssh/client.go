package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ssh-sync-tool/internal/config"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gfile"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	config *config.Config
	client *ssh.Client
}

func NewClient(cfg *config.Config) *Client {
	return &Client{
		config: cfg,
	}
}

func (c *Client) Connect(ctx context.Context) error {
	var auth []ssh.AuthMethod

	// 使用私钥认证
	sshKeyPath := c.config.SSHKey
	if strings.HasPrefix(sshKeyPath, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("获取用户主目录失败: %v", err)
		}
		sshKeyPath = filepath.Join(homeDir, sshKeyPath[1:])
	}

	if sshKeyPath != "" && gfile.Exists(sshKeyPath) {
		key, err := os.ReadFile(sshKeyPath)
		if err != nil {
			return fmt.Errorf("读取SSH私钥失败: %v", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("解析SSH私钥失败: %v", err)
		}

		auth = append(auth, ssh.PublicKeys(signer))
	}

	// SSH客户端配置
	sshConfig := &ssh.ClientConfig{
		User:            c.config.RemoteUser,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 注意：生产环境应该验证主机密钥
		Timeout:         time.Duration(c.config.ConnectTimeout) * time.Second,
	}

	// 连接
	addr := net.JoinHostPort(c.config.RemoteHost, c.config.SSHPort)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("SSH连接失败: %v", err)
	}

	c.client = client
	g.Log().Info(ctx, "SSH连接成功: %s@%s:%s", c.config.RemoteUser, c.config.RemoteHost, c.config.SSHPort)
	return nil
}

func (c *Client) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

func (c *Client) TestConnection(ctx context.Context) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	// defer c.Close() // 不要在这里关闭

	// 测试执行简单命令
	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	output, err := session.Output("echo 'SSH连接测试成功'")
	if err != nil {
		return fmt.Errorf("执行测试命令失败: %v", err)
	}

	g.Log().Info(ctx, "SSH测试输出: %s", string(output))
	return nil
}

func (c *Client) CheckRemotePath(ctx context.Context) error {
	if c.client == nil {
		if err := c.Connect(ctx); err != nil {
			return err
		}
	}

	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	// 检查远程路径是否存在
	cmd := fmt.Sprintf("[ -d '%s' ]", c.config.RemotePath)
	err = session.Run(cmd)
	if err != nil {
		return fmt.Errorf("远程路径不存在: %s", c.config.RemotePath)
	}

	g.Log().Info(ctx, "远程路径存在: %s", c.config.RemotePath)
	return nil
}

func (c *Client) GetRemoteStats(ctx context.Context) (fileCount int, dirSize string, err error) {
	if c.client == nil {
		if err := c.Connect(ctx); err != nil {
			return 0, "", err
		}
	}

	session, err := c.client.NewSession()
	if err != nil {
		return 0, "", fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	// 获取文件数量和目录大小
	cmd := fmt.Sprintf("find '%s' -type f | wc -l; du -sh '%s' 2>/dev/null | cut -f1",
		c.config.RemotePath, c.config.RemotePath)

	output, err := session.Output(cmd)
	if err != nil {
		return 0, "", fmt.Errorf("获取远程统计信息失败: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) >= 2 {
		fileCountStr := strings.TrimSpace(lines[0])
		fc, convErr := strconv.Atoi(fileCountStr)
		if convErr != nil {
			return 0, "", fmt.Errorf("文件数量转换失败: %v", convErr)
		}
		fileCount = fc
		dirSize = strings.TrimSpace(lines[1])
	}

	return fileCount, dirSize, nil
}

func (c *Client) CheckNetwork(ctx context.Context) error {
	// 简单的网络连通性检查
	timeout := time.Duration(c.config.ConnectTimeout) * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.config.RemoteHost, c.config.SSHPort), timeout)
	if err != nil {
		return fmt.Errorf("网络连接失败: %v", err)
	}
	conn.Close()

	g.Log().Info(ctx, "网络连接正常")
	return nil
}

func (c *Client) Client() *ssh.Client {
	return c.client
}
