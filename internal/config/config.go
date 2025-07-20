package config

import (
	"fmt"

	"os"

	"github.com/gogf/gf/v2/os/gfile"
	"gopkg.in/yaml.v2"
)

type Config struct {
	RemoteUser          string `json:"remoteUser" yaml:"remoteUser"`                   // 远程用户名
	RemoteHost          string `json:"remoteHost" yaml:"remoteHost"`                   // 远程主机
	RemotePath          string `json:"remotePath" yaml:"remotePath"`                   // 远程目录
	LocalPath           string `json:"localPath" yaml:"localPath"`                     // 本地目录
	LogFile             string `json:"logFile" yaml:"logFile"`                         // 日志文件
	InstanceLockFile    string `json:"instanceLockFile" yaml:"instanceLockFile"`       // 实例级锁文件
	SyncLockFile        string `json:"syncLockFile" yaml:"syncLockFile"`               // 同步级锁文件
	BackupDir           string `json:"backupDir" yaml:"backupDir"`                     // 备份目录
	SSHPort             string `json:"sshPort" yaml:"sshPort"`                         // SSH端口
	SSHKey              string `json:"sshKey" yaml:"sshKey"`                           // SSH私钥
	ShowProgress        bool   `json:"showProgress" yaml:"showProgress"`               // 是否显示详细进度
	BandwidthLimit      string `json:"bandwidthLimit" yaml:"bandwidthLimit"`           // 带宽限制（KB/s）
	EnableDelete        bool   `json:"enableDelete" yaml:"enableDelete"`               // 是否启用删除本地多余文件
	ConnectTimeout      int    `json:"connectTimeout" yaml:"connectTimeout"`           // 连接超时时间（秒）
	BackupRetention     int    `json:"backupRetention" yaml:"backupRetention"`         // 备份保留天数
	RemoteWatchInterval int    `json:"remoteWatchInterval" yaml:"remoteWatchInterval"` // 远程监听间隔（秒）
	HashFile            string `json:"hashFile" yaml:"hashFile"`                       // 本地hash文件路径
	LogLevel            string `json:"logLevel" yaml:"logLevel"`                       // 日志等级（all/info/warning/error/debug）
}

func Load(configPath string) (*Config, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := Config{}
	decoder := yaml.NewDecoder(f)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.RemoteWatchInterval == 0 {
		cfg.RemoteWatchInterval = 5
	}
	if cfg.HashFile == "" {
		cfg.HashFile = ".last_sync_hash"
	}
	if cfg.InstanceLockFile == "" {
		cfg.InstanceLockFile = "./lock/instance.lock"
	}
	if cfg.SyncLockFile == "" {
		cfg.SyncLockFile = "./lock/sync.lock"
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func Save(config *Config, configPath string) error {
	// 确保目录存在
	dir := gfile.Dir(configPath)
	if !gfile.Exists(dir) {
		if err := gfile.Mkdir(dir); err != nil {
			return err
		}
	}

	content := `# SSH 同步工具配置文件
remoteUser: "` + config.RemoteUser + `"      # 远程用户名
remoteHost: "` + config.RemoteHost + `"      # 远程主机IP或域名
remotePath: "` + config.RemotePath + `"      # 远程数据路径
localPath: "` + config.LocalPath + `"        # 本地数据路径
logFile: "` + config.LogFile + `"            # 日志文件路径
instanceLockFile: "` + config.InstanceLockFile + `"  # 服务实例锁
syncLockFile: "` + config.SyncLockFile + `"          # 同步任务锁
backupDir: "` + config.BackupDir + `"        # 备份目录
sshPort: "` + config.SSHPort + `"            # SSH端口
sshKey: "` + config.SSHKey + `"              # SSH私钥路径
showProgress: ` + fmt.Sprintf("%t", config.ShowProgress) + `                    # 是否显示详细进度
bandwidthLimit: "` + config.BandwidthLimit + `"        # 带宽限制（KB/s）
enableDelete: ` + fmt.Sprintf("%t", config.EnableDelete) + `                    # 启用删除本地多余文件
connectTimeout: ` + fmt.Sprintf("%d", config.ConnectTimeout) + `                   # 连接超时时间（秒）
backupRetention: ` + fmt.Sprintf("%d", config.BackupRetention) + `                  # 备份保留天数
remoteWatchInterval: ` + fmt.Sprintf("%d", config.RemoteWatchInterval) + `           # 远程轮询间隔（秒）
`

	return gfile.PutContents(configPath, content)
}

func (c *Config) Validate() error {
	if c.RemoteUser == "" || c.RemoteHost == "" || c.RemotePath == "" || c.LocalPath == "" {
		return fmt.Errorf("配置项缺失: remoteUser/remoteHost/remotePath/localPath 必填")
	}
	return nil
}
