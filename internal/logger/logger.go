package logger

import (
	"context"
	"path/filepath"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gfile"
)

func InitLogger(logFile string, level string) error {
	// 确保日志目录存在
	logDir := filepath.Dir(logFile)
	if !gfile.Exists(logDir) {
		if err := gfile.Mkdir(logDir); err != nil {
			return err
		}
	}

	if level == "" {
		level = "all"
	}

	// 配置日志输出
	g.Log().SetConfigWithMap(g.Map{
		"path":   logDir,
		"file":   filepath.Base(logFile),
		"level":  level,
		"stdout": true,
		"format": "{datetime} {level} {content}",
	})

	return nil
}

func Info(ctx context.Context, format string, args ...interface{}) {
	g.Log().Infof(ctx, format, args...)
}

func Warning(ctx context.Context, format string, args ...interface{}) {
	g.Log().Warningf(ctx, format, args...)
}

func Error(ctx context.Context, format string, args ...interface{}) {
	g.Log().Errorf(ctx, format, args...)
}

func Debug(ctx context.Context, format string, args ...interface{}) {
	g.Log().Debugf(ctx, format, args...)
}
