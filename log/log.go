package log

import (
	"github.com/rs/zerolog"
)

type Config struct {
	Level        string `yaml:"level"`         // 日志级别，支持 debug info warn error 默认info
	Filename     string `yaml:"filename"`      // 日志文件名，若文件名为空，则会将日志打印至stdout
	MaxAge       int    `yaml:"max_age"`       // 日志文件最大保存天数，默认为30
	ConsoleFmt   bool   `yaml:"console_fmt"`   // 若此选项为true，打印至stdout时将使用终端格式打印
	ConsoleColor bool   `yaml:"console_color"` // 终端打印日志时是否包含颜色
}

// defaultLogger 默认将日志打印至stdout
var defaultLogger = NewZeroLogger(&Config{
	Level:      "info",
	ConsoleFmt: true,
})

func GetDefault() zerolog.Logger {
	return defaultLogger
}

func SetDefault(conf *Config) {
	defaultLogger = NewZeroLogger(conf)
}

// Debug 打印debug级别日志
func Debug() *zerolog.Event {
	return defaultLogger.Debug()
}

// Info 打印info级别日志
func Info() *zerolog.Event {
	return defaultLogger.Info()
}

// Warn 打印warn级别日志
func Warn() *zerolog.Event {
	return defaultLogger.Warn()
}

// Error 打印error级别日志
func Error() *zerolog.Event {
	return defaultLogger.Error()
}

// Err 基于err快捷打印一个error日志
func Err(err error) *zerolog.Event {
	return defaultLogger.Err(err)
}

// Fatal 打印fatal级别日志
func Fatal() *zerolog.Event {
	return defaultLogger.Fatal()
}
