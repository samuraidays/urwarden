package logger

import (
	"fmt"
	"io"
	"os"
	"time"
)

// Level represents the logging level
type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

// Logger provides structured logging functionality
type Logger struct {
	level  Level
	output io.Writer
}

// New creates a new logger instance
func New(level Level, output io.Writer) *Logger {
	if output == nil {
		output = os.Stderr
	}
	return &Logger{
		level:  level,
		output: output,
	}
}

// NewDefault creates a logger with default settings
func NewDefault() *Logger {
	return New(LevelInfo, os.Stderr)
}

// SetLevel changes the logging level
func (l *Logger) SetLevel(level Level) {
	l.level = level
}

// SetOutput changes the output writer
func (l *Logger) SetOutput(w io.Writer) {
	l.output = w
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LevelError, "ERROR", format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LevelWarn, "WARN", format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, "INFO", format, args...)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LevelDebug, "DEBUG", format, args...)
}

// log is the internal logging method
func (l *Logger) log(level Level, levelStr, format string, args ...interface{}) {
	if level > l.level {
		return
	}

	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	message := fmt.Sprintf(format, args...)

	_, _ = fmt.Fprintf(l.output, "[%s] %s: %s\n", timestamp, levelStr, message)
}

// Global logger instance
var Default = NewDefault()

// Convenience functions for global logger
func Error(format string, args ...interface{}) {
	Default.Error(format, args...)
}

func Warn(format string, args ...interface{}) {
	Default.Warn(format, args...)
}

func Info(format string, args ...interface{}) {
	Default.Info(format, args...)
}

func Debug(format string, args ...interface{}) {
	Default.Debug(format, args...)
}
