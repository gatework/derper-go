package fileio

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// readRegularFile 以非阻塞方式打开并检查类型，拒绝 FIFO 等无取消所有权的配置输入。
// 符号链接可以指向普通文件；读取仍受大小上限限制。
func ReadRegularFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("input must be a regular file: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("input exceeds %d bytes: %s", limit, path)
	}
	return data, nil
}
