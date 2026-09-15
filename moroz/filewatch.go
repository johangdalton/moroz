package moroz

import (
	"context"
	"os"
	"syscall"
	"time"
)

// fileStamp identifies one version of a file cheaply. A rename over the path
// changes the inode, an in-place edit changes size or mtime.
type fileStamp struct {
	exists  bool
	size    int64
	modTime int64
	inode   uint64
}

func stampFile(path string) (fileStamp, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileStamp{}, nil
		}
		return fileStamp{}, err
	}
	stamp := fileStamp{exists: true, size: info.Size(), modTime: info.ModTime().UnixNano()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		stamp.inode = uint64(st.Ino)
	}
	return stamp, nil
}

// pollReload calls reload at the interval until ctx ends, forwarding errors.
// It mirrors santaconfig.FileRepo.Watch: the reload keeps the last good state
// on failure and the caller throttles the error log.
func pollReload(ctx context.Context, interval time.Duration, reload func() error, onError func(error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := reload(); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
