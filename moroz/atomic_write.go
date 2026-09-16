package moroz

import (
	"os"
	"path/filepath"
)

// writeFileAtomic replaces path with data using temp+fsync+rename followed by
// a directory sync, so a crash leaves either the old or the new file. The
// temporary file is created in the same directory with the given prefix.
func writeFileAtomic(path, prefix string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, prefix)
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}
