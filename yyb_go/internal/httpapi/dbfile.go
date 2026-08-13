package httpapi

import (
	"fmt"
	"path/filepath"
)

const DefaultDBFilename = "yyb.db"

func prepareDBPath(dbDir, filename string) (string, error) {
	if filename == "" {
		filename = DefaultDBFilename
	}
	if filepath.Base(filename) != filename {
		return "", fmt.Errorf("database filename must not contain path separators: %q", filename)
	}
	return filepath.Join(dbDir, filename), nil
}
