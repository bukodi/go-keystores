package pkcs11ks

import (
	"fmt"
	"os"
	"path/filepath"
)

func findSofthsmDriver() (string, error) {
	if envLib := os.Getenv("SOFTHSM2_LIB"); envLib != "" {
		if _, err := os.Stat(envLib); err != nil {
			return "", fmt.Errorf("can't find %q: %w", envLib, err)
		} else {
			return envLib, nil
		}
	}

	wd, _ := os.Getwd()
	dllPath := filepath.Join(filepath.Dir(wd), "test_softhsm2", "softhsm2-x64.dll")
	if _, err := os.Stat(dllPath); err != nil {
		return "", fmt.Errorf("can't find %q: %w", dllPath, err)
	} else {
		return dllPath, nil
	}

}
