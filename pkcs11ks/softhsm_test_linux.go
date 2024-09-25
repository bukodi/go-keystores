package pkcs11ks

func findSofthsmDriver() (string, error) {
	if envLib := os.Getenv("SOFTHSM2_LIB"); envLib != "" {
		if _, err := os.Stat(envLib); err != nil {
			return "", fmt.Errorf("can't find %q: %w", envLib, err)
		} else {
			return envLib, nil
		}
	}

	//var softhsm2Lib = "/usr/lib/softhsm/libsofthsm2.so"

	//var softhsm2Lib = "/opt/SoftHSMv2/lib/softhsm/libsofthsm2.so"

	//var softhsm2Lib = "libsofthsm2.so"

	var libPath = "/usr/local/lib/softhsm/libsofthsm2.so"
	if _, err := os.Stat(libPath); err == nil {
		return libPath, nil
	} else {
		return "", err
	}

}

func TestDloadLib(t *testing.T) {
	lib, err := dl.Open(softhsm2Lib, 0)
	if err != nil {
		log.Fatalln(err)
	}
	defer lib.Close()
}
