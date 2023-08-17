

If you got this error:
```bash
user@devpc:~/git/go-keystores$ go build ./...
go build github.com/go-piv/piv-go/piv:
# pkg-config --cflags  -- libpcsclite
Package libpcsclite was not found in the pkg-config search path.
Perhaps you should add the directory containing `libpcsclite.pc'
to the PKG_CONFIG_PATH environment variable
No package 'libpcsclite' found
pkg-config: exit status 1
```

Then install `libpcsclite-dev`

```bash
sudo apt install libpcsclite-dev
```
