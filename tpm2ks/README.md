
## Troubleshooting

### Error: compilation failed 
If you have compilation error, check whether the `libssl-dev` package is installed. If not, install it using the following command:
```bash
sudo apt-get install libssl-dev
```

### Error: tpmrm0 permission denied
If you have the following error:
```
can't open TPM "/dev/tpmrm0": open /dev/tpmrm0: permission denied
```
You need to add the current user to the `tss` group:
```bash
sudo usermod -a -G tss $USER
```
Then, log out and log back in.

### Error: Tpm DA lockout mode
This error occurs when the TPM is in lockout mode, because too many invalid login tries. To unlock the TPM, you need to restart the computer or you can use the following command:
```bash
sudo tpm2_clear
```
