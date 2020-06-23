# Simple MOX PKCS#11 provider

You can use this to use internal ECDSA key burned into Turris MOX to connect via ssh.

## Compilation

```
gcc -fPIC -O2 -o libmox-pkcs11.so mox-pkcs11.c -lcrypto -Wall -shared
```

## Export of public key

```
ssh-keygen -D /path/libmox-pkcs11.so -e
```

## SSH connection

```
ssh -o 'PKCS11Provider /path/libmox-pkcs11.so' user@host
```
