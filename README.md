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

# MOX ECDSA public key to SSH public key format conversion

To convert the ECDSA public key as printed in U-Boot or read from
`/sys/firmware/turris-mox-rwtm/pubkey`, use the `moxpk2sshpk` utility.

```
gcc -O2 -o moxpk2sshpk moxpk2sshpk.c -lcrypto -Wall
./moxpk2sshpk <ECDSA_PUBLIC_KEY>
```
