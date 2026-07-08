## Summary

-

## Testing

Go (v2):

- [ ] `go build ./... && go vet -printf.funcs=printf,errorf,warnf ./...`
- [ ] `gofmt -l .` is empty
- [ ] `go test -race ./...` (and `-tags integration` on a disposable host, if touched)

Bash (v1.x), if changed:

- [ ] `bash -n temp-admin.sh tests/unit.sh` · `shellcheck -S warning temp-admin.sh tests/unit.sh scripts/*.sh` · `bash tests/unit.sh`

## Safety Notes

- [ ] No real private keys (including the release signing key), invite bundles, hostnames, server IPs, `/etc/shadow` data, or production `authorized_keys` were committed.
- [ ] User/account/sudoers/systemd behavior was tested in a disposable environment, or is not affected.
