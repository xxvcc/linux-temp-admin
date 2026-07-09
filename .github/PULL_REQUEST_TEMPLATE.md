## Summary

-

## Testing

- [ ] `go build ./... && go vet -printf.funcs=printf,errorf,warnf ./...`
- [ ] `gofmt -l .` is empty
- [ ] `go test -race ./...` (and `-tags integration` on a disposable host, if touched)

Release/install scripts, if changed:

- [ ] `shellcheck -S warning scripts/*.sh`

## Safety Notes

- [ ] No real private keys (including the release signing key), invite bundles, hostnames, server IPs, `/etc/shadow` data, or production `authorized_keys` were committed.
- [ ] User/account/sudoers/systemd behavior was tested in a disposable environment, or is not affected.
