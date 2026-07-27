## Summary

-

## Testing

- [ ] `go build ./...`; `go vet` passes with ordinary and integration tags
- [ ] `gofmt -l .` is empty
- [ ] Ordinary and race tests pass
- [ ] Integration and integration-race tests pass serially on a disposable host, or are unaffected
- [ ] Staticcheck (ordinary and integration tags) and `govulncheck ./...` pass

Release/install scripts, if changed:

- [ ] `bash -n scripts/*.sh`, `sh -n scripts/install.sh`, and `shellcheck -S warning scripts/*.sh`
- [ ] `python3 -B -m unittest -v scripts/mirror_receiver_test.py`
- [ ] Invalid version/tag rejection and static amd64/arm64 builds pass

Workflows, if changed:

- [ ] `actionlint`

Documentation, if changed:

- [ ] Chinese and English user documents remain synchronized and all relative links resolve

## Safety Notes

- [ ] No real private keys (including the release signing key), invite bundles, hostnames, server IPs, `/etc/shadow` data, or production `authorized_keys` were committed.
- [ ] User/account/sudoers/systemd behavior was tested in a disposable environment, or is not affected.
