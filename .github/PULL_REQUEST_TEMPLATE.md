## Summary

-

## Testing

- [ ] `bash -n temp-admin.sh tests/unit.sh`
- [ ] `shellcheck -S warning temp-admin.sh tests/unit.sh`
- [ ] `bash tests/unit.sh`

## Safety Notes

- [ ] No real private keys, invite bundles, hostnames, server IPs, `/etc/shadow` data, or production `authorized_keys` were committed.
- [ ] User/account/sudoers/systemd behavior was tested in a disposable environment, or is not affected.
