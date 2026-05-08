# Examples

## 1. Inventory a single certificate

```bash
pqc-readiness inventory --cert ./tls.pem
```

## 2. Inventory a directory and write a CBOM

```bash
pqc-readiness inventory --directory ./certs --output cbom.json
```

## 3. List algorithms only (machine-readable)

```bash
pqc-readiness algorithms --directory ./certs
```

The output is a JSON array suitable for piping to `jq` or your own tooling.
