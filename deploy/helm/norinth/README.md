# Norinth Helm chart

```bash
helm install norinth oci://ghcr.io/revenant-research/charts/norinth \
  --set database.url='postgresql://norinth:PASSWORD@postgres.internal:5432/norinth' \
  --set secrets.secretKey="$(openssl rand -base64 32)" \
  --set secrets.superAdminPassword="$(openssl rand -base64 24)" \
  --set config.publicBaseUrl=https://norinth.example.com \
  --set ingress.enabled=true --set ingress.hosts[0].host=norinth.example.com
```

Production: put the database URL and secrets in your own Secret (Vault, ESO,
SealedSecrets) and reference it with `database.existingSecret` /
`secrets.existingSecret`. The pod is stateless; scale `replicaCount` freely.
See `values.yaml` for every option and `docs/operations.md` for configuration.

Verify the image before you trust it:

```bash
cosign verify ghcr.io/revenant-research/norinth:<version> \
  --certificate-identity-regexp 'https://github.com/revenant-research/norinth/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
