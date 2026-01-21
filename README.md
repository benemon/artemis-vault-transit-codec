# Vault Transit Codec for Apache ActiveMQ Artemis

A `SensitiveDataCodec` implementation that integrates Apache ActiveMQ Artemis password masking with HashiCorp Vault Transit secrets engine.

## Overview

This codec allows Artemis broker passwords to be encrypted at rest using Vault Transit. Passwords are:
1. Encrypted out-of-band via the `./artemis mask` CLI command
2. Stored as ciphertext in `broker.xml`
3. Decrypted at broker startup/runtime

## Prerequisites

- Java 17 or later
- Apache ActiveMQ Artemis 2.39.0+
- HashiCorp Vault with Transit secrets engine enabled

## Building

```bash
mvn clean package
```

This produces:
- `target/vault-transit-codec-1.0.0.jar` - Standard JAR
- `target/vault-transit-codec-1.0.0-shaded.jar` - Uber JAR with all dependencies (use this one)

## Installation

Copy the shaded JAR to your Artemis instance:

```bash
cp target/vault-transit-codec-1.0.0-shaded.jar $ARTEMIS_INSTANCE/lib/
```

## Configuration

### Environment Variables

The codec supports standard Vault environment variables (same as Vault CLI/SDKs):

| Environment Variable | Description | Required |
|---------------------|-------------|----------|
| `VAULT_ADDR` | Vault server address (e.g., `https://vault:8200`) | Yes |
| `VAULT_TOKEN` | Vault authentication token | No* |
| `VAULT_TOKEN_FILE` | Path to file containing Vault token | No* |
| `VAULT_NAMESPACE` | Vault namespace (Vault Enterprise only) | No |
| `VAULT_SKIP_VERIFY` | Skip TLS certificate verification | No |
| `VAULT_CACERT` | Path to CA certificate for TLS | No |
| `VAULT_CLIENT_CERT` | Path to client certificate for mTLS | No |
| `VAULT_CLIENT_KEY` | Path to client key for mTLS | No |
| `VAULT_ROLE_ID` | AppRole role ID | No** |
| `VAULT_SECRET_ID` | AppRole secret ID | No** |
| `VAULT_SECRET_ID_FILE` | Path to file containing AppRole secret ID | No** |

\* One of `VAULT_TOKEN` or `VAULT_TOKEN_FILE` is required for token authentication.

\*\* Required when using AppRole authentication.

### broker.xml Parameters

Parameters in `broker.xml` override environment variables:

```xml
<password-codec>com.hashicorp.artemis.VaultTransitCodec;vault-addr=https://vault:8200;transit-key=artemis</password-codec>
```

| Parameter | Environment Equivalent | Default | Description |
|-----------|----------------------|---------|-------------|
| `vault-addr` | `VAULT_ADDR` | (required) | Vault server address |
| `transit-mount` | - | `transit` | Transit secrets engine mount path |
| `transit-key` | - | `artemis` | Transit key name |
| `namespace` | `VAULT_NAMESPACE` | - | Vault namespace for authentication (Enterprise) |
| `transit-namespace` | - | - | Namespace for Transit operations (if different from auth) |
| `auth-method` | - | `token` | Authentication method: `token` or `approle` |
| `token-path` | `VAULT_TOKEN_FILE` | `/vault/secrets/.vault-token` | Path to token file |
| `skip-verify` | `VAULT_SKIP_VERIFY` | `false` | Skip TLS verification |
| `ca-cert` | `VAULT_CACERT` | - | CA certificate path |
| `client-cert` | `VAULT_CLIENT_CERT` | - | Client certificate path |
| `client-key` | `VAULT_CLIENT_KEY` | - | Client key path |
| `approle-id` | `VAULT_ROLE_ID` | - | AppRole role ID |
| `approle-secret-file` | `VAULT_SECRET_ID_FILE` | - | AppRole secret file path |
| `cache-ttl-seconds` | - | `300` | Password cache TTL (0 to disable) |
| `max-retries` | - | `3` | Max retries for transient failures |

#### Cross-Namespace Configuration (Vault Enterprise)

When authentication and Transit are in different namespaces, use both `namespace` and `transit-namespace`:

```xml
<password-codec>com.hashicorp.artemis.VaultTransitCodec;namespace=admin;transit-namespace=admin/tenant;transit-key=artemis</password-codec>
```

- `namespace`: Where authentication occurs (e.g., `admin`)
- `transit-namespace`: Where the Transit engine is mounted (e.g., `admin/tenant`)

## Vault Setup

### 1. Enable Transit Secrets Engine

```bash
vault secrets enable transit
```

### 2. Create Transit Key

```bash
vault write -f transit/keys/artemis
```

### 3. Create Policy

Create a policy file `artemis-codec.hcl`:

```hcl
# Allow encrypt/decrypt operations
path "transit/encrypt/artemis" {
  capabilities = ["update"]
}

path "transit/decrypt/artemis" {
  capabilities = ["update"]
}

# Optional: Allow reading key info (for verification)
path "transit/keys/artemis" {
  capabilities = ["read"]
}
```

Apply the policy:

```bash
vault policy write artemis-codec artemis-codec.hcl
```

### 4. Create Token or AppRole

**Option A: Token Authentication**

```bash
vault token create -policy=artemis-codec -ttl=24h
```

**Option B: AppRole Authentication**

```bash
# Enable AppRole
vault auth enable approle

# Create role
vault write auth/approle/role/artemis-codec \
    token_policies=artemis-codec \
    token_ttl=1h \
    token_max_ttl=24h

# Get role ID
vault read auth/approle/role/artemis-codec/role-id

# Generate secret ID
vault write -f auth/approle/role/artemis-codec/secret-id
```

## Usage

For general password masking concepts (`artemis mask`, `ENC()` syntax, supported locations), see the [Artemis Password Masking documentation](https://artemis.apache.org/components/artemis/documentation/latest/masking-passwords.html).

### 1. Configure broker.xml

```xml
<core xmlns="urn:activemq:core">
    <password-codec>com.hashicorp.artemis.VaultTransitCodec;transit-key=artemis</password-codec>
</core>
```

### 2. Mask Passwords

Set Vault environment variables, then use the Artemis CLI:

```bash
export VAULT_ADDR=https://vault:8200
export VAULT_TOKEN=s.xxxxx

./bin/artemis mask myClusterPassword --password-codec=true
# Output: vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM96XVZ
```

### 3. Update broker.xml

```xml
<core xmlns="urn:activemq:core">
    <password-codec>com.hashicorp.artemis.VaultTransitCodec;transit-key=artemis</password-codec>
    <cluster-password>ENC(vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM96XVZ)</cluster-password>
</core>
```

### 4. Start Broker

```bash
export VAULT_ADDR=https://vault:8200
export VAULT_TOKEN_FILE=/vault/secrets/.vault-token

./artemis run
```

Successful initialization:
```
INFO  [com.hashicorp.artemis.VaultTransitCodec] VaultTransitCodec initialized. Vault: https://vault:8200, NS: (root), Mount: transit, Key: artemis, Auth: token
```

## Troubleshooting

### Common Errors

**"Missing required configuration: Vault address"**
- Set `VAULT_ADDR` environment variable or `vault-addr` parameter

**"No Vault token found"**
- Set `VAULT_TOKEN` or `VAULT_TOKEN_FILE` environment variable
- Or configure `token-path` parameter pointing to a token file

**"Transit key 'xxx' not found"**
- Create the Transit key: `vault write -f transit/keys/xxx`

**"Permission denied for transit/encrypt/xxx"**
- Verify Vault policy grants `update` capability on `transit/encrypt/xxx`

**"Permission denied for transit/decrypt/xxx"**
- Verify Vault policy grants `update` capability on `transit/decrypt/xxx`

### Debug Logging

Enable debug logging in Artemis `logging.properties`:

```properties
logger.vault-codec.name=com.hashicorp.artemis
logger.vault-codec.level=DEBUG
```

## Security Considerations

- **Use AppRole in production** - Supports automatic re-authentication when tokens expire
- **Always use TLS** - Set `VAULT_ADDR` to `https://` and configure CA certificates
- **Restrict token file permissions** - Use mode 600 for any token or secret files

## License

Apache License 2.0
