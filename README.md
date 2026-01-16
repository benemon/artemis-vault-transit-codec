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

### 1. Configure broker.xml

First, configure the codec in broker.xml:

```xml
<core xmlns="urn:activemq:core">
    <!-- Configure the codec -->
    <password-codec>com.hashicorp.artemis.VaultTransitCodec;transit-key=artemis</password-codec>
</core>
```

### 2. Mask Passwords

Use the Artemis CLI to encrypt passwords. The command reads the codec from broker.xml:

```bash
export VAULT_ADDR=https://vault:8200
export VAULT_TOKEN=s.xxxxx

./bin/artemis mask myClusterPassword --password-codec=true
```

Output:
```
result: vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM96XVZ
```

### 3. Update broker.xml with Encrypted Passwords

Add the encrypted passwords to broker.xml, wrapped with `ENC()`:

```xml
<core xmlns="urn:activemq:core">
    <!-- Configure the codec -->
    <password-codec>com.hashicorp.artemis.VaultTransitCodec;transit-key=artemis</password-codec>

    <!-- Use encrypted passwords -->
    <cluster-password>ENC(vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM96XVZ)</cluster-password>

    <connectors>
        <connector name="netty-connector">
            tcp://remote-host:61616?sslEnabled=true;keyStorePassword=ENC(vault:v1:...)
        </connector>
    </connectors>
</core>
```

### 4. Start Broker

Ensure Vault environment variables are set, then start the broker:

```bash
export VAULT_ADDR=https://vault:8200
export VAULT_TOKEN_FILE=/vault/secrets/.vault-token

./artemis run
```

Look for this log message to confirm successful initialization:
```
INFO  [com.hashicorp.artemis.VaultTransitCodec] VaultTransitCodec initialized. Vault: https://vault:8200, NS: (root), Mount: transit, Key: artemis, Auth: token
```

### 5. Update artemis-users.properties

The codec also works with user passwords in `artemis-users.properties`. First mask each password using the codec configured in `broker.xml`:

```bash
./bin/artemis mask adminPassword123 --password-codec=true
```

Then update the properties file with encrypted passwords:

```properties
# artemis-users.properties
# Format: username = ENC(ciphertext)

admin = ENC(vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM96XVZ)
appuser = ENC(vault:v1:7KLm2XYDNef8nq58DzDrZkCXBjRRAWYSlGN85WVY)
monitoring = ENC(vault:v1:9TRn4ZHFPgj9or79EAEsAlDZCkSSBUZTmHO97XWX)
```

Ensure `login.config` references the properties file with the password codec:

```
activemq {
    org.apache.activemq.artemis.spi.core.security.jaas.PropertiesLoginModule required
        org.apache.activemq.jaas.properties.user="artemis-users.properties"
        org.apache.activemq.jaas.properties.role="artemis-roles.properties";
};
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

1. **Token Security**: Store Vault tokens in files with restricted permissions (600)
2. **TLS**: Always use TLS in production (`https://` for Vault address)
3. **Token Renewal**: The codec automatically renews tokens at 2/3 of TTL
4. **AppRole**: Prefer AppRole over long-lived tokens in production
5. **Cache**: Password cache is in-memory only; adjust `cache-ttl-seconds` based on security requirements

## License

Apache License 2.0
