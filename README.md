# ConfGuard

ConfGuard is a secure configuration management utility that helps you manage sensitive configuration values in version control systems. It allows you to encrypt specific configuration entries while keeping others in plain text, making it safe to commit configuration files to repositories like GitHub.

## Features

- Supports multiple configuration file formats:
  - YAML (.yaml)
  - Environment files (.env)
- Encrypts only specified sensitive values while leaving others unchanged
- Uses AES-256-GCM encryption for maximum security
- Simple command-line interface
- Supports regeneration of original files for updates

## Installation

```bash
go install github.com/redazzo/confguard@latest
```

## Usage

### Key File

Before using ConfGuard, you need to create a key file named `config_secret` in your working directory. This file should contain exactly 32 bytes of random data. You can generate it using:

```bash
openssl rand -out config_secret 32
```

Keep this file secure and share it through secure channels with your team members.

### File Naming Convention

ConfGuard uses specific file extensions to manage different versions of your configuration files:

- `.clr` - Clear text files with marked secrets (e.g., `config.yaml.clr`)
- `.enc` - Encrypted files safe for version control (e.g., `config.yaml.enc`)
- No suffix - Regular configuration files (e.g., `config.yaml`)

### Marking Secrets

In your `.clr` files, append `.secret` to any key that contains sensitive information:

```yaml
# config.yaml.clr
database:
  host: localhost
  username: dbuser
  password.secret: mysecretpassword
  port: 5432
```

### Commands

1. Encrypt a configuration file:
```bash
confguard encrypt config.yaml.clr
```
This creates `config.yaml.enc` with encrypted secret values.
```yaml
# config.yaml.enc
database:
  host: localhost
  username: dbuser
  password.secret: /#JKJHSHNC<MJOIBFMNDBDFJHDJHBFJDHB
  port: 5432
```
2. Decrypt an encrypted file:
```bash
confguard decrypt config.yaml.enc
```
This creates `config.yaml` with decrypted values and removed `.secret` suffixes.
```yaml
# config yaml
database:
host: localhost
username: dbuser
password: mysecretpassword
port: 5432
```
3. Regenerate clear file from encrypted:
```bash
confguard regen config.yaml.enc
```
This creates `config.yaml.clr` with decrypted values but maintains `.secret` suffixes.
```yaml
# config.yaml.clr
database:
host: localhost
username: dbuser
password.secret: mysecretpassword
port: 5432
```
# Team Workflow

### Important: Edit Only .clr Files

The golden rule when using ConfGuard is: **Always edit the .clr files only**. Never manually edit the .enc files or the final configuration files. This ensures:
- Consistent encryption of sensitive values
- Proper tracking of configuration changes
- No accidental exposure of secrets

### Step-by-Step Team Workflow

1. Initial Setup:
```bash
# Generate encryption key (done once per project)
openssl rand -out config_secret 32

# Create initial clear configuration
touch config.yaml.clr
# Edit config.yaml.clr with your configuration values

# Generate encrypted version
confguard encrypt config.yaml.clr
```

2. Version Control:
```bash
# Commit only the encrypted file
git add config.yaml.enc
git commit -m "Add encrypted configuration"
```

3. Team Member Setup:
```bash
# Get the config_secret file through a secure channel (not git!)
# Place it in your project directory

# Generate working configuration
confguard decrypt config.yaml.enc
```

4. Making Configuration Changes:
```bash
# First, regenerate the clear file
confguard regen config.yaml.enc

# Edit the clear file (config.yaml.clr)
vim config.yaml.clr  # or your preferred editor

# Generate new encrypted and configuration files
confguard encrypt config.yaml.clr

# Commit the updated encrypted file
git add config.yaml.enc
git commit -m "Update configuration: [describe your changes]"
```

### Git Configuration

To prevent accidental commits of sensitive files, create a `.gitignore` file in your project root with these entries:

```gitignore
# ConfGuard sensitive files
*.clr
config_secret

# Configuration files
*.yaml
*.env
.env

# Keep encrypted files
!*.enc

# Optional: IDE and system files
.idea/
.vscode/
.DS_Store
```

This `.gitignore` configuration:
- Ignores all .clr files containing unencrypted secrets
- Ignores the encryption key file (config_secret)
- Ignores all configuration files (yaml, env, etc.)
- Explicitly allows .enc files to be committed
- Optionally ignores common IDE and system files

### File Management Summary

| File Extension | Git Status | Purpose | Edit Directly? |
|---------------|------------|----------|----------------|
| .clr | Ignored | Contains unencrypted configuration with marked secrets | YES |
| .enc | Tracked | Contains encrypted configuration safe for version control | NO |
| no extension | Ignored | Working configuration files used by your application | NO |
| config_secret | Ignored | Encryption key | NO |

## Security Notes

- Never commit the `config_secret` file to version control
- Share the `config_secret` file through secure channels (e.g., password manager, secure file transfer)
- Regularly rotate the encryption key for better security
- Use environment variables for production deployments
- Always check `git status` before committing to ensure no sensitive files are included
- Regularly audit your repository to ensure no sensitive files were accidentally committed

## Best Practices

1. Always edit the .clr files, never the .enc or final configuration files
2. Set up proper `.gitignore` before starting work on configuration files
3. Document the location and sharing method of the `config_secret` file
4. Use descriptive commit messages when updating encrypted configurations
5. Regularly audit encrypted values and rotate secrets
6. Keep backup copies of the `config_secret` file in a secure location
7. Consider using different `config_secret` files for different environments (dev, staging, prod)
8. Review the diff of .enc files before committing to ensure changes are as expected

## Error Handling

ConfGuard provides clear error messages for common issues:
- Missing or invalid key file
- Incorrect file extensions
- Malformed configuration files
- Encryption/decryption failures

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting pull requests.

## License

MIT License - See LICENSE file for details
