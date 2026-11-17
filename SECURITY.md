# Security notes

**Master passwords and encrypted files must never be committed to source control.** Only source code belongs in the GitHub repository.

- AES-256-GCM with independent random nonces; ciphertext integrity is verified before file export.
- scrypt strengthens password-derived key material but does not rescue a weak/reused password.
- Index and blob format is intentionally compatible with Fedora v1; public manifest reveals version, KDF settings and salt, not plaintext notes.
- Unencrypted ZIP is a separate, explicit feature and should be handled as sensitive plaintext.
- Android sandboxing and screenshot suppression are additional protections, not substitutes for Android full-device updates and a secure lock screen.
- GitHub Actions builds the project online; the installed application does not require network access.
- A GitHub debug artifact is test software, not an independently security-audited or production-release binary.
