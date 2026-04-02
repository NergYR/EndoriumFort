#!/usr/bin/env bash
set -euo pipefail

# Generate a dedicated GPG key pair for APT repo signing and print
# GitHub Actions secrets values:
# - APT_GPG_PRIVATE_KEY_BASE64
# - APT_GPG_PASSPHRASE (optional)
# - APT_GPG_KEY_ID

KEY_NAME="${KEY_NAME:-EndoriumFort APT Signing}"
KEY_EMAIL="${KEY_EMAIL:-security@endoriumfort.local}"
KEY_EXPIRE="${KEY_EXPIRE:-2y}"
APT_GPG_PASSPHRASE="${APT_GPG_PASSPHRASE:-}"
OUTPUT_DIR="${OUTPUT_DIR:-./.apt-gpg}"
GITHUB_REPO="${GITHUB_REPO:-}"

mkdir -p "$OUTPUT_DIR"
GNUPGHOME="$(mktemp -d)"
chmod 700 "$GNUPGHOME"
export GNUPGHOME

cleanup() {
  rm -rf "$GNUPGHOME"
}
trap cleanup EXIT

if ! command -v gpg >/dev/null 2>&1; then
  echo "gpg is required" >&2
  exit 1
fi

KEY_PARAMS="$OUTPUT_DIR/keyparams.batch"
cat > "$KEY_PARAMS" <<EOF
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: ${KEY_NAME}
Name-Email: ${KEY_EMAIL}
Expire-Date: ${KEY_EXPIRE}
$( [[ -n "$APT_GPG_PASSPHRASE" ]] && echo "Passphrase: ${APT_GPG_PASSPHRASE}" || echo "%no-protection" )
%commit
EOF

gpg --batch --generate-key "$KEY_PARAMS"

FINGERPRINT="$(gpg --batch --list-secret-keys --with-colons | awk -F: '/^fpr:/ {print $10; exit}')"
if [[ -z "$FINGERPRINT" ]]; then
  echo "Failed to read generated key fingerprint" >&2
  exit 1
fi

PRIVATE_ASC="$OUTPUT_DIR/apt-private-key.asc"
PUBLIC_ASC="$OUTPUT_DIR/apt-public-key.asc"
PUBLIC_URL_COPY="$OUTPUT_DIR/public.key"
PRIVATE_B64_FILE="$OUTPUT_DIR/APT_GPG_PRIVATE_KEY_BASE64.txt"

gpg --batch --armor --export-secret-keys "$FINGERPRINT" > "$PRIVATE_ASC"
gpg --batch --armor --export "$FINGERPRINT" > "$PUBLIC_ASC"
cp "$PUBLIC_ASC" "$PUBLIC_URL_COPY"

base64 -w 0 "$PRIVATE_ASC" > "$PRIVATE_B64_FILE"

cat <<EOF

APT signing key generated.

Files:
- Private key (ASCII armored): $PRIVATE_ASC
- Public key  (ASCII armored): $PUBLIC_ASC
- Public key for APT repo      : $PUBLIC_URL_COPY
- Base64 private key value     : $PRIVATE_B64_FILE

GitHub Actions secrets values:
- APT_GPG_PRIVATE_KEY_BASE64 = $(cat "$PRIVATE_B64_FILE")
- APT_GPG_KEY_ID             = $FINGERPRINT
- APT_GPG_PASSPHRASE         = ${APT_GPG_PASSPHRASE:-<empty>}

Recommended:
- Keep $PRIVATE_ASC and $PRIVATE_B64_FILE in a secure vault.
- Commit only public.key to publish trust material.
EOF

if command -v gh >/dev/null 2>&1 && [[ -n "$GITHUB_REPO" ]]; then
  echo
  echo "Setting GitHub secrets in $GITHUB_REPO ..."
  gh secret set APT_GPG_PRIVATE_KEY_BASE64 --repo "$GITHUB_REPO" < "$PRIVATE_B64_FILE"
  gh secret set APT_GPG_KEY_ID --repo "$GITHUB_REPO" --body "$FINGERPRINT"
  if [[ -n "$APT_GPG_PASSPHRASE" ]]; then
    gh secret set APT_GPG_PASSPHRASE --repo "$GITHUB_REPO" --body "$APT_GPG_PASSPHRASE"
  fi
  echo "Secrets uploaded."
fi
