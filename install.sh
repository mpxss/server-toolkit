#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  One-line installer for Server-Toolkit  |  Ubuntu 20.04+
#  Usage:  bash <(curl -fsSL https://raw.githubusercontent.com/mpxss/server-toolkit/main/install.sh)
# ──────────────────────────────────────────────────────────────
set -euo pipefail

[[ $EUID -ne 0 ]] && exec sudo -E "$0" "$@"

echo -e "\e[1;96m▶ Server-Toolkit Installer\e[0m"

TOOL_DIR="/opt/server-toolkit"
VENV="$TOOL_DIR/venv"
EXEC_BIN="/usr/local/bin/stk"
REPO="https://github.com/mpxss/server-toolkit.git"

apt-get update -qq
apt-get install -y -qq git python3 python3-venv python3-pip wget zip cron curl htop > /dev/null

if [[ -d "$TOOL_DIR/.git" ]]; then
  echo "Updating existing repo…"
  git -C "$TOOL_DIR" pull --quiet
else
  echo "Cloning repo…"
  git clone --quiet "$REPO" "$TOOL_DIR"
fi

[[ -d "$VENV" ]] || python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$TOOL_DIR/requirements.txt"

cat > "$EXEC_BIN" <<EOF
#!/usr/bin/env bash
sudo "$VENV/bin/python" "$TOOL_DIR/cli_menu.py" "\$@"
EOF
chmod +x "$EXEC_BIN"

echo -e "\n\e[1;92m✔ Installation complete!\e[0m"
echo "» write:  \e[1;93mstk\e[0m"
