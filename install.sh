#!/usr/bin/env bash
# =============================================================================
#  Network as Code - ACI : installation "en une frappe"
#  Cible : RHEL 10.x / x86_64.
#
#  Ne necessite NI make NI unzip NI depots dnf actives.
#  Seuls prerequis : bash, curl et python3 (presents par defaut sur RHEL 10).
#
#  Usage :   bash install.sh
# =============================================================================
set -euo pipefail

TERRAFORM_VERSION="1.15.7"   # version epinglee (tests reproductibles)
VENV=".venv"

cd "$(dirname "$0")"

# --- Verification des prerequis de base ------------------------------------
missing=()
command -v curl    >/dev/null 2>&1 || missing+=(curl)
command -v python3 >/dev/null 2>&1 || missing+=(python3)
if [ "${#missing[@]}" -gt 0 ]; then
  echo "!! Outils manquants : ${missing[*]}"
  echo "   Sur RHEL il faut des depots actives pour les installer, par ex. :"
  echo "     sudo subscription-manager register --username <user> --auto-attach"
  echo "     sudo dnf install -y ${missing[*]}"
  exit 1
fi

# --- Installation de Terraform (binaire epingle, sans unzip) ----------------
if command -v terraform >/dev/null 2>&1; then
  echo ">> Terraform deja present : $(terraform version | head -1)"
else
  echo ">> Telechargement de Terraform ${TERRAFORM_VERSION}..."
  curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" -o /tmp/terraform.zip
  echo ">> Extraction (via python zipfile)..."
  rm -rf /tmp/tf_extract && mkdir -p /tmp/tf_extract
  python3 -m zipfile -e /tmp/terraform.zip /tmp/tf_extract
  sudo install -m 0755 /tmp/tf_extract/terraform /usr/local/bin/terraform
  rm -rf /tmp/terraform.zip /tmp/tf_extract
  echo ">> Terraform installe : $(terraform version | head -1)"
fi

# --- venv Python + nac-validate --------------------------------------------
echo ">> Creation du venv (${VENV}) + dependances Python..."
python3 -m venv "${VENV}"
"${VENV}/bin/python" -m pip install --quiet --upgrade pip
"${VENV}/bin/pip" install --quiet -r requirements.txt

# --- Initialisation et validation ------------------------------------------
echo ">> terraform init (provider aci + module Network as Code)..."
terraform init -input=false

echo ">> terraform validate..."
terraform validate

echo ">> nac-validate (syntaxe YAML du dossier data/)..."
"${VENV}/bin/nac-validate" data/

echo ""
echo "============================================================"
echo " Installation terminee avec succes. Rien n'a ete deploye."
echo ""
echo " Prochaine etape (demo, manuelle) :"
echo "   1. Editez le bloc 'provider' dans main.tf (user/pass/url APIC)"
echo "   2. Completez un template data/ (ex: tenants.nac.yaml)"
echo "   3. terraform apply"
echo "============================================================"
