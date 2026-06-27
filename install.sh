#!/usr/bin/env bash
# =============================================================================
#  Network as Code - ACI : installation "en une frappe"
#  Cible : RHEL 10.x / x86_64. Ne necessite PAS make (juste bash).
#
#  Usage :   bash install.sh
# =============================================================================
set -euo pipefail

TERRAFORM_VERSION="1.15.7"   # version epinglee (tests reproductibles)
VENV=".venv"

cd "$(dirname "$0")"

echo ">> Prerequis systeme (dnf)..."
sudo dnf install -y git unzip curl python3 python3-pip

if command -v terraform >/dev/null 2>&1; then
  echo ">> Terraform deja present : $(terraform version | head -1)"
else
  echo ">> Telechargement de Terraform ${TERRAFORM_VERSION}..."
  curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" -o /tmp/terraform.zip
  sudo unzip -o /tmp/terraform.zip -d /usr/local/bin/
  rm -f /tmp/terraform.zip
  echo ">> Terraform installe : $(terraform version | head -1)"
fi

echo ">> Creation du venv (${VENV}) + dependances Python..."
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --quiet --upgrade pip
"${VENV}/bin/pip" install --quiet -r requirements.txt

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
