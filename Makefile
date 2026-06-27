# =============================================================================
#  Network as Code - ACI : installation "en une frappe"
#  Cible : RHEL 10.x / Python 3.12 / x86_64
#
#  Commande principale :   make install
# =============================================================================

# --- Versions epinglees (pour des tests reproductibles apres rollback VM) ---
TERRAFORM_VERSION ?= 1.15.7
VENV              ?= .venv

SHELL := /bin/bash

.PHONY: install deps terraform-bin python-deps init validate clean help

# -----------------------------------------------------------------------------
# install : installe tout puis valide. NE DEPLOIE RIEN (pas de terraform apply).
# -----------------------------------------------------------------------------
install: deps init validate
	@echo ""
	@echo "============================================================"
	@echo " Installation terminee avec succes."
	@echo ""
	@echo " Prochaine etape (demo, manuelle) :"
	@echo "   1. Editez le bloc 'provider' dans main.tf"
	@echo "      (username / password / url de votre APIC)"
	@echo "   2. Completez les templates dans data/ (ex: tenants.nac.yaml)"
	@echo "   3. terraform apply"
	@echo "============================================================"

# -----------------------------------------------------------------------------
# deps : prerequis systeme + Terraform + dependances Python
# -----------------------------------------------------------------------------
deps: terraform-bin python-deps

# Installe Terraform (binaire epingle) seulement s'il est absent
terraform-bin:
	@if command -v terraform >/dev/null 2>&1; then \
		echo ">> Terraform deja present : $$(terraform version | head -1)"; \
	else \
		echo ">> Installation des prerequis systeme (dnf)..."; \
		sudo dnf install -y git unzip curl; \
		echo ">> Telechargement de Terraform $(TERRAFORM_VERSION)..."; \
		curl -fsSL https://releases.hashicorp.com/terraform/$(TERRAFORM_VERSION)/terraform_$(TERRAFORM_VERSION)_linux_amd64.zip -o /tmp/terraform.zip; \
		sudo unzip -o /tmp/terraform.zip -d /usr/local/bin/; \
		rm -f /tmp/terraform.zip; \
		echo ">> Terraform installe : $$(terraform version | head -1)"; \
	fi

# Cree le venv Python et installe nac-validate
python-deps:
	@echo ">> Installation de Python 3 (dnf)..."
	@sudo dnf install -y python3 python3-pip
	@echo ">> Creation du venv ($(VENV)) + installation des dependances..."
	@python3 -m venv $(VENV)
	@$(VENV)/bin/pip install --quiet --upgrade pip
	@$(VENV)/bin/pip install --quiet -r requirements.txt
	@echo ">> Dependances Python installees."

# -----------------------------------------------------------------------------
# init : telecharge le provider aci + le module Network as Code
# -----------------------------------------------------------------------------
init:
	@echo ">> terraform init..."
	@terraform init -input=false

# -----------------------------------------------------------------------------
# validate : validation Terraform (HCL) + validation YAML (nac-validate)
# -----------------------------------------------------------------------------
validate:
	@echo ">> terraform validate..."
	@terraform validate
	@echo ">> nac-validate (syntaxe YAML du dossier data/)..."
	@$(VENV)/bin/nac-validate data/
	@echo ">> Validation OK."

# -----------------------------------------------------------------------------
# clean : supprime l'etat local, le venv et les fichiers temporaires
# -----------------------------------------------------------------------------
clean:
	@rm -rf .terraform .terraform.lock.hcl terraform.tfstate* $(VENV)
	@echo ">> Nettoye."

# -----------------------------------------------------------------------------
# help : affiche les commandes disponibles
# -----------------------------------------------------------------------------
help:
	@echo "Commandes disponibles :"
	@echo "  make install   - installe tout et valide (commande principale)"
	@echo "  make deps      - installe Terraform + Python uniquement"
	@echo "  make init      - terraform init"
	@echo "  make validate  - valide la config Terraform + YAML"
	@echo "  make clean     - supprime l'etat local et le venv"
