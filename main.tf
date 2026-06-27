###############################################################################
# Network as Code - ACI : configuration principale
#
# Reprend l'approche de l'exemple OFFICIEL "comprehensive" de Cisco
# (github.com/netascode/nac-aci-comprehensive-example) :
#   - un provider "aci" pour parler a l'APIC
#   - le module "netascode/nac-aci/aci" qui lit TOUS les *.nac.yaml dans data/
#
# Les SIX sections de la fabric sont gerees (manage_* = true) : l'utilisateur
# a donc le controle complet des objets. Les fichiers data/ sont des TEMPLATES
# VIDES a completer lors de la demo.
###############################################################################

terraform {
  required_version = ">= 1.8.0"

  required_providers {
    aci = {
      source = "CiscoDevNet/aci"
    }
  }
}

###############################################################################
# Connexion a l'APIC (methode 1 : username / password)
#
#  >>> A MODIFIER avec les informations de VOTRE APIC / simulateur <<<
#
#  insecure = true  -> accepte le certificat self-signed du simulateur
###############################################################################
provider "aci" {
  username = "admin"            # <-- a modifier
  password = "C1sco12345"       # <-- a modifier
  url      = "https://10.0.0.1" # <-- a modifier (IP/URL de l'APIC)
  insecure = true               # simulateur : certificat self-signed
}

###############################################################################
# Module Network as Code pour ACI
#   - yaml_directories : ou se trouvent les fichiers *.nac.yaml
#   - manage_*         : les SIX sections sont gerees (controle complet)
###############################################################################
module "aci" {
  source  = "netascode/nac-aci/aci"
  version = "2.0.0"

  yaml_directories = ["data"]

  manage_fabric_policies    = true
  manage_access_policies    = true
  manage_pod_policies       = true
  manage_node_policies      = true
  manage_interface_policies = true
  manage_tenants            = true
}
