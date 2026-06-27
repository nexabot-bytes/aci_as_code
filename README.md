# Network as Code — ACI : installation

Installation **en une frappe** de l'environnement Cisco *Network as Code* (NaC)
pour ACI, sur une machine **RHEL 10.x** neuve, contre un **simulateur APIC**
(authentification user/password, certificat self-signed).

Ce projet reprend la structure de l'exemple officiel Cisco
([nac-aci-comprehensive-example](https://github.com/netascode/nac-aci-comprehensive-example)) :
les **six sections** de la fabric sont gérées (`manage_* = true`), et le dossier
`data/` contient un **template vide par section**, prêt à compléter.

> `make install` installe et **valide** l'environnement. Le **déploiement**
> (ajout d'un VLAN, etc.) se fait ensuite **manuellement** avec `terraform apply`.

---

## Prérequis

- RHEL 10.x, x86_64, accès `sudo`
- Accès internet (pour Terraform, le module NaC et nac-validate)
- Un APIC / simulateur joignable

Pas besoin d'installer Terraform ni Python à la main : `make install` s'en charge.

---

## Installation en une frappe

```bash
git clone https://github.com/nexabot-bytes/aci_as_code.git
cd aci_as_code
bash install.sh
```

> C'est l'URL de ce dépôt. Un autre utilisateur n'a qu'à le cloner et lancer
> `bash install.sh` pour obtenir le même environnement.
>
> **Pourquoi `bash install.sh` et pas `make install` ?** Sur une VM RHEL 10
> minimale, `make` n'est pas installé par défaut. Le script `install.sh` ne
> dépend que de `bash` → il marche sur une VM vierge sans aucun prérequis.
> Si vous préférez `make` : `sudo dnf install -y make` puis `make install`
> (le `Makefile` fait exactement la même chose).

`make install` réalise automatiquement :

1. installe les prérequis système (`git`, `unzip`, `curl`) ;
2. installe **Terraform 1.15.7** (binaire épinglé) ;
3. installe **Python 3** et crée un venv `.venv/` avec **nac-validate** ;
4. `terraform init` → télécharge le provider `aci` et le module `netascode/nac-aci/aci` v2.0.0 ;
5. `terraform validate` + `nac-validate data/` → vérifie la config et les YAML.

À la fin, l'environnement est prêt. **Rien n'est déployé sur la fabric.**

---

## Configurer la connexion à l'APIC

Éditez le bloc `provider` dans **`main.tf`** :

```hcl
provider "aci" {
  username = "admin"               # votre utilisateur
  password = "C1sco12345"          # votre mot de passe
  url      = "https://10.0.0.1"    # IP/URL de l'APIC
  insecure = true                  # simulateur : certificat self-signed
}
```

> Le mot de passe n'est jamais commité : `terraform.tfvars`, `*.tfstate` et
> `.terraform/` sont déjà exclus via `.gitignore`.

---

## Le data model (`data/`)

Le module lit **tous** les `*.nac.yaml` du dossier `data/` et les **fusionne**.
Le découpage en plusieurs fichiers (un par section) est une **convention de
lisibilité** de l'exemple officiel — ce n'est pas obligatoire (on pourrait tout
mettre dans un seul fichier ; les noms de fichiers sont libres).

| Fichier (template vide)       | Section gérée                                   |
|-------------------------------|-------------------------------------------------|
| `apic.nac.yaml`               | Réglages globaux APIC                            |
| `fabric_policies.nac.yaml`    | BGP RR, DNS, NTP, SNMP, Syslog, backups…        |
| `access_policies.nac.yaml`    | VLAN pools, domains, AAEPs, CDP/LLDP/LACP…       |
| `pod_policies.nac.yaml`       | Pods, TEP, pod policy groups                     |
| `node_policies.nac.yaml`      | Spines/leafs, vPC groups, mgmt                   |
| `interface_policies.nac.yaml` | Affectation des policy groups aux ports          |
| `tenants.nac.yaml`            | Tenants, VRFs, BDs, EPGs, contracts, L3Outs      |
| `defaults.nac.yaml`           | **Surcharge** des valeurs par défaut du module   |

> **`defaults.nac.yaml` ≠ les défauts du module.** Le module embarque déjà un
> gros fichier de valeurs par défaut (best practices). Votre `defaults.nac.yaml`
> sert uniquement à **surcharger** ce que vous voulez changer ; laissé vide, on
> garde tous les défauts du module.

---

## Démo (manuelle, après l'installation)

1. Complétez un template, par ex. `data/tenants.nac.yaml` (ajout d'un tenant/VLAN).
2. Déployez :

```bash
terraform apply
```

Pour tout retirer :

```bash
terraform destroy
```

---

## Tester / recommencer (rollback VM)

Versions épinglées (Terraform + nac-validate) → reproductible. Après un rollback,
relancez simplement `make install`. Sans rollback :

```bash
make clean      # supprime .terraform/, state local et venv
```

---

## Commandes utiles

| Commande        | Effet                                          |
|-----------------|------------------------------------------------|
| `make install`  | Installe tout et valide (commande principale)  |
| `make deps`     | Installe Terraform + Python seulement          |
| `make init`     | `terraform init`                               |
| `make validate` | Valide la config Terraform + YAML              |
| `make clean`    | Supprime l'état local et le venv               |

---

## Références officielles

- NaC ACI — First Steps : https://netascode.cisco.com/docs/start/aci/first_steps/
- Exemple complet : https://github.com/netascode/nac-aci-comprehensive-example
- Module Terraform : https://github.com/netascode/terraform-aci-nac-aci
- Provider ACI : https://github.com/CiscoDevNet/terraform-provider-aci
