# ACI as Code — Brownfield Network-as-Code pour Cisco ACI

Outil de **reprise brownfield** pour [Cisco Network as Code](https://netascode.cisco.com/) :
il photographie une fabric ACI **existante** dans le data model NaC (YAML), l'adopte dans
Terraform **sans jamais écrire sur la fabric**, puis permet de la gérer en Infrastructure-as-Code
— avec un dispositif de sûreté conçu pour qu'aucune opération ne puisse provoquer de panne
(secrets écrasés, objets détruits, configuration remise aux défauts).

```
   Fabric ACI existante ──capture──▶ data/*.nac.yaml ──adopt──▶ state Terraform
        (lecture seule)              (source de vérité)         (import, zéro POST)
                                            │
                              l'équipe édite le YAML (git)
                                            │
                                          sync  ──▶ terraform apply (gardes-fous)
```

## Composants

| Élément | Rôle |
|---|---|
| [`tools/nac.py`](tools/nac.py) | L'outil : `capture` / `validate` / `plan` / `sync` / `adopt` / `drift` / `bootstrap` |
| [`data/*.nac.yaml`](data/) | Le data model NaC (une section par fichier), généré par `capture`, édité ensuite par l'équipe |
| `main.tf` + module [`netascode/nac-aci`](https://github.com/netascode/terraform-aci-nac-aci) v2.0.0 | Le déploiement Terraform officiel Cisco (non modifié) |
| [`tools/test_nac.py`](tools/test_nac.py) | Outillage de test : audit, couverture, round-trip, selftest |

Le mapping APIC ↔ YAML est **dérivé automatiquement** des blocs `content {}` des sous-modules
Terraform officiels (source de vérité versionnée) — complété par ~60 captures dédiées pour les
objets enfants, relations et attributs complexes.

## Installation (RHEL 10.x, une frappe)

```bash
git clone https://github.com/nexabot-bytes/aci_as_code.git
cd aci_as_code
bash install.sh          # Terraform épinglé + venv + terraform init + validations
```

Configurer ensuite la connexion APIC dans le bloc `provider "aci"` de `main.tf`
(surchargeable par `APIC_URL` / `APIC_USER` / `APIC_PWD`).

## Workflow brownfield (l'ordre est important)

```bash
python tools/nac.py capture     # 1. photo complète de la fabric -> data/ (LECTURE SEULE)
python tools/nac.py validate    # 2. validation du schéma (nac-validate)
python tools/nac.py plan        # 3. aperçu terraform (ne change rien)
python tools/nac.py adopt --yes # 4. adoption par IMPORT terraform (zéro POST fabric)
python tools/nac.py plan        # 5. attendu : « No changes » = round-trip parfait
```

Ensuite, cycle de vie normal : éditer `data/*.nac.yaml` (revue git) → `plan` → `sync`.
`bootstrap` enchaîne capture+validate+plan (+`--adopt`). `drift` compare fabric vs YAML sans rien toucher.

## Dispositif de sûreté (résumé — analyse complète : [tools/ANALYSE_SURETE_2026-07-06.md](tools/ANALYSE_SURETE_2026-07-06.md))

Le scénario redouté — *« un usager ajoute un objet au YAML, on sync, et un mot de passe est
écrasé sur la fabric »* — est bloqué par **quatre couches indépendantes, toutes fail-closed** :

1. **Capture sans secrets** : aucun secret n'est jamais lu ni écrit ; 3 placeholders documentés
   uniquement là où le module exige la variable (pwd utilisateur, authKey OSPF, PSK MACsec).
2. **Câblage null** : tous les autres secrets sont omis du POST (`null`) → l'APIC conserve la
   valeur existante, même au CREATE.
3. **`ignore_changes`** : les modules Cisco retirent les secrets du diff → un UPDATE ne renvoie
   jamais un secret.
4. **Garde CREATE (`SECRET_CLASSES`, 17 classes)** : tout CREATE visant un objet à secret qui
   existe déjà sur la fabric est **refusé** par `sync` et `adopt` → adoption par import obligatoire.

S'y ajoutent : garde **anti-destroy** (tout destroy/replace bloque, comptage via plan JSON),
capture **fail-closed** (une classe APIC illisible ⇒ la photo n'est pas écrite, jamais de YAML
tronqué), lectures APIC **paginées** (pas de liste tronquée sur grosse fabric), et gardes
elles-mêmes fail-closed (APIC injoignable pendant la vérification ⇒ abort, jamais « supposé absent »).
`--force` désactive toutes les protections : réservé aux opérations revues.

Validé par audit adversarial indépendant (2026-07-06) : vulnérabilités C1/M3/M4 trouvées,
corrigées et testées unitairement le jour même.

## Couverture

**187 modules NaC sur 195** capturés et validés en round-trip golden (objet créé sur fabric →
capture → adopt → `terraform plan` = *No changes*). Détail complet, méthode et pièges APIC :
[tools/MODULE_COVERAGE.md](tools/MODULE_COVERAGE.md) (34 vagues documentées) et
[tools/COVERAGE_GAPS_2026-07-03.md](tools/COVERAGE_GAPS_2026-07-03.md) (audit variable par variable).

**Exclusions volontaires (documentées)** :

| Exclusion | Raison |
|---|---|
| `aci_mcp`, `aci_smart_licensing` | secret requis (clé MCP, token CSSM) — désactivés via `data/modules.nac.yaml` |
| `aci_node_registration` | sécurité : risque de ré-enregistrement/perte d'un switch — activable explicitement |
| `pod-setup` (TEP pool), tenant `infra`/`mgmt`/`common` | fondations fabric, `managed: false` |
| Multi-device (service graph, device selection), VMM absent du lab | warning émis à la capture, complétion manuelle |
| Classes `vxlan*` | non résolues sur APIC 6.0(7e) |

**À signaler à Cisco (bugs upstream identifiés)** : condition `console_realm`/`default_realm`
inversée dans `terraform-aci-aaa` (accès console LDAP cassé au sync — contourné par nac.py) ;
`ignore_changes` manquant sur `snmpTrapDest.secName` ; `cert=""` posté au create par le module
keyring (bloqué par notre garde).

## Environnement de validation

Développé et validé contre un simulateur APIC **6.0(7e)** : fabric de test 7 tenants
(L3Outs OSPF/BGP, floating SVI, vPC, contrats/PBR, HSRP, MACsec, SPAN, QoS…), 579 ressources
Terraform gérées, plan final *No changes*. Versions épinglées (Terraform 1.15.7, nac-aci 2.0.0).

## Références

- NaC ACI — First Steps : https://netascode.cisco.com/docs/start/aci/first_steps/
- Module Terraform : https://github.com/netascode/terraform-aci-nac-aci
- Provider ACI : https://github.com/CiscoDevNet/terraform-provider-aci
- Exemple officiel : https://github.com/netascode/nac-aci-comprehensive-example
