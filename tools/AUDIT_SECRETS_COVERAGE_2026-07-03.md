# Audit nac.py — couverture des variables & sûreté anti-écrasement de secrets

> Date : 2026-07-03 · Périmètre : `tools/nac.py` vs les 195 modules `.terraform/modules/aci/modules/terraform-aci-*`
> Méthode : mesure outil (`test_nac.py coverage`) + vérification code (nac.py, main.tf/variables.tf de chaque module à secret, câblage parent nac-aci) + échantillonnage variable-par-variable sur 5 gros modules.

---

## PARTIE 1 — Couverture des variables (compliance Network-as-Code)

### Verdict chiffré : 187/195 modules couverts

- L'outil de mesure affiche 174/195, mais **13 modules sont des faux négatifs** (captures dédiées que le bookkeeping ne compte pas — class_name `None` ou conditionnel) : bfd-policy (`capture_bfd_policies` nac.py:3319), ldap (nac.py:3016), macsec-parameters-policy (nac.py:2745), monitoring-policy (nac.py:3256), vspan-session (nac.py:2370), redirect-backup-policy (nac.py:1560), service-epg-policy (nac.py:1590), device-selection-policy (nac.py:1708), track-list/track-member (nac.py:1334/1312), access-leaf-interface-policy-group (nac.py:494), access-spine-interface-selector (nac.py:3477), switch-configuration (nac.py:1977-2021).
- **4 exclusions volontaires et documentées** : mcp + smart-licensing (secret requis, `DISABLE_MODULES`), pod-setup (TEP pool), node-registration (sécurité ré-enregistrement, réactivable via `data/modules.nac.yaml`).
- **4 vrais trous non volontaires** :

| Module | Classe | Vars | Raison | Gravité brownfield |
|---|---|---|---|---|
| vmware-vmm-domain | vmmDomP | 17 | PHASE2, pas de capture dédiée (VMM absent du sim) | **HAUTE** si VMM utilisé |
| nutanix-vmm-domain | vmmDomP | 9 | idem | Moyenne |
| imported-l4l7-device | vnsLDevIf | 4 | capture L4L7 limitée single-device physique | Moyenne |
| rbac-node-rule | aaaRbacNodeRule | 2 | pas fait | Faible |

### Pertes réelles dans des modules marqués « couverts » (écarts vs MODULE_COVERAGE.md)

Les plus graves d'abord :

1. **endpoint-group — `static_ports` / `bulk_static_ports` (fvRsPathAtt) : AUCUNE capture** (0 hit dans nac.py). Aussi manquants : static_leafs, static_endpoints, static_aaeps, subnets EPG (fvSubnet lu seulement sous BD), tags (tagInst), contract_imported_consumers/intra_epgs/masters, custom_qos/trust_control/DPP refs ; `vmware_vmm_domains` réduit aux noms (immediacy/u-seg perdus). **La perte brownfield la plus grave de l'audit** : les bindings statiques d'une fabric réelle ne sont pas reflétés au YAML.
2. **l3out — bloc protocole niveau L3Out absent** : `ospfExtP` (0 hit → `ospf`, `ospf_area`, cost, type, ctrl), `bgp`, `eigrp`, `l3_multicast_ipv4` (pimExtP), interleak/dampening/redistribution route-maps, multipod, sr_mpls. MODULE_COVERAGE.md dit « ospf/bgp couverts ailleurs » — vrai pour les *interface profiles* (ospfIfP), **faux au niveau l3extOut**. Un L3Out OSPF re-poussé perdrait son activation OSPF. De plus, les route-maps scoped L3Out sont rangées au mauvais scope (dédup plus-court-DN, nac.py:541-560).
3. **bridge-domain** : 9 relations enfants jamais capturées (dhcp_labels, netflow_monitor_policies, igmp_interface/snooping, nd_interface, endpoint_retention, legacy_mode_vlan, pim filters, nd_prefix_policy des subnets).
4. **contract** : filtres capturés par nom seul (nac.py:943-944) → `action`/`log`/`no_stats` par filtre perdus ; service_graph (vzRsSubjGraphAtt) et vzInTerm/vzOutTerm non capturés.
5. **interface-configuration (nouveau paradigme)** : `pcMember` (port_channel_member_policy) non capturé et `policy_group_type` non émis (préfixe accbundle jeté, nac.py:2004-2007) → un port PC/VPC serait ré-émis type « access ».
6. **maintenance-group** : `target_version` (maintMaintP.version) non capturé (capture_update_groups ne lit que firmwareFwGrp+scheduler, nac.py:3347-3364).
7. Mineurs : banner (apic_gui_banner_message/url), control-plane-mtu (apic_mtu_apply), port-tracking (include_apic).

### Attributs complexes : 20/27 modules flagués sont en fait couverts par enrichissement dédié

Vérifié ligne par ligne (remote-location, radius/tacacs, endpoint-mac-tag, link-level autoNeg, ptp, mcastARPDrop, hsrp ctrl, interface-type direc, psu adminRdnM, storm-control, syslog rfc5424-ts, pfc 3-états, port-channel ctrl, netflow match, redirect srcMacRewrite, l4l7 activeActive, interface-config assocGrp…). `endpoint-loop-protection.action` est un faux positif (géré génériquement). `sr-mpls localId` est une constante (rien à capturer).

### Échantillonnage 5 gros modules

- **ospf-interface-policy** : ✅ 100 % des 14 variables dérivables.
- **contract / bridge-domain / endpoint-group / l3out** : voir pertes ci-dessus.

---

## PARTIE 2 — Sûreté anti-écrasement des secrets

### Mécanique validée

- Tous les sous-modules utilisent `aci_rest_managed` (935 occurrences ; les 2 `aci_rest` sont mgmtInB/mgmtOoB, sans secret) → le garde-fou `_secret_overwrite_check` (nac.py:3827), qui lit `after.class_name`, n'est jamais aveugle pour cause de ressource native.
- Sémantique provider : attribut `null` dans `content{}` = **omis du POST** (l'APIC conserve la valeur) ; `""` = **envoyé** (écrase). C'est le critère discriminant.
- `ignore_changes` ne protège **qu'après** entrée dans le state → le danger est le CREATE par-dessus un objet existant. C'est exactement ce que bloque `SECRET_CLASSES` + `_secret_overwrite_check` dans `sync`.

### Modules SÛRS (vérifiés un par un)

| Module | Secret | Protection |
|---|---|---|
| user | pwd placeholder `Placeholder123!` | ignore_changes + classe gardée (aaaUser) |
| radius / tacacs / ldap | key, monitoring_password | jamais capturés + `try(...,null)` → omis du POST + ignore_changes + classes gardées |
| remote-location | password, clés ssh | jamais capturés, wiring `""`→null dans le module, ignore_changes, classe gardée |
| keyring | key/cert | jamais capturés, ignore_changes ; cert `""` au create bloqué par la garde |
| ospf auth (l3out-interface-profile) | authKey placeholder `NacKey12` | ignore_changes + ospfIfP gardée |
| bgp peers / bfd multihop / pim / ntp keys / evpn peers | password/key | jamais capturés + `null` → omis du POST + ignore_changes |
| mcp / smart-licensing | key / token | modules désactivés (`DISABLE_MODULES`) + classes gardées |
| snmp users (snmpUserP) | authKey/privKey | jamais capturés (nac.py:2770-2774) ; communautés = round-trip exact par `name` (pas d'écrasement possible) |
| ca-certificate | certChain | PUBLIC, round-trip complet voulu |

### ⚠️ RISQUES CONFIRMÉS

1. **macsecKeyPol (PSK MACsec) — PRIORITAIRE.** La capture émet `pre_shared_key: "AB12"×16` pour CHAQUE clé existante (nac.py:1880, 1928-1944) ; le module POSTe `preSharedKey` inconditionnellement sur un DN déterministe `…/keyp-<key_name>`. Le parent `macsecKeyChainPol` est gardé mais **pas l'enfant `macsecKeyPol`**. Scénario : keychain déjà adopté → nouvelle clé créée en GUI → re-capture → le plan ne contient qu'un CREATE `macsecKeyPol` → la garde ne matche pas → **le vrai PSK est remplacé par le placeholder** (risque de perte de liens fabric).
2. **hsrpGroupPol (clé HSRP MD5).** Câblage : `auth_key = try(policy.key, "")` (aci_tenants.tf:3117) → `""` POSTé au create (pas null). La capture plate capture les politiques HSRP (sans la clé) et `hsrpGroupPol` n'est **pas** dans SECRET_CLASSES → un `sync` sans `adopt` sur une fabric avec HSRP MD5 **vide la clé** (auth_type md5 conservé → adjacences cassées).
3. **pkiExportEncryptionKey (config-passphrase).** Singleton `uni/exportcryptkey` qui existe toujours sur une fabric configurée. Jamais capturé (sûr côté capture), mais si l'utilisateur ajoute `config_passphrase` au YAML sans `adopt`, le CREATE remplace la passphrase AES réelle sans garde.
4. **snmpTrapDest.secName sans ignore_changes** (module upstream) : la garde ne couvre que les CREATE ; après adopt, une divergence YAML/fabric serait réécrite en UPDATE. Non déclenché par la capture (destinations omises) — fragile en authoring manuel.
5. **Robustesse du garde** : (a) `hits is None` (échec du plan interne de `_secret_overwrite_check`) est traité comme « pas de risque » (nac.py:3871) ; (b) `--force` bypasse garde destroy ET garde secret ; (c) l'apply final d'`adopt` (nac.py:4074) peut contenir des CREATE résiduels (objets « skipped » : classe illisible à la vérif d'existence, DN avec `:`) et ce chemin n'appelle **pas** `_secret_overwrite_check`.

### RECOMMANDATIONS

1. **SECRET_CLASSES (nac.py:3822)** : ajouter `macsecKeyPol` (risque 1), `hsrpGroupPol` (risque 2), `pkiExportEncryptionKey` (risque 3) ; défensivement `snmpUserP`, `vmmUsrAccP`, `fvPeeringP`, `datetimeNtpAuthKey` (coût nul, couvre l'authoring manuel).
2. `cmd_sync` : traiter `hits is None` comme bloquant ; appeler aussi `_secret_overwrite_check` avant l'apply d'`adopt`.
3. Ne PAS patcher `.terraform/modules` localement (régénéré par `terraform init`) — la garde côté nac.py est la bonne réponse ; signaler upstream (netascode) l'absence d'`ignore_changes` sur `snmpTrapDest.secName` et le `cert=""` du keyring.
4. Documenter : workflow sûr = strictement `capture → adopt → sync` ; `--force` désactive TOUTES les protections secrets.
5. Couverture (compliance brownfield), par priorité : static_ports EPG (fvRsPathAtt), bloc ospfExtP/bgpExtP/eigrpExtP niveau L3Out (+scope des route-maps), relations enfants BD, options de filtres de contrats, pcMember/policy_group_type (interface-configuration), target_version (maintenance-group).
