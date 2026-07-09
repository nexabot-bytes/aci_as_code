# Analyse de sûreté — nac.py : aucun chemin destructif capture → YAML → sync

> Date : 2026-07-06 · Méthode : audit adversarial indépendant (agent) + inventaire systématique croisé, correctifs appliqués et testés unitairement.
> Question du client : « on capture la fabric, un usager ajoute quelque chose au YAML, on sync — peut-on créer une panne, p. ex. des mots de passe écrasés ? »

## VERDICT : SÛR (après correctifs C1/M3/M4 de cette date)

Le scénario redouté est bloqué par **quatre couches indépendantes**, désormais toutes **fail-closed** :

## 1. Le dispositif secrets (4 couches)

| Couche | Mécanisme | Preuve |
|---|---|---|
| 1. Capture | Aucun secret réel n'est jamais lu ni écrit dans le YAML. 3 placeholders seulement, quand le câblage exige la variable : `aaaUser.pwd`, `ospfIfP.authKey` (si auth active), `macsecKeyPol.preSharedKey` | grep `PLACEHOLDER` nac.py |
| 2. Câblage null | Tous les autres secrets sont passés `try(..., null)` → attribut **omis du POST** → l'APIC conserve la valeur existante (vérifié : bgp `password` aux 10 sites du câblage, bfd multihop `key`, radius/tacacs/ldap `key`, ntp, pim, remote-location…) | aci_tenants.tf:1131 et al. |
| 3. ignore_changes | Chaque module à secret retire l'attribut secret du diff → un UPDATE post-adoption ne renvoie jamais le secret (vérifié module par module : user, radius, tacacs, ldap, keyring, remote-location, snmp users, macsec, ospf, bgp peers, bfdMh, pim, hsrp, ntp, config-passphrase) | audit F8 |
| 4. Garde CREATE | `SECRET_CLASSES` (17 classes) : tout CREATE du plan visant une classe à secret dont le DN **existe déjà** sur la fabric est refusé par `sync` ET `adopt` → l'adoption (import, zéro POST) est le seul chemin pour ces objets | nac.py `_secret_overwrite_check` |

**Scénario usager** : il ajoute au YAML un user/radius/keychain/hsrp/peer dont le nom existe déjà sur la fabric → le plan est un CREATE → couche 4 le bloque (classes à placeholder) ou couche 2 rend le POST inoffensif (secrets null/omis). Un usager qui écrit *explicitement* un `password:` dans le YAML exprime une intention — et `bgpPeerP` est quand même gardé en défense en profondeur.

## 2. Correctifs issus de l'audit adversarial (2026-07-06)

| ID | Vulnérabilité trouvée | Correctif appliqué | Test |
|---|---|---|---|
| **C1 (critique)** | Le garde était **fail-open** : si l'APIC répondait mal (timeout 30s, 403 RBAC, 503) pendant la vérification d'existence, la classe était traitée comme vide → l'apply passait → placeholder POSTé sur le vrai secret (panne MACsec/OSPF/comptes). Même trou dans la vérification d'existence d'`adopt`. | **Fail-closed partout** : toute erreur de lecture (login, classe, plan) → abort explicite. | unit-test : classe illisible → `None` (bloquant) ✅ ; login KO → bloquant ✅ ; adopt → abort ✅ |
| **C1-bis** | `get_class` non paginé : une réponse tronquée sur une grosse fabric rendrait un DN existant invisible au garde | Pagination `order-by dn` + `page-size` ; une erreur en cours de pagination **lève** (jamais de liste partielle) ; fallback requête simple uniquement si `order-by` non supporté (page 0) | unit-test : échec page 1 → exception ✅ ; capture complète du sim paginée ✅ |
| **M3 (moyen)** | Capture **fail-silent** : une classe illisible pendant `capture` → YAML tronqué → au sync, les singletons repartent aux **défauts** (ex. `vzAny.prefGrMemb` → disabled = perte des contrats vzAny de tout le VRF) | `try_class` : HTTP 400 (classe non résolue sur cette version) = bénin ; toute autre erreur est enregistrée → `capture` **refuse d'écrire** une photo tronquée | unit-test : 400 bénin ✅, 403 enregistré ✅ ; capture réelle OK ✅ |
| **M4 (moyen)** | Gardes destroy/add de `sync` basées sur un parse regex du stdout terraform | Comptage via `terraform show -json` du plan (source unique, réutilisée par le garde secret) ; un replace (`delete`+`create`) compte dans les deux gardes | plan réel : 579 ressources, 0 changement, garde `[]` ✅ |
| **M2 (moyen, upstream)** | Bug **module Cisco** `terraform-aci-aaa/main.tf:24` : le providerGroup **console** teste `default_realm == "ldap"` au lieu de `console_realm` → un sync d'une fabric en console-LDAP effacerait le provider group (console cassée) | nac.py refuse de capturer `console_realm=ldap` (warning explicite, gestion manuelle) ; **à signaler à Cisco au road test** | code + warning |
| F6 | `bgpPeerP` hors SECRET_CLASSES (acceptable car password toujours null/omis) | Ajouté en défense en profondeur | — |

## 3. Le chemin destroy

- `sync` : abort si le plan contient le moindre destroy (comptage JSON) sauf `--force`. Un **rename** YAML = replace = compte comme destroy → bloqué.
- `adopt` : même garde destroy avant son apply, + garde secret sur les CREATE résiduels, + `imports_adopt.tf` nettoyé en `finally` (un import partiel ne modifie rien : import = lecture seule).
- Suppression volontaire d'une ligne YAML : bloquée par la garde ; l'usager doit utiliser `--force` en connaissance de cause.

## 4. Limites résiduelles assumées (documentées)

1. **`--force` désactive TOUTES les protections** (destroy + secrets). C'est le contrat de l'option ; ne jamais l'utiliser en production sans revue du plan.
2. **Workflow requis : `capture → adopt → sync`**. Un sync sans re-capture après des changements GUI réécrit les attributs gérés à la valeur du YAML — c'est la sémantique voulue de NaC (le YAML est la source de vérité), pas une panne. Les secrets restent intouchés (couches 2-4).
3. **Objets non gérés** (mode multi-device, bgpExtP sans peers, tenant infra) : jamais touchés par Terraform (aucune ressource ne les déclare), signalés par warnings à la capture.
4. **snmpTrapDest.secName** : pas d'`ignore_changes` upstream — la communauté vient toujours du YAML de l'usager (jamais d'un placeholder), un update la réécrit à la valeur YAML. À signaler à Cisco (amélioration).

## 5. Ce que le road test Cisco doit savoir

- Signaler upstream : bug console_realm/default_realm (M2), absence d'ignore_changes sur snmpTrapDest.secName, `cert=""` posté au create par le module keyring (bloqué par notre garde).
- Le garde suppose un compte APIC avec droits de LECTURE sur les 17 classes de SECRET_CLASSES : c'est maintenant vérifié fail-closed (un compte à droits partiels bloque le sync au lieu de le laisser passer aveugle).
