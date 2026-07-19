#!/usr/bin/env python3
"""
nac.py — Brownfield Network-as-Code management tool for Cisco ACI.

Captures an EXISTING ACI fabric as NaC YAML (netascode/nac-aci module),
synchronizes it with Terraform, and validates everything — without ever
overwriting the fabric.

The APIC<->YAML mapping is DERIVED automatically from the `content {}` blocks
of the Terraform sub-modules (versioned source of truth): 100% of attributes,
zero hand-written mapping.

Pure SYNC tool: fabric <-> data/*.nac.yaml <-> Terraform.
Test/dev tooling (audit, coverage, selftest, comparison) lives in
test_nac.py (separate) — nac.py only does its sync job.

Subcommands
-----------
  capture     Read the fabric -> data/*.nac.yaml (READ-ONLY, ALL attributes)
  validate    nac-validate on the data/ directory
  plan        terraform plan (preview, changes nothing)
  sync        terraform apply (destroy guard included)
  adopt       write-free adoption (bulk terraform import)
  bootstrap   capture + validate + plan (+ adoption with --adopt)

Authentication: read from the `provider "aci"` block in main.tf
(overridable with the APIC_URL / APIC_USER / APIC_PWD environment variables).

Usage: python tools/nac.py <subcommand> [options]
"""
from __future__ import annotations
import argparse, datetime, glob, json, logging, os, re, ssl, sys, urllib.request
from collections import defaultdict

# ───────────────────────────────────────────────────────────── chemins & log
ROOT     = os.environ.get("NAC_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")
MAIN_TF  = os.path.join(ROOT, "main.tf")
MODDIR   = os.path.join(ROOT, ".terraform", "modules", "aci")
CHILDDIR = os.path.join(MODDIR, "modules")
SYSTEM_TENANTS = {"infra", "mgmt", "common"}
SECTION_FILES = {
    "access_policies":    "aci_access_policies.tf",
    "fabric_policies":    "aci_fabric_policies.tf",
    "node_policies":      "aci_node_policies.tf",
    "pod_policies":       "aci_pod_policies.tf",
}
SECTION_OUT = {  # section -> fichier data
    "access_policies": "access_policies.nac.yaml", "fabric_policies": "fabric_policies.nac.yaml",
    "node_policies": "node_policies.nac.yaml", "pod_policies": "pod_policies.nac.yaml",
    "interface_policies": "interface_policies.nac.yaml",
}
# Modules a relation/secret : objets incomplets ou non capturables -> exclus de la passe plate
PHASE2_MODULES = {
    "aci_physical_domain", "aci_routed_domain", "aci_l2_domain", "aci_aaep",
    "aci_user", "aci_login_domain", "aci_radius", "aci_tacacs", "aci_ca_certificate",
    "aci_keyring", "aci_psu_policy", "aci_config_export", "aci_remote_location",
    "aci_fabric_scheduler", "aci_node_registration", "aci_inband_node_address",
    "aci_oob_node_address", "aci_rbac_node_rule", "aci_vmware_vmm_domain",
    "aci_nutanix_vmm_domain", "aci_vlan_pool",
    "aci_mcp",             # MCP global : requiert un mot de passe (secret non capturable)
    "aci_smart_licensing", # requiert un Token ID CSSM (secret non capturable)
    "aci_pod_setup",       # TEP pool (fondamental, indexe par 'id' != var) -> non gere
    # SPAN destination groups : classe spanDestGrp AMBIGUE (access uni/infra ET fabric uni/fabric).
    # Le moteur plat dédoublonne par classe et rangerait l'objet dans la mauvaise section ->
    # géré par capture_span_destination_groups (filtré par DN uni/infra). [#37]
    "aci_access_span_destination_group", "aci_fabric_span_destination_group",
    # idem spanSrcGrp ambiguë access/fabric -> capture_span_source_groups (filtre uni/infra). [#40]
    "aci_access_span_source_group", "aci_fabric_span_source_group",
}
# Singletons que le MODULE cree toujours (count sans garde de donnees) mais qui
# exigent un secret : on les DESACTIVE via la cle `modules:` du data model, sinon
# terraform tente de les creer avec des defauts incomplets et echoue.
DISABLE_MODULES = {
    "aci_mcp": False,               # mot de passe MCP requis
    "aci_smart_licensing": False,   # Token ID CSSM requis
    # SECURITE : la (re)declaration de noeuds (fabricNodeIdentP) peut re-enregistrer
    # un switch et le sortir de la fabric. Desactive PAR DEFAUT : les entrees
    # node_policies.nodes[] role leaf/spine ne declenchent alors JAMAIS
    # d'enregistrement (mais alimentent normalement switch_configuration, adresses
    # mgmt, profils...). Pour gerer l'enregistrement volontairement (greenfield),
    # passer aci_node_registration: true dans data/modules.nac.yaml apres capture.
    "aci_node_registration": False,
}

log = logging.getLogger("nac")

def _setup_log(verbose=False):
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(message)s", stream=sys.stderr)

# ───────────────────────────────────────────────────────────── credentials
def load_creds() -> tuple[str, str, str]:
    """URL/user/pwd depuis le provider "aci" de main.tf, surchargeable par l'env."""
    url = user = pwd = None
    if os.path.isfile(MAIN_TF):
        m = re.search(r'provider\s+"aci"\s*\{(.*?)\n\}', open(MAIN_TF).read(), re.S)
        if m:
            blk = m.group(1)
            def g(k):
                mm = re.search(rf'\b{k}\s*=\s*"([^"]*)"', blk)
                return mm.group(1) if mm else None
            url, user, pwd = g("url"), g("username"), g("password")
    url  = os.environ.get("APIC_URL",  url)
    user = os.environ.get("APIC_USER", user)
    pwd  = os.environ.get("APIC_PWD",  pwd)
    if not all((url, user, pwd)):
        sys.exit("ERROR: credentials not found (provider \"aci\" block in main.tf "
                 "or APIC_URL/APIC_USER/APIC_PWD environment variables).")
    return url, user, pwd

# ───────────────────────────────────────────────────────────── client APIC
class Apic:
    """Client REST APIC minimal, en lecture seule par defaut."""
    def __init__(self, url, user, pwd):
        self.url, self.user, self.pwd = url, user, pwd
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.token = None
        self.read_failures = []       # classes illisibles (hors 400) [audit M3]

    def _do(self, path, data=None, method=None):
        req = urllib.request.Request(
            self.url + path,
            data=json.dumps(data).encode() if data is not None else None,
            method=method or ("POST" if data is not None else "GET"))
        if self.token:
            req.add_header("Cookie", "APIC-cookie=" + self.token)
        with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
            return json.loads(r.read())

    def login(self):
        d = self._do("/api/aaaLogin.json",
                     {"aaaUser": {"attributes": {"name": self.user, "pwd": self.pwd}}})
        a = d["imdata"][0]["aaaLogin"]["attributes"]
        self.token = a["token"]
        return a.get("version", "?")

    def try_class(self, cn):
        """get_class TOLERANT, pour les tables generiques : None si la classe
        n'existe pas sur cette version APIC (HTTP 400 unresolved class = benin).
        Toute AUTRE erreur (timeout/403/503) est enregistree dans read_failures ->
        cmd_capture ABANDONNE au lieu d'ecrire une photo tronquee (qui remettrait
        les defauts au sync). [audit adversarial 2026-07-06 M3]"""
        import urllib.error
        try:
            return self.get_class(cn)
        except urllib.error.HTTPError as e:
            if e.code == 400:
                return None
            self.read_failures.append(f"{cn}: HTTP {e.code}")
            return None
        except Exception as e:
            self.read_failures.append(f"{cn}: {e}")
            return None

    def get_class(self, cn, page_size=40000):
        """Requete par classe PAGINEE (order-by dn) : une grosse fabric peut depasser
        la limite de reponse APIC — une liste tronquee rendrait un DN existant
        invisible au garde anti-ecrasement. [audit adversarial 2026-07-06 C1]"""
        out, page = [], 0
        while True:
            try:
                imdata = self._do(f"/api/class/{cn}.json?order-by={cn}.dn"
                                  f"&page-size={page_size}&page={page}")["imdata"]
            except Exception:
                if page == 0:      # classe sans support order-by -> requete simple
                    imdata = self._do(f"/api/class/{cn}.json")["imdata"]
                    return [list(x.values())[0]["attributes"] for x in imdata]
                raise              # page>0 : ne JAMAIS retourner une liste partielle
            rows = [list(x.values())[0]["attributes"] for x in imdata]
            out.extend(rows)
            if len(rows) < page_size:
                return out
            page += 1

    def count(self, cn):
        return len(self.get_class(cn))

    def post_mo(self, path, body):
        return self._do(path, body, method="POST")

# ───────────────────────────────────────────────── mapping derive des modules
_RE_BOOL = re.compile(r'^(?:var|each\.value)\.([a-z0-9_]+)(?:\s*==\s*true)?\s*\?\s*"([^"]*)"\s*:\s*"([^"]*)"$')
_RE_VAR  = re.compile(r'^(?:var|each\.value)\.([a-z0-9_]+)$')
# nombre avec sentinelle pour 0 : var.x == 0 ? "infinite" : var.x  (endpoint retention, etc.)
_RE_NUM0 = re.compile(r'^(?:var|each\.value)\.([a-z0-9_]+)\s*==\s*0\s*\?\s*"([^"]*)"\s*:\s*(?:var|each\.value)\.\1$')
_RE_FLOAT = re.compile(r'^format\("%\.\d+f",\s*(?:var|each\.value)\.([a-z0-9_]+)\)$')  # rate/burst
_RE_JOIN  = re.compile(r'^join\("[^"]*",\s*(?:var|each\.value)\.([a-z0-9_]+)\)$')      # liste -> csv
_RE_NUMNULL = re.compile(r'^(?:var|each\.value)\.([a-z0-9_]+)\s*!=\s*0\s*\?\s*(?:var|each\.value)\.\1\s*:\s*null$')
_MAP_CACHE: dict = {}

def attr_map(module, label):
    """[(apicAttr, champYAML, kind, extra)] du resource <label> du sous-module."""
    key = (module, label)
    if key in _MAP_CACHE:
        return _MAP_CACHE[key]
    out, path = [], os.path.join(CHILDDIR, module, "main.tf")
    if os.path.isfile(path):
        m = re.search(rf'resource\s+"aci_rest_managed"\s+"{re.escape(label)}"\s*\{{(.*?)\n\}}',
                      open(path).read(), re.S)
        if m:
            cm = re.search(r'content\s*=\s*\{(.*?)\n\s*\}', m.group(1), re.S)
            if cm:
                for line in cm.group(1).splitlines():
                    mm = re.match(r'\s*"?([A-Za-z0-9_]+)"?\s*=\s*(.+?)\s*$', line)
                    if not mm:
                        continue
                    apic, expr = mm.group(1), mm.group(2).strip()
                    # champ "ctrl" = join(",", concat(var.X==true?["flag"]:[], ...)) -> N bools
                    if expr.startswith("join(") and "concat(" in expr:
                        pairs = re.findall(
                            r'(?:var|each\.value)\.([a-z0-9_]+)(?:\s*==\s*true)?\s*\?\s*\["([^"]+)"\]', expr)
                        if pairs:
                            for var, flag in pairs:
                                out.append((apic, var, "flag", flag))
                            continue
                    b, v, n0 = _RE_BOOL.match(expr), _RE_VAR.match(expr), _RE_NUM0.match(expr)
                    fl, jn, nn = _RE_FLOAT.match(expr), _RE_JOIN.match(expr), _RE_NUMNULL.match(expr)
                    if b:    out.append((apic, b.group(1), "bool", (b.group(2), b.group(3))))
                    elif n0: out.append((apic, n0.group(1), "num0", n0.group(2)))
                    elif fl: out.append((apic, fl.group(1), "float", None))
                    elif jn: out.append((apic, jn.group(1), "list", None))
                    elif nn: out.append((apic, nn.group(1), "direct", None))
                    elif v:  out.append((apic, v.group(1), "direct", None))
    _MAP_CACHE[key] = out
    return out

def _num(v):
    return int(v) if isinstance(v, str) and re.fullmatch(r"-?\d+", v) else v

def reverse(amap, mo):
    """Construit l'objet YAML complet depuis le MO + mapping. Ignore null/vide."""
    o = {}
    for apic, field, kind, extra in amap:
        if apic not in mo:
            continue
        raw = mo[apic]
        if kind == "bool":
            o[field] = (raw == extra[0])
        elif kind == "num0":                       # sentinelle ("infinite"/"none") -> 0
            o[field] = 0 if raw == extra else _num(raw)
        elif kind == "float":                       # "100.000000" -> 100 ou 100.5
            try:
                f = float(raw); o[field] = int(f) if f == int(f) else f
            except (ValueError, TypeError):
                pass
        elif kind == "list":                        # "a,b,c" -> [a,b,c]
            o[field] = [s for s in raw.split(",") if s]
        elif kind == "flag":                        # bool = flag present dans ctrl "f1,f2"
            o[field] = extra in str(raw).split(",")
        elif raw not in ("", None):
            o[field] = _num(raw)
    return o

def obj(module, label, mo):
    o = reverse(attr_map(module, label), mo)
    if mo.get("name") and "name" not in o:        # certains modules n'echoent pas name
        o = {"name": mo["name"], **o}
    return o

def child_primary(module):
    """(label, class_name) du resource primaire (sans for_each/count) d'un sous-module."""
    path = os.path.join(CHILDDIR, module, "main.tf")
    if not os.path.isfile(path):
        return None
    txt = open(path).read()
    for m in re.finditer(r'resource\s+"aci_rest_managed"\s+"([^"]+)"\s*\{(.*?)\n\}', txt, re.S):
        label, body = m.group(1), m.group(2)
        if "for_each" in body.split("content")[0] or "count" in body.split("content")[0]:
            continue
        c = re.search(r'class_name\s*=\s*"([^"]+)"', body)
        if c:
            return label, c.group(1)
    return None

# ─────────────────────────────────── moteur de classes PLATES (derive des sections)
def _flat_table():
    """[(section, class_name, module, label, yaml_path)] des list-classes simples."""
    table, seen = [], {}
    for section, fname in SECTION_FILES.items():
        txt = open(os.path.join(MODDIR, fname)).read()
        for m in re.finditer(r'module\s+"([^"]+)"\s*\{(.*?)\n\}', txt, re.S):
            name, body = m.group(1), m.group(2)
            if name in PHASE2_MODULES:
                continue
            src = re.search(r'source\s*=\s*"\./modules/([^"]+)"', body)
            fe = re.search(r'for_each\s*=\s*\{\s*for\s+\w+\s+in\s+try\(\s*local\.([\w.]+)\s*,\s*\[\]\)', body)
            if not (src and fe):
                continue
            path = fe.group(1)
            if not path.startswith(section):
                continue
            prim = child_primary(src.group(1))
            if not prim:
                continue
            label, cls = prim
            if cls in seen:                       # une classe -> un seul chemin (sinon ambigu)
                continue
            seen[cls] = path
            table.append((section, cls, src.group(1), label, path))
    return table

def _place(tree, path, item):
    node = tree
    for p in path.split(".")[:-1]:
        node = node.setdefault(p, {})
    node.setdefault(path.split(".")[-1], []).append(item)

def _set_path(tree, path, field, value):
    node = tree
    for p in (path.split(".") if path else []):
        node = node.setdefault(p, {})
    node[field] = value

# ─────────────────────────────────── moteur de SINGLETONS (count-based, dict)
def _singleton_table():
    """[(section, class, module, label, {var:(path,field)})] des modules count-based."""
    out = []
    for section, fname in SECTION_FILES.items():
        txt = open(os.path.join(MODDIR, fname)).read()
        for m in re.finditer(r'module\s+"([^"]+)"\s*\{(.*?)\n\}', txt, re.S):
            name, body = m.group(1), m.group(2)
            if name in PHASE2_MODULES or "for_each" in body or "\n  count" not in body:
                continue
            src = re.search(r'source\s*=\s*"\./modules/([^"]+)"', body)
            if not src:
                continue
            var2pf = {}
            for vm in re.finditer(r'^\s*([A-Za-z0-9_]+)\s*=\s*try\(\s*local\.([\w.]+)', body, re.M):
                full = vm.group(2)
                if "." not in full:
                    continue
                path, field = full.rsplit(".", 1)
                var2pf[vm.group(1)] = (path, field)
            prim = child_primary(src.group(1))
            if var2pf and prim:
                out.append((section, prim[1], src.group(1), prim[0], var2pf))
    return out

def capture_singletons(apic: Apic):
    """Capture les singletons (global_settings, coop, isis...) a leurs vraies valeurs."""
    trees = defaultdict(dict)
    for section, cls, module, label, var2pf in _singleton_table():
        mos = apic.try_class(cls)
        if mos is None:
            continue
        if cls == "bgpAsP":
            # classe AMBIGUE : bgpAsP existe aussi sous les bgp peers tenant/l3out
            # -> ne garder que le singleton fabric (uni/fabric/bgpInstP-default/as)
            mos = [m for m in mos if m.get("dn", "").startswith("uni/fabric/bgpInstP")]
        if not mos:
            continue
        mo = mos[0]
        for apic_attr, var, kind, extra in attr_map(module, label):
            if var not in var2pf or apic_attr not in mo:
                continue
            path, field = var2pf[var]
            sub = path.split(".", 1)[1] if "." in path else ""      # "" = directement sous la section
            raw = mo[apic_attr]
            if kind == "bool":
                _set_path(trees[section], sub, field, raw == extra[0])
            elif raw not in ("", None):
                _set_path(trees[section], sub, field, _num(raw))
        if cls == "dbgOngoingAcMode" and mo.get("adminSt"):
            # admin_state cable SANS try() dans le parent -> absent de var2pf ; or
            # count = admin_state != null : sans ce champ le module n'est jamais
            # instancie (singleton non gere). [methode C]
            _set_path(trees[section], "atomic_counter", "admin_state",
                      mo["adminSt"] == "enabled")
    return trees

def capture_flat(apic: Apic):
    """Capture toutes les list-classes plates (full attrs) par section."""
    trees = defaultdict(dict)
    for section, cls, module, label, path in _flat_table():
        mos = apic.try_class(cls)
        if mos is None:
            continue
        seen = set()
        for mo in mos:
            name = mo.get("name", "")
            if "/tn-" in mo.get("dn", ""):                       # tenant-scoped -> section tenants
                continue
            if name == "default" or name.startswith(("system-", "__")):
                continue
            if name in seen:
                continue
            seen.add(name)
            _place(trees[section], path.split(".", 1)[1], obj(module, label, mo))
    return trees

# ───────────────────────────────────────────────────────── helpers DN
def _seg(dn, key):
    m = re.search(rf"/{key}-([^/\[]+)", dn)
    return m.group(1) if m else None

def _parent(dn, depth=1):
    """Remonte de `depth` niveaux en ignorant les '/' dans les [crochets]."""
    for _ in range(depth):
        lvl = 0
        for i in range(len(dn) - 1, -1, -1):
            c = dn[i]
            if c == "]": lvl += 1
            elif c == "[": lvl -= 1
            elif c == "/" and lvl == 0:
                dn = dn[:i]; break
    return dn

def _ref(tdn):
    for pat in (r"uni/phys-([^/\]]+)", r"uni/l3dom-([^/\]]+)",
                r"uni/infra/vlanns-\[([^\]]+)\]", r"/ctx-([^/\]]+)", r"/BD-([^/\]]+)"):
        m = re.search(pat, tdn)
        if m:
            return m.group(1)
    return tdn

def _by_parent(rows, depth=1):
    d = defaultdict(list)
    for a in rows:
        d[_parent(a["dn"], depth)].append(a)
    return d

def _set(o, key, children):
    if children:
        o[key] = children

# ═══════════════════════════════════════════════════════ CAPTURE : access
def capture_access(apic: Apic, warnings: list):
    ap = {}
    # vlan pools (+ ranges)
    encaps = _by_parent(apic.get_class("fvnsEncapBlk"))
    pools = []
    for p in apic.get_class("fvnsVlanInstP"):
        o = obj("terraform-aci-vlan-pool", "fvnsVlanInstP", p)
        ranges = []
        for blk in encaps.get(p["dn"], []):
            r = obj("terraform-aci-vlan-pool", "fvnsEncapBlk", blk)
            r.pop("name", None)
            r["from"] = _num(blk["from"].replace("vlan-", ""))
            r["to"]   = _num(blk["to"].replace("vlan-", ""))
            ranges.append(r)
        _set(o, "ranges", ranges)
        pools.append(o)
    _set(ap, "vlan_pools", pools)
    # domains -> vlan_pool
    vlanns = {_parent(a["dn"]): _ref(a["tDn"]) for a in apic.get_class("infraRsVlanNs")}
    secdom_by = _by_parent(apic.get_class("aaaDomainRef"))    # RBAC [audit 2026-07-03]
    for cn, mod, key in (("physDomP", "terraform-aci-physical-domain", "physical_domains"),
                         ("l3extDomP", "terraform-aci-routed-domain", "routed_domains")):
        doms = []
        for d in apic.get_class(cn):
            if d.get("uid") == "0" and d["dn"] not in vlanns:
                continue                         # domaine SYSTEME sans pool (ex 'phys')
            o = obj(mod, cn, d)
            if d["dn"] in vlanns:                # vlan_pool OPTIONNEL (bug corrige :
                o["vlan_pool"] = vlanns[d["dn"]] # les domaines sans pool etaient perdus)
            _set(o, "security_domains",
                 sorted(x["name"] for x in secdom_by.get(d["dn"], [])))
            doms.append(o)
        _set(ap, key, doms)
    # aaeps -> domains + bindings EPG (infraRsFuncToEpg sous gen-default)
    dom_by_aaep = _by_parent(apic.get_class("infraRsDomP"))
    epg_by_aaep = defaultdict(list)
    for rs in apic.get_class("infraRsFuncToEpg"):
        if "/gen-default/" not in rs["dn"]:                       # ignore le binding infra_vlan
            continue
        t = rs["tDn"]                                             # uni/tn-X/ap-Y/epg-Z
        b = {"tenant": _seg(t, "tn"), "application_profile": _seg(t, "ap"),
             "endpoint_group": _seg(t, "epg")}
        prim = rs.get("primaryEncap", "unknown")
        enc = rs.get("encap", "unknown")
        if prim != "unknown":                     # micro-seg : encap=secondary, primaryEncap=primary
            b["primary_vlan"] = _num(prim.replace("vlan-", ""))
            if enc != "unknown":
                b["secondary_vlan"] = _num(enc.replace("vlan-", ""))
        elif enc != "unknown":
            b["vlan"] = _num(enc.replace("vlan-", ""))
        if rs.get("mode") and rs["mode"] != "regular":            # defaut regular
            b["mode"] = rs["mode"]
        if rs.get("instrImedcy") and rs["instrImedcy"] != "lazy": # defaut lazy
            b["deployment_immediacy"] = rs["instrImedcy"]
        epg_by_aaep[_parent(rs["dn"], 2)].append(b)               # parent: .../gen-default/rs.. -> attentp-X
    # infra_vlan : encap du binding provacc -> epg-default [audit 2026-07-04]
    infravlan_by_aaep = {}
    for rs in apic.get_class("infraRsFuncToEpg"):
        if "/provacc/" in rs["dn"] and rs.get("encap", "").startswith("vlan-"):
            infravlan_by_aaep[_parent(rs["dn"], 2)] = int(rs["encap"].replace("vlan-", ""))
    aaeps = []
    for a in apic.get_class("infraAttEntityP"):
        if a["name"] == "default":
            continue
        o = obj("terraform-aci-aaep", "infraAttEntityP", a)
        phys, rout, vmw, nut = [], [], [], []
        for rs in dom_by_aaep.get(a["dn"], []):
            t = rs["tDn"]
            if "/phys-" in t: phys.append(_ref(t))
            elif "/l3dom-" in t: rout.append(_ref(t))
            elif "/vmmp-VMware/dom-" in t: vmw.append(t.rsplit("/dom-", 1)[1])
            elif "/vmmp-Nutanix/dom-" in t: nut.append(t.rsplit("/dom-", 1)[1])
        _set(o, "physical_domains", phys); _set(o, "routed_domains", rout)
        _set(o, "vmware_vmm_domains", vmw); _set(o, "nutanix_vmm_domains", nut)
        if a["dn"] in infravlan_by_aaep:
            o["infra_vlan"] = infravlan_by_aaep[a["dn"]]
        _set(o, "endpoint_groups", epg_by_aaep.get(a["dn"], []))
        aaeps.append(o)
    _set(ap, "aaeps", aaeps)
    # interface policy groups (leaf access/bundle) + leurs references de policies
    _set(ap, "leaf_interface_policy_groups", _capture_pgs(apic))
    # (les interface_policies plates sont couvertes par capture_flat)
    return ap

# relation-class -> (attribut tn*Name, champ NaC) pour les interface policy groups
PG_RELATIONS = [
    ("infraRsHIfPol", "tnFabricHIfPolName", "link_level_policy"),
    ("infraRsCdpIfPol", "tnCdpIfPolName", "cdp_policy"),
    ("infraRsLldpIfPol", "tnLldpIfPolName", "lldp_policy"),
    ("infraRsStpIfPol", "tnStpIfPolName", "spanning_tree_policy"),
    ("infraRsMcpIfPol", "tnMcpIfPolName", "mcp_policy"),
    ("infraRsL2IfPol", "tnL2IfPolName", "l2_policy"),
    ("infraRsLacpPol", "tnLacpLagPolName", "port_channel_policy"),
    ("infraRsStormctrlIfPol", "tnStormctrlIfPolName", "storm_control_policy"),
    ("infraRsL2PortSecurityPol", "tnL2PortSecurityPolName", "port_security_policy"),
    ("infraRsQosEgressDppIfPol", "tnQosDppPolName", "egress_data_plane_policing_policy"),   # [#88]
    ("infraRsQosIngressDppIfPol", "tnQosDppPolName", "ingress_data_plane_policing_policy"),
    ("infraRsQosPfcIfPol", "tnQosPfcIfPolName", "priority_flow_control_policy"),
]

def _capture_pgs(apic: Apic):
    rels = defaultdict(dict)
    for cls_, attr, field in PG_RELATIONS:
        for r in (apic.try_class(cls_) or []):
            if r.get(attr):
                rels[_parent(r["dn"])][field] = r[attr]
    aaep_rel = {}
    for r in (apic.try_class("infraRsAttEntP") or []):
        if r.get("tDn"):
            aaep_rel[_parent(r["dn"])] = _seg(r["tDn"], "attentp")
    pgs = []
    for cls_, fixed_type in (("infraAccPortGrp", "access"), ("infraAccBndlGrp", None)):
        for pg in apic.get_class(cls_):
            if "/tn-" in pg["dn"] or pg["name"] == "default" or pg["name"].startswith("system-"):
                continue
            o = {"name": pg["name"],
                 "type": fixed_type or ("vpc" if pg.get("lagT") == "node" else "pc")}
            o.update(rels.get(pg["dn"], {}))
            if aaep_rel.get(pg["dn"]):
                o["aaep"] = aaep_rel[pg["dn"]]
            pgs.append(o)
    return pgs

# ─────────────────────────────────── moteur TENANT-POLICIES (flatten derive)
def _tenant_flat_table():
    """[(subpath, class, module, label)] des sous-objets tenant.policies.* (flatten)."""
    txt = open(os.path.join(MODDIR, "aci_tenants.tf")).read()
    local2sub = {}
    for m in re.finditer(r'^  ([a-z_]+)\s*=\s*flatten\(\[(.*?)\n  \]\)', txt, re.S | re.M):
        sm = re.search(r'for\s+\w+\s+in\s+try\(\s*tenant\.([\w.]+),', m.group(2))
        if sm:
            local2sub[m.group(1)] = sm.group(1)
    out, seen = [], set()
    for m in re.finditer(r'module\s+"([^"]+)"\s*\{(.*?)\n\}', txt, re.S):
        name, body = m.group(1), m.group(2)
        if name in PHASE2_MODULES:
            continue
        src = re.search(r'source\s*=\s*"\./modules/([^"]+)"', body)
        fe = re.search(r'for_each\s*=\s*\{\s*for\s+\w+\s+in\s+local\.([\w]+)\s*:', body)
        if not (src and fe):
            continue
        sub = local2sub.get(fe.group(1))
        if not sub or not sub.startswith("policies"):     # generique = uniquement policies.*
            continue
        prim = child_primary(src.group(1))
        if prim and prim[1] not in seen:                  # une classe -> un seul subpath
            seen.add(prim[1]); out.append((sub, prim[1], src.group(1), prim[0]))
    return out

# Cas connus var-module != champ-YAML (curated : un remap générique parse-les-sections
# s'est avéré non fiable -> on liste seulement les cas sûrs et vérifiés).
TENANT_FIELD_REMAP = {
    "igmpIfPol": {"version_": "version"},
}

def _rtctrl_contexts(dn, ctx_by_prof, scope_attr, ctx_subj):
    """contexts (rtctrlCtxP) d'un route map rtctrlProfile -> liste ordonnee. Partage
    entre route maps tenant et route maps scoped L3Out [audit 2026-07-06]."""
    contexts = []
    for c in sorted(ctx_by_prof.get(dn, []), key=lambda x: int(x.get("order", "0") or 0)):
        cx = {"name": c["name"]}
        if c.get("descr"):
            cx["description"] = c["descr"]
        if c.get("action") and c["action"] != "permit":     # defaut permit
            cx["action"] = c["action"]
        if c.get("order") and c["order"] != "0":            # defaut 0
            cx["order"] = int(c["order"])
        sc = scope_attr.get(c["dn"] + "/scp/rsScopeToAttrP")
        if sc and sc.get("tnRtctrlAttrPName"):
            cx["set_rule"] = sc["tnRtctrlAttrPName"]
        mrs = [r["tnRtctrlSubjPName"] for r in ctx_subj.get(c["dn"], [])
               if r.get("tnRtctrlSubjPName")]
        if mrs:
            cx["match_rules"] = mrs
        contexts.append(cx)
    return contexts

def _syslog_src_entry(s, dest):
    """syslogSrc (+ syslogRsDestGroup) -> entree syslog_policies (flags incl audit/
    events/faults/session en diff des defauts, minSev, destination_group). Partage
    entre monitoring access/fabric/tenant [audit 2026-07-06]."""
    e = {"name": s["name"]}
    incl = set((s.get("incl") or "").split(","))
    for flag, dflt in (("audit", True), ("events", True), ("faults", True), ("session", False)):
        present = flag in incl or "all" in incl
        if present != dflt:
            e[flag] = present
    if s.get("minSev") and s["minSev"] != "warnings":    # defaut warnings
        e["minimum_severity"] = s["minSev"]
    if dest and "/slgroup-" in dest.get("tDn", ""):
        e["destination_group"] = dest["tDn"].rsplit("/slgroup-", 1)[1]
    return e

def capture_tenant_policies(apic: Apic, keep):
    """tenant -> {subpath: [objets]} pour toutes les policies tenant.
    Dedup par nom en gardant le DN le plus court (la même classe peut exister à
    plusieurs scopes : ex rtctrlProfile au niveau tenant ET sous un L3Out)."""
    byname = defaultdict(lambda: defaultdict(dict))   # tenant -> sub -> {name: (dn, obj)}
    for sub, cls, module, label in _tenant_flat_table():
        mos = apic.try_class(cls)
        if mos is None:
            continue
        rmap = TENANT_FIELD_REMAP.get(cls, {})
        for mo in mos:
            t = _seg(mo["dn"], "tn")
            if t not in keep:
                continue
            # rtctrlProfile scoped L3Out (uni/tn-X/out-Y/prof-Z) : ne va PAS au niveau
            # tenant (sinon dedup plus-court-DN l'ecrase / le mal-scope) -> capture
            # dediee dans l'objet L3Out [audit 2026-07-06]
            if cls == "rtctrlProfile" and "/out-" in mo["dn"]:
                continue
            o = obj(module, label, mo)
            for lf, yf in rmap.items():
                if lf in o:
                    o[yf] = o.pop(lf)
            key = o.get("name", mo["dn"])
            prev = byname[t][sub].get(key)
            if prev is None or len(mo["dn"]) < len(prev[0]):   # garde le scope le plus haut
                byname[t][sub][key] = (mo["dn"], o)
    # enrichir les route maps (rtctrlProfile) avec leurs contexts (rtctrlCtxP)
    ctx_by_prof = _by_parent(apic.get_class("rtctrlCtxP"))            # contexts par route map DN
    scope_attr = {x["dn"]: x for x in apic.get_class("rtctrlRsScopeToAttrP")}  # set_rule
    ctx_subj = _by_parent(apic.get_class("rtctrlRsCtxPToSubjP"))      # match_rules par ctx DN
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.route_control_route_maps", {}).items():
            contexts = _rtctrl_contexts(dn, ctx_by_prof, scope_attr, ctx_subj)
            if contexts:
                o["contexts"] = contexts
    # enrichir les set_rules (rtctrlAttrP) avec leurs clauses set
    setcomm = {x["dn"]: x for x in apic.get_class("rtctrlSetComm")}
    settag = {x["dn"]: x for x in apic.get_class("rtctrlSetTag")}
    sweight = {x["dn"]: x for x in apic.get_class("rtctrlSetWeight")}
    snh = {x["dn"]: x for x in apic.get_class("rtctrlSetNh")}
    spref = {x["dn"]: x for x in apic.get_class("rtctrlSetPref")}
    smetric = {x["dn"]: x for x in apic.get_class("rtctrlSetRtMetric")}
    smetrict = {x["dn"]: x for x in apic.get_class("rtctrlSetRtMetricType")}
    # clauses avancees [audit 2026-07-04]
    sdamp = {x["dn"]: x for x in apic.get_class("rtctrlSetDamp")}
    saddcomm = _by_parent(apic.get_class("rtctrlSetAddComm"))
    saspath = _by_parent(apic.get_class("rtctrlSetASPath"))
    saspathasn = _by_parent(apic.get_class("rtctrlSetASPathASN"))
    snhunch = {x["dn"] for x in apic.get_class("rtctrlSetNhUnchanged")}
    smpath = {x["dn"] for x in apic.get_class("rtctrlSetRedistMultipath")}
    sptag_rs = {_parent(x["dn"], 2): x for x in apic.get_class("rtctrlRsSetPolicyTagToInstP")}
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.set_rules", {}).items():
            c = setcomm.get(dn + "/scomm")
            if c and c.get("community"):
                o["community"] = c["community"]
                if c.get("setCriteria") and c["setCriteria"] != "append":   # defaut append
                    o["community_mode"] = c["setCriteria"]
            for d, field, key, cast in (
                (settag, "tag", "tag", int), (sweight, "weight", "weight", int),
                (snh, "addr", "next_hop", str), (spref, "localPref", "preference", int),
                (smetric, "metric", "metric", int)):
                suffix = {"tag": "/srttag", "weight": "/sweight", "addr": "/nh",
                          "localPref": "/spref", "metric": "/smetric"}[field]
                mo = d.get(dn + suffix)
                if mo and mo.get(field) not in (None, ""):
                    o[key] = cast(mo[field])
            mt = smetrict.get(dn + "/smetrict")
            if mt and mt.get("metricType"):
                o["metric_type"] = mt["metricType"]
            # dampening (bloc, defauts NaC omis)
            dm = sdamp.get(dn + "/sdamp")
            if dm:
                db = {}
                for attr, key, dflt in (("halfLife", "half_life", "15"),
                                        ("maxSuppressTime", "max_suppress_time", "60"),
                                        ("reuse", "reuse_limit", "750"),
                                        ("suppress", "suppress_limit", "2000")):
                    if dm.get(attr) not in (None, "", dflt):
                        db[key] = int(dm[attr])
                o["dampening"] = db          # dict present = active (meme si defauts)
            # additional communities
            _set(o, "additional_communities",
                 [{"community": x["community"], **({"description": x["descr"]} if x.get("descr") else {})}
                  for x in saddcomm.get(dn, [])])
            # set as paths (prepend avec asns, ou autres criteres)
            asps = []
            for ap in saspath.get(dn, []):
                ae = {"criteria": ap.get("criteria", "prepend")}
                if ap.get("lastnum") not in (None, "", "0"):
                    ae["count"] = int(ap["lastnum"])
                asns = sorted(saspathasn.get(ap["dn"], []),
                              key=lambda x: int(x.get("order", "0") or 0))
                if asns:
                    ae["asns"] = [{"number": int(a["asn"]),
                                   **({"order": int(a["order"])} if a.get("order") not in (None, "", "0") else {})}
                                  for a in asns]
                asps.append(ae)
            _set(o, "set_as_paths", asps)
            if dn + "/redistmpath" in smpath:
                o["multipath"] = True
            elif dn + "/nhunchanged" in snhunch:   # nhunchanged sans multipath = next_hop_propagation
                o["next_hop_propagation"] = True
            # external endpoint group (policy tag)
            rs = sptag_rs.get(dn)
            if rs and rs.get("tDn"):
                mm = re.search(r"tn-([^/]+)/out-([^/]+)/instP-(.+)$", rs["tDn"])
                if mm:
                    eeg = {"name": mm.group(3), "l3out": mm.group(2)}
                    if mm.group(1) != t:
                        eeg["tenant"] = mm.group(1)
                    o["external_endpoint_group"] = eeg
    # enrichir les match_rules (rtctrlSubjP) : prefixes (rtctrlMatchRtDest) +
    # community terms/factors + regex terms [audit 2026-07-03]
    matchdest = _by_parent(apic.get_class("rtctrlMatchRtDest"))
    commterm = _by_parent(apic.get_class("rtctrlMatchCommTerm"))
    commfact = _by_parent(apic.get_class("rtctrlMatchCommFactor"))
    commrx = _by_parent(apic.get_class("rtctrlMatchCommRegexTerm"))
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.match_rules", {}).items():
            prefixes = []
            for p in matchdest.get(dn, []):
                px = {"ip": p["ip"], "aggregate": p.get("aggregate") == "yes"}
                if p.get("descr"):
                    px["description"] = p["descr"]
                if p.get("fromPfxLen") and p["fromPfxLen"] != "0":
                    px["from_length"] = int(p["fromPfxLen"])
                if p.get("toPfxLen") and p["toPfxLen"] != "0":
                    px["to_length"] = int(p["toPfxLen"])
                prefixes.append(px)
            if prefixes:
                o["prefixes"] = prefixes
            terms = []
            for tm in commterm.get(dn, []):
                e = {"name": tm["name"]}
                if tm.get("descr"):
                    e["description"] = tm["descr"]
                facts = []
                for f in commfact.get(tm["dn"], []):
                    fe = {"community": f["community"]}
                    if f.get("descr"):
                        fe["description"] = f["descr"]
                    if f.get("scope") and f["scope"] != "transitive":   # defaut
                        fe["scope"] = f["scope"]
                    facts.append(fe)
                _set(e, "factors", facts)
                terms.append(e)
            if terms:
                o["community_terms"] = terms
            rxs = []
            for r in commrx.get(dn, []):
                e = {"name": r["name"], "regex": r.get("regex", "")}
                if r.get("commType") and r["commType"] != "regular":    # defaut
                    e["type"] = r["commType"]
                if r.get("descr"):
                    e["description"] = r["descr"]
                rxs.append(e)
            if rxs:
                o["regex_community_terms"] = rxs
    # enrichir les igmp_interface_policies : limites d'etat (igmpStateLPol) +
    # 3 route-maps (report/static_report/state_limit) [audit 2026-07-04]
    igmp_statel = {_parent(x["dn"]): x for x in apic.get_class("igmpStateLPol")}
    igmp_rtmap = {x["dn"]: x.get("tDn", "") for x in apic.get_class("rtdmcRsFilterToRtMapPol")}
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.igmp_interface_policies", {}).items():
            sl = igmp_statel.get(dn)              # dict keye par parent (igmpIfPol dn)
            if sl:
                if sl.get("max") and sl["max"] != "unlimited":         # defaut unlimited
                    o["max_mcast_entries"] = int(sl["max"])
                if sl.get("rsvd") and sl["rsvd"] != "undefined":       # defaut undefined
                    o["reserved_mcast_entries"] = int(sl["rsvd"])
                rm = igmp_rtmap.get(sl["dn"] + "/rsfilterToRtMapPol", "")
                if "/rtmap-" in rm:
                    o["state_limit_multicast_route_map"] = rm.rsplit("/rtmap-", 1)[1]
            rm = igmp_rtmap.get(dn + "/igmpstrepPol-static-group/rsfilterToRtMapPol", "")
            if "/rtmap-" in rm:
                o["report_policy_multicast_route_map"] = rm.rsplit("/rtmap-", 1)[1]
            rm = igmp_rtmap.get(dn + "/igmprepPol/rsfilterToRtMapPol", "")
            if "/rtmap-" in rm:
                o["static_report_multicast_route_map"] = rm.rsplit("/rtmap-", 1)[1]
    # enrichir les multicast route maps (pimRouteMapPol) avec leurs entries (pimRouteMapEntry)
    # for_each sur var.entries (liste derivee) -> non capture par le moteur generique
    mrm_entries = _by_parent(apic.get_class("pimRouteMapEntry"))
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.multicast_route_maps", {}).items():
            entries = []
            for e in sorted(mrm_entries.get(dn, []), key=lambda x: int(x.get("order", "0") or 0)):
                ex = {"order": int(e["order"])}
                if e.get("action") and e["action"] != "permit":       # defaut permit
                    ex["action"] = e["action"]
                if e.get("src") and e["src"] not in ("0.0.0.0", ""):   # defaut 0.0.0.0
                    ex["source_ip"] = e["src"]
                if e.get("grp") and e["grp"] not in ("0.0.0.0", ""):
                    ex["group_ip"] = e["grp"]
                if e.get("rp") and e["rp"] not in ("0.0.0.0", ""):
                    ex["rp_ip"] = e["rp"]
                entries.append(ex)
            if entries:
                o["entries"] = entries
    # tenant netflow : match_parameters (join+sort non parsé) + relations exporter/monitor
    nf_rec = {x["dn"]: x for x in apic.get_class("netflowRecordPol")}
    nf_exp_ctx = {_parent(x["dn"]): x for x in apic.get_class("netflowRsExporterToCtx")}
    nf_exp_epg = {_parent(x["dn"]): x for x in apic.get_class("netflowRsExporterToEPg")}
    nf_mon_rec = {_parent(x["dn"]): x for x in apic.get_class("netflowRsMonitorToRecord")}
    nf_mon_exp = _by_parent(apic.get_class("netflowRsMonitorToExporter"))
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.netflow_records", {}).items():
            mo = nf_rec.get(dn)
            if mo and mo.get("match"):
                o["match_parameters"] = sorted(mo["match"].split(","))
        for name, (dn, o) in subs.get("policies.netflow_exporters", {}).items():
            ctx = nf_exp_ctx.get(dn)
            if ctx and ctx.get("tDn"):                       # -> vrf
                o["vrf"] = _seg(ctx["tDn"], "ctx")
            epg = nf_exp_epg.get(dn)
            if epg and epg.get("tDn"):
                tdn = epg["tDn"]
                if "/ap-" in tdn:                            # binding EPG
                    o["epg_type"] = "epg"
                    o["application_profile"] = _seg(tdn, "ap")
                    o["endpoint_group"] = _seg(tdn, "epg")
                elif "/out-" in tdn:                         # binding L3Out ext-EPG
                    o["epg_type"] = "external_epg"
                    o["l3out"] = _seg(tdn, "out")
                    o["external_endpoint_group"] = _seg(tdn, "instP")
        for name, (dn, o) in subs.get("policies.netflow_monitors", {}).items():
            rec = nf_mon_rec.get(dn)
            if rec and rec.get("tnNetflowRecordPolName"):
                o["flow_record"] = rec["tnNetflowRecordPolName"]
            exps = sorted(x["tnNetflowExporterPolName"] for x in nf_mon_exp.get(dn, [])
                          if x.get("tnNetflowExporterPolName"))
            if exps:
                o["flow_exporters"] = exps
    # qos custom (qosCustomPol) : dscp_priority_maps (qosDscpClass) + dot1p_classifiers
    # (qosDot1PClass) = for_each dérivés -> non vus par le générique. [#83]
    qds = _by_parent(apic.get_class("qosDscpClass"))
    qd1 = _by_parent(apic.get_class("qosDot1PClass"))

    def _qos_map(c, fromk, tok):
        m = {fromk: _num(c["from"]), tok: _num(c["to"])}    # DSCP keyword reste str, dot1p -> int
        if c.get("prio") and c["prio"] != "level3":            # défaut level3
            m["priority"] = c["prio"]
        if c.get("target") and c["target"] != "unspecified":
            m["dscp_target"] = c["target"]
        if c.get("targetCos") and c["targetCos"] != "unspecified":
            m["cos_target"] = _num(c["targetCos"])
        return m
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.qos", {}).items():
            dm = [_qos_map(c, "dscp_from", "dscp_to") for c in qds.get(dn, [])]
            if dm:
                o["dscp_priority_maps"] = dm
            d1 = [_qos_map(c, "dot1p_from", "dot1p_to") for c in qd1.get(dn, [])]
            if d1:
                o["dot1p_classifiers"] = d1
    # tenant-monitoring-policy (monEPGPol, base captée par le générique subpath
    # policies.monitoring.policies) : ENRICHIR avec fault_severity_policies (monEPGTarget/
    # faultSevAsnP, même logique que #14). snmp/syslog sources = réfs fabric groups -> omis. [#85]
    mon_tgt = _by_parent(apic.get_class("monEPGTarget"))       # par monEPGPol DN
    mon_fsev = _by_parent(apic.get_class("faultSevAsnP"))      # par monEPGTarget DN
    mon_snmpsrc = _by_parent(apic.get_class("snmpSrc"))        # sources snmp/syslog [audit 2026-07-06]
    mon_snmpdest = {_parent(x["dn"]): x for x in apic.get_class("snmpRsDestGroup")}
    mon_slsrc = _by_parent(apic.get_class("syslogSrc"))
    mon_sldest = {_parent(x["dn"]): x for x in apic.get_class("syslogRsDestGroup")}
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.monitoring.policies", {}).items():
            fsp = []
            for tgt in mon_tgt.get(dn, []):
                faults = []
                for f in mon_fsev.get(tgt["dn"], []):
                    fx = {"fault_id": f["code"], "initial_severity": f["initial"],
                          "target_severity": f["target"]}
                    if f.get("descr"):
                        fx["description"] = f["descr"]
                    faults.append(fx)
                if faults:
                    fsp.append({"class": tgt["scope"], "faults": faults})
            if fsp:
                o["fault_severity_policies"] = fsp
            # snmp trap policies + syslog policies (sources sous monEPGPol)
            snmps = []
            for s in mon_snmpsrc.get(dn, []):
                e = {"name": s["name"]}
                d = mon_snmpdest.get(s["dn"])
                if d and "/snmpgroup-" in d.get("tDn", ""):
                    e["destination_group"] = d["tDn"].rsplit("/snmpgroup-", 1)[1]
                snmps.append(e)
            _set(o, "snmp_trap_policies", snmps)
            _set(o, "syslog_policies", [_syslog_src_entry(s, mon_sldest.get(s["dn"]))
                                        for s in mon_slsrc.get(dn, [])])
    # tenant-span dest groups (spanDestGrp) : base générique + spanRsDestEpg (comme #37/#41) [#86]
    sp_dest = _by_parent(apic.get_class("spanDest"))
    sp_destepg = {_parent(x["dn"]): x for x in apic.get_class("spanRsDestEpg")}
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.span.destination_groups", {}).items():
            for d in sp_dest.get(dn, []):
                e = sp_destepg.get(d["dn"])
                if not e:
                    continue
                mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", e.get("tDn", ""))
                if mm:
                    o["tenant"], o["application_profile"], o["endpoint_group"] = mm.groups()
                if e.get("ip"):
                    o["ip"] = e["ip"]
                if e.get("srcIpPrefix"):
                    o["source_prefix"] = e["srcIpPrefix"]
                if e.get("dscp") and e["dscp"] != "unspecified":
                    o["dscp"] = e["dscp"]
                if e.get("flowId") and e["flowId"] != "1":
                    o["flow_id"] = int(e["flowId"])
                if e.get("mtu") and e["mtu"] != "1518":
                    o["mtu"] = int(e["mtu"])
                if e.get("ttl") and e["ttl"] != "64":
                    o["ttl"] = int(e["ttl"])
                vm = re.match(r"ver(\d+)", e.get("ver", ""))
                if vm and vm.group(1) != "2":
                    o["version"] = int(vm.group(1))
                if e.get("verEnforced") == "yes":
                    o["enforce_version"] = True
                break
    # tenant-span source groups (spanSrcGrp) : base + admin_state générique ; enrichir
    # destination (spanSpanLbl) + sources (spanSrc + spanRsSrcToEpg) (comme #40) [#86]
    sp_src = _by_parent(apic.get_class("spanSrc"))
    sp_srcepg = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcToEpg")}
    sp_lbl = _by_parent(apic.get_class("spanSpanLbl"))
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.span.source_groups", {}).items():
            for l in sp_lbl.get(dn, []):
                o["destination"] = l["name"]            # tenant : destination = string (nom du dest group)
                break
            sl = []
            for s in sp_src.get(dn, []):
                so = {"name": s["name"]}
                if s.get("descr"):
                    so["description"] = s["descr"]
                if s.get("dir") and s["dir"] != "both":
                    so["direction"] = s["dir"]
                e = sp_srcepg.get(s["dn"])
                if e:
                    mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", e.get("tDn", ""))
                    if mm:
                        so["tenant"], so["application_profile"], so["endpoint_group"] = mm.groups()
                sl.append(so)
            if sl:
                o["sources"] = sl
    res = defaultdict(lambda: defaultdict(list))
    for t, subs in byname.items():
        for sub, objs in subs.items():
            res[t][sub] = [o for _, o in objs.values()]
    return res

# ═══════════════════════════════════════════════════════ CAPTURE : tenants
# fvRsPathAtt : 6 formes de tDn (port, sub-port, PC, vPC, FEX, FEX-PC/vPC) [#57 static_ports]
_RE_PATHEP = re.compile(
    r"topology/pod-(\d+)/(?:protpaths-(\d+)-(\d+)|paths-(\d+))"
    r"(?:/extprotpaths-(\d+)-(\d+)|/extpaths-(\d+))?/pathep-\[([^\]]+)\]$")

def _span_path_entry(tdn):
    """tDn d'un path SPAN (spanRsSrcToPathEp/spanRsDestPathEp) -> entree access_paths
    (pod_id/node_id/node2_id/module/port/sub_port/channel/fex). None si non reconnu.
    [audit 2026-07-06]"""
    m = _RE_PATHEP.match(tdn or "")
    if not m:
        return None
    pod, n1v, n2v, n1, f1v, f2v, f1, ep = m.groups()
    o = {"pod_id": int(pod), "node_id": int(n1v or n1)}
    if n2v:
        o["node2_id"] = int(n2v)
    if f1v:
        o["fex_id"], o["fex2_id"] = int(f1v), int(f2v)
    elif f1:
        o["fex_id"] = int(f1)
    pm = re.match(r"eth(\d+)/(\d+)(?:/(\d+))?$", ep)
    if pm:
        if pm.group(1) != "1":
            o["module"] = int(pm.group(1))
        o["port"] = int(pm.group(2))
        if pm.group(3):
            o["sub_port"] = int(pm.group(3))
    else:
        o["channel"] = ep
    return o

def _path_att_entry(rs):
    """Reverse un fvRsPathAtt -> entree static_ports du data model (None si tDn inconnu).
    Defauts NaC omis : pod 1, module 1, mode regular, deployment_immediacy lazy."""
    m = _RE_PATHEP.match(rs.get("tDn", ""))
    mv = re.match(r"vlan-(\d+)$", rs.get("encap", ""))
    if not m or not mv:
        return None
    pod, n1v, n2v, n1, f1v, f2v, f1, ep = m.groups()
    o = {"node_id": int(n1v or n1)}
    if n2v:
        o["node2_id"] = int(n2v)
    if f1v:
        o["fex_id"], o["fex2_id"] = int(f1v), int(f2v)
    elif f1:
        o["fex_id"] = int(f1)
    pm = re.match(r"eth(\d+)/(\d+)(?:/(\d+))?$", ep)
    if pm:                                   # port physique (module omis si 1)
        if pm.group(1) != "1":
            o["module"] = int(pm.group(1))
        o["port"] = int(pm.group(2))
        if pm.group(3):
            o["sub_port"] = int(pm.group(3))
    else:                                    # PC/vPC : pathep = nom du policy group
        o["channel"] = ep
    o["vlan"] = int(mv.group(1))
    if pod != "1":
        o["pod_id"] = int(pod)
    if rs.get("descr"):
        o["description"] = rs["descr"]
    pv = re.match(r"vlan-(\d+)$", rs.get("primaryEncap", ""))
    if pv:
        o["primary_vlan"] = int(pv.group(1))
    if rs.get("mode") and rs["mode"] != "regular":
        o["mode"] = rs["mode"]
    if rs.get("instrImedcy") and rs["instrImedcy"] != "lazy":
        o["deployment_immediacy"] = rs["instrImedcy"]
    return o

def _node_att_entry(rs):
    """Reverse un fvRsNodeAtt -> entree static_leafs du data model."""
    m = re.match(r"topology/pod-(\d+)/node-(\d+)$", rs.get("tDn", ""))
    mv = re.match(r"vlan-(\d+)$", rs.get("encap", ""))
    if not m or not mv:
        return None
    o = {"node_id": int(m.group(2)), "vlan": int(mv.group(1))}
    if m.group(1) != "1":
        o["pod_id"] = int(m.group(1))
    if rs.get("mode") and rs["mode"] != "regular":
        o["mode"] = rs["mode"]
    if rs.get("instrImedcy") and rs["instrImedcy"] != "lazy":
        o["deployment_immediacy"] = rs["instrImedcy"]
    return o

def capture_tenants(apic: Apic, warnings: list):
    tn_rows = [t for t in apic.get_class("fvTenant") if t["name"] not in SYSTEM_TENANTS]
    tenants = {t["name"]: obj("terraform-aci-tenant", "fvTenant", t) for t in tn_rows}
    # security domains RBAC du tenant (aaaDomainRef) [audit 2026-07-03]
    tsd_by = _by_parent(apic.get_class("aaaDomainRef"))
    for t in tn_rows:
        sd = sorted(x["name"] for x in tsd_by.get(t["dn"], []))
        if sd:
            tenants[t["name"]]["security_domains"] = sd
    keep = set(tenants)
    system = [{"name": n, "managed": False} for n in SYSTEM_TENANTS]
    tn = lambda dn: _seg(dn, "tn")

    # vzAny (enfant inconditionnel du module vrf) : preferred_group + contrats vzAny.
    # SANS capture, un sync repasserait prefGrMemb a disabled et detruirait les
    # contrats vzAny (securite de tout le VRF). [audit 2026-07-03]
    any_by_vrf = {_parent(a["dn"]): a for a in apic.get_class("vzAny")}
    any_cons = _by_parent(apic.get_class("vzRsAnyToCons"), 2)     # <ctx>/any/rsanyToCons-X
    any_prov = _by_parent(apic.get_class("vzRsAnyToProv"), 2)
    any_impc = _by_parent(apic.get_class("vzRsAnyToConsIf"), 2)
    vrfs = defaultdict(list)
    for v in apic.get_class("fvCtx"):
        if tn(v["dn"]) not in keep:
            continue
        vo = obj("terraform-aci-vrf", "fvCtx", v)
        va = any_by_vrf.get(v["dn"])
        if va and va.get("prefGrMemb") == "enabled":              # défaut false
            vo["preferred_group"] = True
        c = {}
        cons = sorted(x["tnVzBrCPName"] for x in any_cons.get(v["dn"], []) if x.get("tnVzBrCPName"))
        prov = sorted(x["tnVzBrCPName"] for x in any_prov.get(v["dn"], []) if x.get("tnVzBrCPName"))
        impc = sorted(x["tnVzCPIfName"] for x in any_impc.get(v["dn"], []) if x.get("tnVzCPIfName"))
        if cons: c["consumers"] = cons
        if prov: c["providers"] = prov
        if impc: c["imported_consumers"] = impc
        if c:
            vo["contracts"] = c
        vrfs[tn(v["dn"])].append(vo)

    bd_vrf = {_parent(a["dn"]): _seg(a["tDn"], "ctx") for a in apic.get_class("fvRsCtx")}
    subnets = _by_parent(apic.get_class("fvSubnet"))
    bd_out = _by_parent(apic.get_class("fvRsBDToOut"))            # BD -> L3Out
    # enfants BD : dhcp labels + refs de policies [audit 2026-07-03]
    dhcplbl_by_bd = _by_parent(apic.get_class("dhcpLbl"))
    dhcpopt_by_lbl = {_parent(x["dn"]): x for x in apic.get_class("dhcpRsDhcpOptionPol")}
    igmpifp_by_bd = {_parent(x["dn"], 2): x for x in apic.get_class("igmpRsIfPol")}
    igmpsn_by_bd = {_parent(x["dn"]): x for x in apic.get_class("fvRsIgmpsn")}
    ndp_by_bd = {_parent(x["dn"]): x for x in apic.get_class("fvRsBDToNdP")}
    epret_by_bd = {_parent(x["dn"]): x for x in apic.get_class("fvRsBdToEpRet")}
    accp_by_bd = {_parent(x["dn"]): x for x in apic.get_class("fvAccP")}
    nf_by_bd = _by_parent(apic.get_class("fvRsBDToNetflowMonitorPol"))
    ndpfx_by_sub = {_parent(x["dn"]): x for x in apic.get_class("fvRsNdPfxPol")}
    pim_rtmap = {x["dn"]: x.get("tDn", "") for x in apic.get_class("rtdmcRsFilterToRtMapPol")}
    bds = defaultdict(list)
    for b in apic.get_class("fvBD"):
        if tn(b["dn"]) not in keep:
            continue
        vrf = bd_vrf.get(b["dn"])
        if not vrf:
            warnings.append(f"BD '{tn(b['dn'])}/{b['name']}' has no VRF -> skipped")
            continue
        o = obj("terraform-aci-bridge-domain", "fvBD", b); o["vrf"] = vrf
        if b.get("mcastARPDrop") == "yes":          # conditionnel (!=null?...:null) non parsé par attr_map, défaut false [#56]
            o["multicast_arp_drop"] = True
        subs = []
        for s in subnets.get(b["dn"], []):
            so = obj("terraform-aci-bridge-domain", "fvSubnet", s)
            pfx = ndpfx_by_sub.get(s["dn"])         # nd ra prefix policy du subnet
            if pfx and pfx.get("tnNdPfxPolName"):
                so["nd_ra_prefix_policy"] = pfx["tnNdPfxPolName"]
            subs.append(so)
        _set(o, "subnets", subs)
        _set(o, "l3outs", [rs["tnL3extOutName"] for rs in bd_out.get(b["dn"], [])])
        # dhcp labels (dhcpLbl + option policy)
        lbls = []
        for lb in dhcplbl_by_bd.get(b["dn"], []):
            e = {"dhcp_relay_policy": lb["name"]}
            if lb.get("owner") and lb["owner"] != "tenant":     # defaut tenant
                e["scope"] = lb["owner"]
            op = dhcpopt_by_lbl.get(lb["dn"])
            if op and op.get("tnDhcpOptionPolName"):
                e["dhcp_option_policy"] = op["tnDhcpOptionPolName"]
            lbls.append(e)
        _set(o, "dhcp_labels", lbls)
        # refs de policies (relations auto-creees avec tnName vide -> ignorees)
        rs = igmpifp_by_bd.get(b["dn"])
        if rs and "/igmpIfPol-" in rs.get("tDn", ""):
            o["igmp_interface_policy"] = rs["tDn"].rsplit("/igmpIfPol-", 1)[1]
        for src, key, attr in ((igmpsn_by_bd, "igmp_snooping_policy", "tnIgmpSnoopPolName"),
                               (ndp_by_bd, "nd_interface_policy", "tnNdIfPolName"),
                               (epret_by_bd, "endpoint_retention_policy", "tnFvEpRetPolName")):
            rs = src.get(b["dn"])
            if rs and rs.get(attr):
                o[key] = rs[attr]
        acc = accp_by_bd.get(b["dn"])               # legacy mode (fvAccP encap)
        if acc and acc.get("encap", "").startswith("vlan-"):
            o["legacy_mode_vlan"] = int(acc["encap"].replace("vlan-", ""))
        _set(o, "netflow_monitor_policies",
             [{"name": x["tnNetflowMonitorPolName"], "ip_filter_type": x.get("fltType", "ipv4")}
              for x in nf_by_bd.get(b["dn"], []) if x.get("tnNetflowMonitorPolName")])
        # filtres PIM (route maps) sous <bd>/pimbdp/pimbdfilterp/
        src = pim_rtmap.get(b["dn"] + "/pimbdp/pimbdfilterp/pimbdsrcfilterp/rsfilterToRtMapPol", "")
        if "/rtmap-" in src:
            o["pim_source_filter"] = src.rsplit("/rtmap-", 1)[1]
        dst = pim_rtmap.get(b["dn"] + "/pimbdp/pimbdfilterp/pimbddestfilterp/rsfilterToRtMapPol", "")
        if "/rtmap-" in dst:
            o["pim_destination_filter"] = dst.rsplit("/rtmap-", 1)[1]
        bds[tn(b["dn"])].append(o)

    epg_bd = {_parent(a["dn"]): _seg(a["tDn"], "BD") for a in apic.get_class("fvRsBd")}
    epg_cons = _by_parent(apic.get_class("fvRsCons"))           # EPG -> contrats consommes
    epg_prov = _by_parent(apic.get_class("fvRsProv"))           # EPG -> contrats fournis
    epg_dom = _by_parent(apic.get_class("fvRsDomAtt"))          # EPG -> domaines
    epg_paths = _by_parent(apic.get_class("fvRsPathAtt"))       # bindings statiques ports [#57]
    epg_nodes = _by_parent(apic.get_class("fvRsNodeAtt"))       # bindings statiques leafs [#57]
    # enfants EPG additionnels [audit 2026-07-04] (subnets reutilise `subnets` du BD)
    epg_tags = _by_parent(apic.get_class("tagInst"))           # tags
    epg_consif = _by_parent(apic.get_class("fvRsConsIf"))      # contrats importes consommes
    epg_intra = _by_parent(apic.get_class("fvRsIntraEpg"))     # contrats intra-EPG
    epg_master = _by_parent(apic.get_class("fvRsSecInherited"))# EPG masters (herit. contrats)
    epg_custqos = {_parent(x["dn"]): x for x in apic.get_class("fvRsCustQosPol")}
    epg_trust = {_parent(x["dn"]): x for x in apic.get_class("fvRsTrustCtrl")}
    epg_dpp = {_parent(x["dn"]): x for x in apic.get_class("fvRsDppPol")}
    epgs = _by_parent(apic.get_class("fvAEPg"))
    esgs = _by_parent(apic.get_class("fvESg"))                  # ESG par AP DN
    esg_scope = {x["dn"]: x for x in apic.get_class("fvRsScope")}    # <esg>/rsscope -> vrf
    esg_tagsel = _by_parent(apic.get_class("fvTagSelector"))    # tag selectors par ESG
    esg_ipsel = _by_parent(apic.get_class("fvEPSelector"))      # ip subnet selectors par ESG
    crtrns = {_parent(c["dn"]): c for c in apic.get_class("fvCrtrn")}   # <epg>/crtrn [#106]
    ipattrs = _by_parent(apic.get_class("fvIpAttr"), 2)         # par EPG DN (sous crtrn)
    macattrs = _by_parent(apic.get_class("fvMacAttr"), 2)
    aps = defaultdict(list)
    for ap_mo in apic.get_class("fvAp"):
        if tn(ap_mo["dn"]) not in keep:
            continue
        eg, useg = [], []
        for e in epgs.get(ap_mo["dn"], []):
            attr_based = e.get("isAttrBasedEPg") == "yes"        # uSeg EPG [#106]
            mod = "terraform-aci-useg-endpoint-group" if attr_based else "terraform-aci-endpoint-group"
            eo = obj(mod, "fvAEPg", e)
            if epg_bd.get(e["dn"]):
                eo["bridge_domain"] = epg_bd[e["dn"]]
            # contrats (consommes / fournis) — cœur de la securite ACI
            cons = [rs["tnVzBrCPName"] for rs in epg_cons.get(e["dn"], [])]
            prov = [rs["tnVzBrCPName"] for rs in epg_prov.get(e["dn"], [])]
            if cons or prov:
                eo["contracts"] = {}
                if cons: eo["contracts"]["consumers"] = cons
                if prov: eo["contracts"]["providers"] = prov
            # domaines associes (physiques / vmm)
            phys, vmw = [], []
            for rs in epg_dom.get(e["dn"], []):
                t = rs["tDn"]
                if "/phys-" in t: phys.append(_ref(t))
                elif "/vmmp-VMware/dom-" in t: vmw.append(t.rsplit("/dom-", 1)[1])
            _set(eo, "physical_domains", phys); _set(eo, "vmware_vmm_domains", vmw)
            # bindings statiques (fvRsPathAtt/fvRsNodeAtt) [#57]
            sps, sls = [], []
            for rs in epg_paths.get(e["dn"], []):
                sp = _path_att_entry(rs)
                if sp is None:
                    warnings.append(f"EPG '{e['name']}': fvRsPathAtt non reconnu "
                                    f"({rs.get('tDn')}) -> ignore")
                elif attr_based:               # le module useg n'a pas static_ports
                    warnings.append(f"uSeg EPG '{e['name']}': static port "
                                    f"{rs.get('tDn')} non supporte par le module -> ignore")
                else:
                    sps.append(sp)
            for rs in epg_nodes.get(e["dn"], []):
                sl = _node_att_entry(rs)
                if sl is None:
                    warnings.append(f"EPG '{e['name']}': fvRsNodeAtt non reconnu "
                                    f"({rs.get('tDn')}) -> ignore")
                else:
                    sls.append(sl)
            _set(eo, "static_ports", sps)
            _set(eo, "static_leafs", sls)
            # enfants communs EPG/useg-EPG [audit 2026-07-04]
            _set(eo, "subnets", [obj("terraform-aci-endpoint-group", "fvSubnet", s)
                                 for s in subnets.get(e["dn"], [])])
            _set(eo, "tags", sorted(x["name"] for x in epg_tags.get(e["dn"], [])))
            # contrats importes / intra / masters -> completent eo["contracts"]
            consif = [rs["tnVzCPIfName"] for rs in epg_consif.get(e["dn"], [])]
            intra = [rs["tnVzBrCPName"] for rs in epg_intra.get(e["dn"], [])]
            if consif or intra:
                eo.setdefault("contracts", {})
                if consif: eo["contracts"]["imported_consumers"] = consif
                if intra: eo["contracts"]["intra_epgs"] = intra
            masters = []
            for rs in epg_master.get(e["dn"], []):
                mm = re.search(r"/ap-([^/]+)/epg-(.+)$", rs.get("tDn", ""))
                if mm:
                    masters.append({"application_profile": mm.group(1),
                                    "endpoint_group": mm.group(2)})
            if masters:
                eo.setdefault("contracts", {})["masters"] = masters
            cq = epg_custqos.get(e["dn"])
            if cq and cq.get("tnQosCustomPolName"):
                eo["custom_qos_policy"] = cq["tnQosCustomPolName"]
            tc = epg_trust.get(e["dn"])
            if tc and tc.get("tnFhsTrustCtrlPolName"):
                eo["trust_control_policy"] = tc["tnFhsTrustCtrlPolName"]
            dp = epg_dpp.get(e["dn"])
            if dp and dp.get("tnQosDppPolName"):
                eo["data_plane_policing_policy"] = dp["tnQosDppPolName"]
            if attr_based:                                       # criteres uSeg [#106]
                cr = crtrns.get(e["dn"] + "/crtrn")
                ua = {}
                if cr and cr.get("match") and cr["match"] != "any":
                    ua["match_type"] = cr["match"]
                ips = []
                for x in ipattrs.get(e["dn"], []):
                    io = {"name": x["name"]}
                    if x.get("usefvSubnet") == "yes":            # DEFAUT NaC = true !
                        io["use_epg_subnet"] = True
                    else:
                        io["use_epg_subnet"] = False             # requis sinon defaut true
                        if x.get("ip") and x["ip"] != "0.0.0.0":
                            io["ip"] = x["ip"]
                    ips.append(io)
                _set(ua, "ip_statements", ips)
                macs = [{"name": x["name"], "mac": x["mac"]}
                        for x in macattrs.get(e["dn"], [])]
                _set(ua, "mac_statements", macs)
                # vm_statements (fvVmAttr) : VMM absent du simulateur -> non captures
                if ua:
                    eo["useg_attributes"] = ua
                useg.append(eo)
            else:
                eg.append(eo)
        # endpoint security groups (fvESg) sous l'AP : attrs + vrf + selecteurs
        esg_list = []
        for es in esgs.get(ap_mo["dn"], []):
            eso = obj("terraform-aci-endpoint-security-group", "fvESg", es)
            sc = esg_scope.get(es["dn"] + "/rsscope")
            if sc and sc.get("tnFvCtxName"):
                eso["vrf"] = sc["tnFvCtxName"]
            # contrats ESG : memes classes fvRsCons/fvRsProv que les EPG, deja
            # chargees par parent — elles n'etaient jamais lues ici [audit 2026-07-03]
            ec = {}
            cons = [rs["tnVzBrCPName"] for rs in epg_cons.get(es["dn"], [])]
            prov = [rs["tnVzBrCPName"] for rs in epg_prov.get(es["dn"], [])]
            if cons: ec["consumers"] = cons
            if prov: ec["providers"] = prov
            if ec:
                eso["contracts"] = ec
            tags = []
            for ts in esg_tagsel.get(es["dn"], []):
                t = {"key": ts["matchKey"], "value": ts["matchValue"]}
                if ts.get("valueOperator") and ts["valueOperator"] != "equals":
                    t["operator"] = ts["valueOperator"]
                if ts.get("descr"):
                    t["description"] = ts["descr"]
                tags.append(t)
            _set(eso, "tag_selectors", tags)
            ips = []
            for s in esg_ipsel.get(es["dn"], []):
                mm = re.search(r"ip=='([^']+)'", s.get("matchExpression", ""))
                if not mm:
                    continue
                ip = {"value": mm.group(1)}
                if s.get("descr"):
                    ip["description"] = s["descr"]
                ips.append(ip)
            _set(eso, "ip_subnet_selectors", ips)
            esg_list.append(eso)
        ao = obj("terraform-aci-application-profile", "fvAp", ap_mo)
        _set(ao, "endpoint_groups", eg)
        _set(ao, "useg_endpoint_groups", useg)
        _set(ao, "endpoint_security_groups", esg_list)
        aps[tn(ap_mo["dn"])].append(ao)

    entries = _by_parent(apic.get_class("vzEntry"))
    filters = defaultdict(list)
    for f in apic.get_class("vzFilter"):
        if tn(f["dn"]) not in keep:
            continue
        fo = obj("terraform-aci-filter", "vzFilter", f)
        ents = []
        for e in entries.get(f["dn"], []):
            eo = obj("terraform-aci-filter", "vzEntry", e)
            # prot/ports = ternaires (numéro->mot-clé) non parsés par attr_map ; on capture la forme
            # mot-clé telle qu'APIC la stocke (DN basé sur le nom -> stable). [#58]
            if e.get("prot") and e["prot"] != "unspecified":
                eo["protocol"] = e["prot"]
            for fld, key in (("sFromPort", "source_from_port"), ("sToPort", "source_to_port"),
                             ("dFromPort", "destination_from_port"), ("dToPort", "destination_to_port")):
                if e.get(fld) and e[fld] != "unspecified":
                    eo[key] = e[fld]
            ents.append(eo)
        _set(fo, "entries", ents)
        filters[tn(f["dn"])].append(fo)

    subjf = _by_parent(apic.get_class("vzRsSubjFiltAtt"))
    subjs = _by_parent(apic.get_class("vzSubj"))
    subjg = {_parent(g["dn"]): g for g in apic.get_class("vzRsSubjGraphAtt")}

    def _subj_filter_entry(rs):
        """vzRsSubjFiltAtt -> entree filters[] (options non-defaut) [audit 2026-07-03]"""
        fe = {"filter": rs.get("tnVzFilterName") or _ref(rs["tDn"])}
        if rs.get("action") and rs["action"] != "permit":
            fe["action"] = rs["action"]
        if rs.get("priorityOverride") and rs["priorityOverride"] != "default":
            fe["priority"] = rs["priorityOverride"]
        dirs = (rs.get("directives") or "").split(",")
        if "log" in dirs:
            fe["log"] = True
        if "no_stats" in dirs:
            fe["no_stats"] = True
        return fe

    contracts = defaultdict(list)
    for c in apic.get_class("vzBrCP"):
        if tn(c["dn"]) not in keep:
            continue
        co = obj("terraform-aci-contract", "vzBrCP", c)
        subs = []
        for s in subjs.get(c["dn"], []):
            so = obj("terraform-aci-contract", "vzSubj", s)
            _set(so, "filters", [_subj_filter_entry(rs) for rs in subjf.get(s["dn"], [])])
            # service graph attache au sujet (vzRsSubjGraphAtt) [audit 2026-07-03]
            g = subjg.get(s["dn"])
            if g and g.get("tnVnsAbsGraphName"):
                so["service_graph"] = g["tnVnsAbsGraphName"]
            subs.append(so)
        _set(co, "subjects", subs)
        contracts[tn(c["dn"])].append(co)

    l3_vrf = {_parent(a["dn"]): _seg(a["tDn"], "ctx") for a in apic.get_class("l3extRsEctx")}
    l3_dom = {_parent(a["dn"]): _ref(a["tDn"]) for a in apic.get_class("l3extRsL3DomAtt")}
    # external endpoint groups (l3extInstP) sous chaque L3Out : primaire + subnets + contrats
    # + route control profiles (EPG et subnet) + route summarization [audit 2026-07-06]
    ext_sub = _by_parent(apic.get_class("l3extSubnet"))
    ext_rcp = _by_parent(apic.get_class("l3extRsInstPToProfile"))        # EPG -> route-maps
    sub_rcp = _by_parent(apic.get_class("l3extRsSubnetToProfile"))       # subnet -> route-maps
    sub_summ = {_parent(x["dn"]): x for x in apic.get_class("l3extRsSubnetToRtSumm")}

    def _rcp_list(rows):
        """l3extRs*ToProfile -> [{name, direction}] (direction != import omis? non: requis)."""
        out = []
        for rs in rows:
            if not rs.get("tnRtctrlProfileName"):
                continue
            r = {"name": rs["tnRtctrlProfileName"]}
            if rs.get("direction") and rs["direction"] != "import":     # defaut import
                r["direction"] = rs["direction"]
            out.append(r)
        return out

    extepg_by_l3out = defaultdict(list)
    for e in apic.get_class("l3extInstP"):
        if tn(e["dn"]) not in keep:
            continue
        eo = obj("terraform-aci-external-endpoint-group", "l3extInstP", e)
        subs = []
        for s in ext_sub.get(e["dn"], []):
            so = obj("terraform-aci-external-endpoint-group", "l3extSubnet", s)
            _set(so, "route_control_profiles", _rcp_list(sub_rcp.get(s["dn"], [])))
            summ = sub_summ.get(s["dn"])                 # route summarization (bgp/ospf/eigrp)
            if summ and summ.get("tDn"):
                t = summ["tDn"]
                if "/bgprtsum-" in t:
                    so["bgp_route_summarization"] = True
                    if not t.endswith("bgprtsum-default"):
                        so["bgp_route_summarization_policy"] = t.rsplit("/bgprtsum-", 1)[1]
                elif "/ospfrtsumm-" in t:
                    so["ospf_route_summarization"] = True
                    if not t.endswith("ospfrtsumm-default"):
                        so["ospf_route_summarization_policy"] = t.rsplit("/ospfrtsumm-", 1)[1]
                elif "/eigrprtsumm-" in t:
                    so["eigrp_route_summarization"] = True
            subs.append(so)
        _set(eo, "subnets", subs)
        _set(eo, "route_control_profiles", _rcp_list(ext_rcp.get(e["dn"], [])))
        cons = [rs["tnVzBrCPName"] for rs in epg_cons.get(e["dn"], [])]
        prov = [rs["tnVzBrCPName"] for rs in epg_prov.get(e["dn"], [])]
        consif = [rs["tnVzCPIfName"] for rs in epg_consif.get(e["dn"], [])]
        if cons or prov or consif:
            eo["contracts"] = {}
            if cons: eo["contracts"]["consumers"] = cons
            if prov: eo["contracts"]["providers"] = prov
            if consif: eo["contracts"]["imported_consumers"] = consif
        masters = []
        for rs in epg_master.get(e["dn"], []):
            mm = re.search(r"/out-([^/]+)/instP-(.+)$", rs.get("tDn", ""))
            if mm:
                masters.append({"l3out": mm.group(1), "external_endpoint_group": mm.group(2)})
        if masters:
            eo.setdefault("contracts", {})["masters"] = masters
        extepg_by_l3out[_parent(e["dn"])].append(eo)
    # interface profiles (l3extLIfP) sous chaque node profile : name/qos + interfaces (paths)
    path_bind = _by_parent(apic.get_class("l3extRsPathL3OutAtt"))
    peer_bind = _by_parent(apic.get_class("bgpPeerP"))              # bgpPeerP par path/node DN
    asp_by_dn = {a["dn"]: a for a in apic.get_class("bgpAsP")}      # <peer>/as -> remote_as
    localasn_by_dn = {a["dn"]: a for a in apic.get_class("bgpLocalAsnP")}  # <peer>/localasn
    peerpfx_by_dn = {_parent(x["dn"]): x for x in apic.get_class("bgpRsPeerPfxPol")}
    peerprof_by_dn = _by_parent(apic.get_class("bgpRsPeerToProfile"))  # <peer> -> route-maps
    ospfifp_by_dn = {x["dn"]: x for x in apic.get_class("ospfIfP")}        # <lifp>/ospfIfP
    ospfrsifpol_by_dn = {x["dn"]: x for x in apic.get_class("ospfRsIfPol")}
    bfdrsifpol_by_dn = {x["dn"]: x for x in apic.get_class("bfdRsIfPol")}  # <lifp>/bfdIfP/rsIfPol
    # profils d'interface restants : eigrp/pim/nd + micro-BFD [audit 2026-07-06]
    eigrpifp_by_dn = {x["dn"]: x for x in apic.get_class("eigrpIfP")}      # <lifp>/eigrpIfP
    eigrprspol_by_dn = {x["dn"]: x for x in apic.get_class("eigrpRsIfPol")}
    eigrpkc_by_dn = {x["dn"]: x for x in apic.get_class("eigrpRsKeyChainPol")}
    pimrsifpol_by_dn = {x["dn"]: x for x in apic.get_class("pimRsIfPol")}
    ndrsifpol_by_dn = {x["dn"]: x for x in apic.get_class("l3extRsNdIfPol")}
    microbfd_by_path = {_parent(x["dn"]): x for x in apic.get_class("bfdMicroBfdP")}
    vlifp_by_ifp = _by_parent(apic.get_class("l3extVirtualLIfP"))          # floating SVI [audit 2026-07-03]
    dynpath_by_vlifp = _by_parent(apic.get_class("l3extRsDynPathAtt"))

    def _bgp_peer_entry(bp):
        """bgpPeerP -> entree bgp_peers[] (flags ctrl/peerCtrl/privateASctrl/addrTCtrl
        reverses + bgpAsP/bgpLocalAsnP). Utilise pour paths reguliers ET floating SVI."""
        pr = {"ip": bp["addr"]}
        asp = asp_by_dn.get(bp["dn"] + "/as")
        if asp and asp.get("asn"):
            pr["remote_as"] = asp["asn"]
        if bp.get("descr"):
            pr["description"] = bp["descr"]
        ctrl = set((bp.get("ctrl") or "").split(","))
        for fl, key in (("allow-self-as", "allow_self_as"), ("as-override", "as_override"),
                        ("dis-peer-as-check", "disable_peer_as_check"), ("nh-self", "next_hop_self"),
                        ("send-com", "send_community"), ("send-ext-com", "send_ext_community")):
            if fl in ctrl:
                pr[key] = True
        pctrl = set((bp.get("peerCtrl") or "").split(","))
        if "bfd" in pctrl:
            pr["bfd"] = True
        if "dis-conn-check" in pctrl:
            pr["disable_connected_check"] = True
        pas = set((bp.get("privateASctrl") or "").split(","))
        for fl, key in (("remove-all", "remove_all_private_as"), ("remove-exclusive", "remove_private_as"),
                        ("replace-as", "replace_private_as_with_local_as")):
            if fl in pas:
                pr[key] = True
        aft = set((bp.get("addrTCtrl") or "").split(","))
        pr["unicast_address_family"] = "af-ucast" in aft       # defaut true
        pr["multicast_address_family"] = "af-mcast" in aft     # defaut true
        if bp.get("adminSt") == "disabled":                    # defaut enabled (true)
            pr["admin_state"] = False
        if bp.get("allowedSelfAsCnt") and bp["allowedSelfAsCnt"] != "3":
            pr["allowed_self_as_count"] = int(bp["allowedSelfAsCnt"])
        if bp.get("ttl") and bp["ttl"] != "1":
            pr["ttl"] = int(bp["ttl"])
        if bp.get("weight") and bp["weight"] != "0":
            pr["weight"] = int(bp["weight"])
        la = localasn_by_dn.get(bp["dn"] + "/localasn")
        if la:
            if la.get("localAsn"):
                pr["local_as"] = int(la["localAsn"])
            if la.get("asnPropagate") and la["asnPropagate"] != "none":
                pr["as_propagate"] = la["asnPropagate"]
        # peer prefix policy + route control profiles import/export [audit 2026-07-06]
        pfx = peerpfx_by_dn.get(bp["dn"])
        if pfx and pfx.get("tnBgpPeerPfxPolName"):
            pr["peer_prefix_policy"] = pfx["tnBgpPeerPfxPolName"]
        for rs in peerprof_by_dn.get(bp["dn"], []):
            mm = re.search(r"/prof-(.+)$", rs.get("tDn", ""))
            if mm and rs.get("direction"):
                pr[f"{rs['direction']}_route_control"] = mm.group(1)
        return pr

    ifp_by_np = defaultdict(list)
    for ifp in apic.get_class("l3extLIfP"):
        if tn(ifp["dn"]) not in keep:
            continue
        ifo = obj("terraform-aci-l3out-interface-profile", "l3extLIfP", ifp)
        ifaces = []
        for pb in path_bind.get(ifp["dn"], []):
            t = pb.get("tDn", "")
            mp = re.search(r"pod-(\d+)", t)
            mn = re.search(r"(?:protpaths|paths)-([\d-]+)", t)
            mport = re.search(r"pathep-\[([^\]]+)\]", t)
            if not (mp and mn and mport):
                continue
            ns = mn.group(1).split("-")
            ifc = {"node_id": int(ns[0]), "pod_id": int(mp.group(1))}
            if len(ns) > 1:
                ifc["node2_id"] = int(ns[1])
            # port physique eth<module>/<port>[/<sub>]  OU  port-channel/vPC (channel)
            pm = re.match(r"eth(\d+)/(\d+)(?:/(\d+))?$", mport.group(1))
            if pm:
                ifc["module"] = int(pm.group(1)); ifc["port"] = int(pm.group(2))
                if pm.group(3):
                    ifc["sub_port"] = int(pm.group(3))
            else:
                ifc["channel"] = mport.group(1)
            if pb.get("addr") and pb["addr"] != "0.0.0.0":
                ifc["ip"] = pb["addr"]
            if pb.get("encap", "").startswith("vlan-"):
                ifc["vlan"] = int(pb["encap"].replace("vlan-", ""))
            svi = pb.get("ifInstT") == "ext-svi"
            if svi:
                ifc["svi"] = True
            if pb.get("mtu") and pb["mtu"] != "inherit":
                ifc["mtu"] = _num(pb["mtu"])
            if pb.get("descr"):
                ifc["description"] = pb["descr"]
            if pb.get("autostate") == "enabled":          # defaut disabled (false)
                ifc["autostate"] = True
            if pb.get("mode") and pb["mode"] != "regular":  # defaut regular
                ifc["mode"] = pb["mode"]
            if pb.get("mac") and pb["mac"] != "00:22:BD:F8:19:FF":  # defaut module
                ifc["mac"] = pb["mac"]
            if svi and pb.get("encapScope") == "ctx":       # defaut local
                ifc["scope"] = "vrf"
            # micro-BFD (bfdMicroBfdP sous le path, vPC) [audit 2026-07-06]
            mb = microbfd_by_path.get(pb["dn"])
            if mb and mb.get("dst"):
                mbo = {"destination_ip": mb["dst"]}
                if mb.get("stTm") not in (None, "", "0"):
                    mbo["start_timer"] = int(mb["stTm"])
                ifc["micro_bfd"] = mbo
            # bgp peers (bgpPeerP) sous le path : reverse des flags packes
            peers = [_bgp_peer_entry(bp) for bp in peer_bind.get(pb["dn"], [])]
            if peers:
                ifc["bgp_peers"] = peers
            ifaces.append(ifc)
        # floating SVI (l3extVirtualLIfP) : meme liste interfaces[], floating_svi=true,
        # + paths (l3extRsDynPathAtt) + bgp peers sous le vlifp [audit 2026-07-03]
        for vl in vlifp_by_ifp.get(ifp["dn"], []):
            mm = re.search(r"vlifp-\[topology/pod-(\d+)/node-(\d+)\]-\[vlan-(\d+)\]", vl["dn"])
            if not mm:
                warnings.append(f"floating SVI non reconnu ({vl['dn']}) -> ignore")
                continue
            ifc = {"node_id": int(mm.group(2)), "pod_id": int(mm.group(1)),
                   "vlan": int(mm.group(3)), "floating_svi": True}
            if vl.get("addr") and vl["addr"] != "0.0.0.0":
                ifc["ip"] = vl["addr"]
            if vl.get("descr"):
                ifc["description"] = vl["descr"]
            if vl.get("autostate") == "enabled":            # defaut disabled
                ifc["autostate"] = True
            if vl.get("mode") and vl["mode"] != "regular":
                ifc["mode"] = vl["mode"]
            if vl.get("mtu") and vl["mtu"] != "inherit":
                ifc["mtu"] = _num(vl["mtu"])
            if vl.get("mac") and vl["mac"] != "00:22:BD:F8:19:FF":
                ifc["mac"] = vl["mac"]
            if vl.get("encapScope") == "ctx":               # defaut local
                ifc["scope"] = "vrf"
            if vl.get("llAddr") and vl["llAddr"] != "::":
                ifc["link_local_address"] = vl["llAddr"]
            paths = []
            for dp in dynpath_by_vlifp.get(vl["dn"], []):
                t = dp.get("tDn", "")
                po = {}
                if t.startswith("uni/phys-"):
                    po["physical_domain"] = t.split("/phys-", 1)[1]
                elif "/vmmp-VMware/dom-" in t:
                    po["vmware_vmm_domain"] = t.rsplit("/dom-", 1)[1]
                else:
                    warnings.append(f"floating path domaine non reconnu ({t}) -> ignore")
                    continue
                if dp.get("floatingAddr") and dp["floatingAddr"] != "0.0.0.0":
                    po["floating_ip"] = dp["floatingAddr"]
                if dp.get("encap", "").startswith("vlan-"):
                    po["vlan"] = int(dp["encap"].replace("vlan-", ""))
                for attr, key in (("forgedTransmit", "forged_transmit"),
                                  ("macChange", "mac_change"), ("promMode", "promiscous_mode")):
                    if dp.get(attr) == "Enabled":           # defaut Disabled
                        po[key] = True
                paths.append(po)
            if paths:
                ifc["paths"] = paths
            peers = [_bgp_peer_entry(bp) for bp in peer_bind.get(vl["dn"], [])]
            if peers:
                ifc["bgp_peers"] = peers
            ifaces.append(ifc)
        _set(ifo, "interfaces", ifaces)
        # ospf interface profile (ospfIfP) + relation policy (ospfRsIfPol)
        oifp = ospfifp_by_dn.get(ifp["dn"] + "/ospfIfP")
        if oifp is not None:
            ospf = {}
            if oifp.get("name"):
                ospf["ospf_interface_profile_name"] = oifp["name"]
            rsp = ospfrsifpol_by_dn.get(oifp["dn"] + "/rsIfPol")
            if rsp and rsp.get("tnOspfIfPolName"):
                ospf["policy"] = rsp["tnOspfIfPolName"]
            # authentification OSPF : authType/authKeyId sont PUBLICS et doivent
            # etre captures (sinon un sync remettrait authType=none et couperait
            # l'auth MD5 d'un brownfield) ; authKey = write-only (ignore_changes)
            # -> placeholder, requis par le module quand l'auth est active
            if oifp.get("authType") and oifp["authType"] != "none":
                ospf["auth_type"] = oifp["authType"]
                if oifp.get("authKeyId") and oifp["authKeyId"] != "1":
                    ospf["auth_key_id"] = _num(oifp["authKeyId"])
                ospf["auth_key"] = OSPF_KEY_PLACEHOLDER   # 8 car. max en auth simple
            if ospf:
                ifo["ospf"] = ospf
        # bfd interface profile (bfdIfP) -> bfd_policy (via bfdRsIfPol)
        brs = bfdrsifpol_by_dn.get(ifp["dn"] + "/bfdIfP/rsIfPol")
        if brs and brs.get("tnBfdIfPolName"):
            ifo["bfd_policy"] = brs["tnBfdIfPolName"]
        # eigrp interface profile (eigrpIfP + rsIfPol + keychain) [audit 2026-07-06]
        eifp = eigrpifp_by_dn.get(ifp["dn"] + "/eigrpIfP")
        if eifp is not None:
            eig = {}
            if eifp.get("name") and eifp["name"] != _seg(ifp["dn"], "out"):  # defaut = nom L3Out
                eig["interface_profile_name"] = eifp["name"]
            rsp = eigrprspol_by_dn.get(eifp["dn"] + "/rsIfPol")
            if rsp and rsp.get("tnEigrpIfPolName"):
                eig["interface_policy"] = rsp["tnEigrpIfPolName"]
            kc = eigrpkc_by_dn.get(eifp["dn"] + "/eigrpAuthIfP/rsKeyChainPol")
            if kc and kc.get("tnFvKeyChainPolName"):
                eig["keychain_policy"] = kc["tnFvKeyChainPolName"]
            if eig:
                ifo["eigrp"] = eig
        # pim / igmp / nd interface policies (refs) [audit 2026-07-06]
        prs = pimrsifpol_by_dn.get(ifp["dn"] + "/pimifp/rsIfPol")
        if prs and "/pimifpol-" in prs.get("tDn", ""):
            ifo["pim_policy"] = prs["tDn"].rsplit("/pimifpol-", 1)[1]
        irs = igmpifp_by_bd.get(ifp["dn"])       # igmpRsIfPol keye par grand-parent (BD OU lifp)
        if irs and "/igmpIfPol-" in irs.get("tDn", ""):
            ifo["igmp_interface_policy"] = irs["tDn"].rsplit("/igmpIfPol-", 1)[1]
        nrs = ndrsifpol_by_dn.get(ifp["dn"] + "/rsNdIfPol")
        if nrs and nrs.get("tnNdIfPolName"):
            ifo["nd_interface_policy"] = nrs["tnNdIfPolName"]
        ifp_by_np[_parent(ifp["dn"])].append(ifo)
    # node profiles (l3extLNodeP) sous chaque L3Out : name/description + nodes + interface_profiles
    node_bind = _by_parent(apic.get_class("l3extRsNodeL3OutAtt"))
    loopback_bind = _by_parent(apic.get_class("l3extLoopBackIfP"))   # par node-binding DN
    route_bind = _by_parent(apic.get_class("ipRouteP"))              # par node-binding DN
    nh_bind = _by_parent(apic.get_class("ipNexthopP"))               # par route DN
    mh_by_np = {_parent(x["dn"]): x for x in apic.get_class("bfdMhNodeP")}   # bfd multihop auth
    mhpol_by_np = {x["dn"]: x for x in apic.get_class("bfdRsMhNodePol")}     # bfd multihop pol ref
    np_by_l3out = defaultdict(list)
    for np in apic.get_class("l3extLNodeP"):
        if tn(np["dn"]) not in keep:
            continue
        npo = obj("terraform-aci-l3out-node-profile", "l3extLNodeP", np)
        nodes = []
        for nb in node_bind.get(np["dn"], []):
            m = re.search(r"pod-(\d+)/node-(\d+)", nb.get("tDn", ""))
            if not m:
                continue
            nd = {"node_id": int(m.group(2)), "pod_id": int(m.group(1))}
            if nb.get("rtrId"):
                nd["router_id"] = nb["rtrId"]
            nd["router_id_as_loopback"] = nb.get("rtrIdLoopBack") == "yes"
            # loopbacks explicites (l3extLoopBackIfP enfants du node-binding)
            lbs = [lb["addr"] for lb in loopback_bind.get(nb["dn"], []) if lb.get("addr")]
            if lbs:
                nd["loopbacks"] = lbs
            # static routes (ipRouteP) + next hops (ipNexthopP)
            routes = []
            for rt in route_bind.get(nb["dn"], []):
                sr = {"prefix": rt["ip"]}
                if rt.get("descr"):
                    sr["description"] = rt["descr"]
                if rt.get("pref") is not None:
                    sr["preference"] = int(rt["pref"])
                sr["bfd"] = "bfd" in (rt.get("rtCtrl") or "")
                nhs = []
                for nh in nh_bind.get(rt["dn"], []):
                    h = {"ip": nh["nhAddr"]}
                    if nh.get("descr"):
                        h["description"] = nh["descr"]
                    if nh.get("pref") is not None:
                        h["preference"] = int(nh["pref"])
                    if nh.get("type"):
                        h["type"] = nh["type"]
                    nhs.append(h)
                if nhs:
                    sr["next_hops"] = nhs
                routes.append(sr)
            if routes:
                nd["static_routes"] = routes
            nodes.append(nd)
        _set(npo, "nodes", nodes)
        _set(npo, "interface_profiles", ifp_by_np.get(np["dn"], []))
        # bgp peers loopback (bgpPeerP directement sous l3extLNodeP) [audit 2026-07-06]
        _set(npo, "bgp_peers", [_bgp_peer_entry(bp) for bp in peer_bind.get(np["dn"], [])])
        # bfd multihop : ref policy (bfdRsMhNodePol) + auth (bfdMhNodeP, key=secret omis)
        mhpol = mhpol_by_np.get(np["dn"] + "/bfdMhNodeP/rsMhNodePol")
        if mhpol and mhpol.get("tnBfdMhNodePolName"):
            npo["bfd_multihop_node_policy"] = mhpol["tnBfdMhNodePolName"]
        mh = mh_by_np.get(np["dn"])
        if mh and mh.get("type") and mh["type"] != "none":   # auth active (defaut none)
            b = {"type": mh["type"]}
            if mh.get("keyId") and mh["keyId"] != "1":
                b["key_id"] = int(mh["keyId"])
            npo["bfd_multihop_auth"] = b
        np_by_l3out[_parent(np["dn"])].append(npo)
    drl_by_l3out = {_parent(x["dn"]): x for x in apic.get_class("l3extDefaultRouteLeakP")}
    # blocs protocoles niveau L3Out [audit 2026-07-03]
    ospf_by_l3out  = {_parent(x["dn"]): x for x in apic.get_class("ospfExtP")}
    eigrp_by_l3out = {_parent(x["dn"]): x for x in apic.get_class("eigrpExtP")}
    pim_by_l3out   = {_parent(x["dn"]): x for x in apic.get_class("pimExtP")}
    bgp_l3out_dns  = {_parent(x["dn"]) for x in apic.get_class("bgpExtP")}
    ilk_by_l3out   = {_parent(x["dn"]): x for x in apic.get_class("l3extRsInterleakPol")}
    # route maps scoped L3Out (rtctrlProfile sous /out-) : import/export/route_maps [audit 2026-07-06]
    rmap_by_l3out = _by_parent(apic.get_class("rtctrlProfile"))
    rm_ctx = _by_parent(apic.get_class("rtctrlCtxP"))
    rm_scope = {x["dn"]: x for x in apic.get_class("rtctrlRsScopeToAttrP")}
    rm_subj = _by_parent(apic.get_class("rtctrlRsCtxPToSubjP"))
    l3outs = defaultdict(list)
    for l in apic.get_class("l3extOut"):
        if tn(l["dn"]) not in keep:
            continue
        vrf, dom = l3_vrf.get(l["dn"]), l3_dom.get(l["dn"])
        if not (vrf and dom):
            warnings.append(f"L3Out '{tn(l['dn'])}/{l['name']}' has no VRF/domain -> skipped")
            continue
        lo = obj("terraform-aci-l3out", "l3extOut", l); lo["vrf"] = vrf; lo["domain"] = dom
        # content = merge(...) non parsé par attr_map -> enrich attrs propres l3extOut [#60]
        if l.get("descr"):
            lo["description"] = l["descr"]
        if l.get("nameAlias"):
            lo["alias"] = l["nameAlias"]
        if l.get("targetDscp") and l["targetDscp"] != "unspecified":
            lo["target_dscp"] = l["targetDscp"]
        rtc = (l.get("enforceRtctrl") or "").split(",")
        if "import" in rtc:                          # défaut false
            lo["import_route_control_enforcement"] = True
        if "export" not in rtc:                      # défaut true (export présent par défaut)
            lo["export_route_control_enforcement"] = False
        if l.get("mplsEnabled") == "yes":            # sr_mpls (défaut false)
            lo["sr_mpls"] = True
        # bloc ospf (ospfExtP) : la presence du dict YAML active le protocole
        oe = ospf_by_l3out.get(l["dn"])
        if oe:
            ob = {"area": "backbone" if oe.get("areaId") in (None, "", "0.0.0.0")
                          else oe["areaId"]}
            if oe.get("areaCost") not in (None, "", "1"):
                ob["area_cost"] = int(oe["areaCost"])
            if oe.get("areaType") and oe["areaType"] != "regular":
                ob["area_type"] = oe["areaType"]
            ac = (oe.get("areaCtrl") or "").split(",")
            if "redistribute" not in ac:             # défaut true
                ob["area_control_redistribute"] = False
            if "summary" not in ac:                  # défaut true
                ob["area_control_summary"] = False
            if "suppress-fa" in ac:                  # défaut false
                ob["area_control_suppress_fa"] = True
            lo["ospf"] = ob
        # bloc eigrp (eigrpExtP)
        ee = eigrp_by_l3out.get(l["dn"])
        if ee and ee.get("asn"):
            lo["eigrp"] = {"asn": int(ee["asn"])}
        # pim (pimExtP) -> l3_multicast_ipv4
        if l["dn"] in pim_by_l3out:
            lo["l3_multicast_ipv4"] = True
        # interleak route map (l3extRsInterleakPol) : ref par nom
        ilk = ilk_by_l3out.get(l["dn"])
        if ilk and ilk.get("tnRtctrlProfileName"):
            lo["interleak_route_map"] = ilk["tnRtctrlProfileName"]
        # bgpExtP (BGP address family sur le L3Out) est DERIVE par le cablage NaC de
        # la presence de bgp_peers / multipod / sr_mpls : pas de cle YAML propre.
        # S'il existe SANS aucun de ces porteurs, NaC ne peut pas le representer.
        # Le module genere alors count=0 -> l'objet reste NON GERE par Terraform
        # (PAS detruit : aci_rest_managed ne touche pas un DN qu'il ne declare pas),
        # mais il n'apparaitra pas dans le YAML. On le signale pour info.
        if (l["dn"] in bgp_l3out_dns and not lo.get("sr_mpls")
                and "bgp_peers" not in json.dumps(np_by_l3out.get(l["dn"], []))):
            warnings.append(f"L3Out '{tn(l['dn'])}/{l['name']}': BGP active (bgpExtP) sans "
                            "bgp_peers -> non representable en NaC, reste non gere (non detruit)")
        # default route leak (l3extDefaultRouteLeakP) -> bloc default_route_leak_policy
        drl = drl_by_l3out.get(l["dn"])
        if drl:
            sc = (drl.get("scope") or "").split(",")
            lo["default_route_leak_policy"] = {
                "always": drl.get("always") == "yes",
                "criteria": drl.get("criteria"),
                "context_scope": "ctx" in sc,
                "outside_scope": "l3-out" in sc,
            }
        # route maps scoped L3Out : default-import -> import_route_map, default-export
        # -> export_route_map, autres -> route_maps[] [audit 2026-07-06]
        rmaps = []
        for prof in rmap_by_l3out.get(l["dn"], []):
            rm = {"name": prof["name"]}
            if prof.get("descr"):
                rm["description"] = prof["descr"]
            ctxs = _rtctrl_contexts(prof["dn"], rm_ctx, rm_scope, rm_subj)
            if ctxs:
                rm["contexts"] = ctxs
            if prof["name"] == "default-import":
                if prof.get("type") and prof["type"] != "global":   # defaut import = global
                    rm["type"] = prof["type"]
                rm.pop("name")
                lo["import_route_map"] = rm
            elif prof["name"] == "default-export":
                if prof.get("type") and prof["type"] != "global":
                    rm["type"] = prof["type"]
                rm.pop("name")
                lo["export_route_map"] = rm
            else:
                if prof.get("type") and prof["type"] != "combinable":  # defaut route_maps = combinable
                    rm["type"] = prof["type"]
                rmaps.append(rm)
        _set(lo, "route_maps", rmaps)
        _set(lo, "external_endpoint_groups", extepg_by_l3out.get(l["dn"], []))
        _set(lo, "node_profiles", np_by_l3out.get(l["dn"], []))
        l3outs[tn(l["dn"])].append(lo)

    pols = capture_tenant_policies(apic, keep)                # policies.* (BGP/OSPF/HSRP...)
    # hsrp-interface-policy (hsrpIfPol) : ctrl = join(concat(var.bfd_enable?["bfd"], var.use_bia?["bia"]))
    # MULTI-LIGNE dans le module -> attr_map (parse ligne/ligne) tronque l'expr. Reverse dédié. [#54]
    hsrp_ctrl = {(_seg(x["dn"], "tn"), x["name"]): x.get("ctrl", "") for x in apic.get_class("hsrpIfPol")}
    for t2, subs in pols.items():
        for o in subs.get("policies.hsrp_interface_policies", []):
            flags = hsrp_ctrl.get((t2, o["name"]), "").split(",")
            if "bfd" in flags:                                # défaut false
                o["bfd_enable"] = True
            if "bia" in flags:
                o["use_bia"] = True
    # endpoint-mac-tag-policy (fvEpMacTag) : bdName/ctxName ternaires + tags (tagTag) ; for_each sur
    # liste dérivée -> capture dédiée. bdName '*' <-> bridge_domain 'all' (+ ctxName=vrf). [#55]
    epmt = defaultdict(list)
    tags_by = _by_parent(apic.get_class("tagTag"))            # par fvEpMacTag DN
    for m in apic.get_class("fvEpMacTag"):
        t2 = _seg(m["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"mac": m["mac"]}
        bd = m.get("bdName", "")
        if bd == "*":
            o["bridge_domain"] = "all"
            if m.get("ctxName"):
                o["vrf"] = m["ctxName"]
        elif bd:
            o["bridge_domain"] = bd
        tags = [{"key": tg["key"], "value": tg.get("value", "")}
                for tg in tags_by.get(m["dn"], []) if tg.get("key")]
        if tags:
            o["tags"] = tags
        epmt[t2].append(o)
    for t2, lst in epmt.items():
        pols.setdefault(t2, {})["policies.endpoint_mac_tags"] = lst
    # endpoint-ip-tag-policy (fvEpIpTag) : ip + vrf (ctxName) + tags. Miroir IP de #55. [#61]
    epit = defaultdict(list)
    for m in apic.get_class("fvEpIpTag"):
        t2 = _seg(m["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"ip": m["ip"]}
        if m.get("ctxName"):
            o["vrf"] = m["ctxName"]
        tags = [{"key": tg["key"], "value": tg.get("value", "")}
                for tg in tags_by.get(m["dn"], []) if tg.get("key")]
        if tags:
            o["tags"] = tags
        epit[t2].append(o)
    for t2, lst in epit.items():
        pols.setdefault(t2, {})["policies.endpoint_ip_tags"] = lst
    # dhcp-relay-policy (dhcpRelayP owner=tenant) + providers (dhcpRsProv tDn epg/l3out). for_each
    # liste dérivée -> capture dédiée. Filtre scope tenant (les owner=infra sont uni/infra). [#66]
    prov_by = _by_parent(apic.get_class("dhcpRsProv"))
    dhcpr = defaultdict(list)
    for p in apic.get_class("dhcpRelayP"):
        t2 = _seg(p["dn"], "tn")
        if not t2 or t2 not in keep:                          # exclut owner=infra (uni/infra)
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        provs = []
        for rs in prov_by.get(p["dn"], []):
            pr = {"ip": rs.get("addr")}
            tdn = rs.get("tDn", "")
            mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", tdn)
            if mm:
                pr["type"] = "epg"
                pr["tenant"], pr["application_profile"], pr["endpoint_group"] = mm.groups()
            else:
                mm = re.search(r"tn-([^/]+)/out-([^/]+)/instP-(.+)$", tdn)
                if mm:
                    pr["type"] = "l3out"
                    pr["tenant"], pr["l3out"], pr["external_endpoint_group"] = mm.groups()
            provs.append(pr)
        if provs:
            o["providers"] = provs
        dhcpr[t2].append(o)
    for t2, lst in dhcpr.items():
        pols.setdefault(t2, {})["policies.dhcp_relay_policies"] = lst
    # dhcp-option-policy (dhcpOptionPol) + options (dhcpOption id/data/name). [#66]
    opt_by = _by_parent(apic.get_class("dhcpOption"))
    dhcpo = defaultdict(list)
    for p in apic.get_class("dhcpOptionPol"):
        t2 = _seg(p["dn"], "tn")
        if not t2 or t2 not in keep:
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        opts = []
        for op in opt_by.get(p["dn"], []):
            oo = {"name": op["name"]}
            if op.get("id") and op["id"] != "0":
                oo["id"] = int(op["id"])
            if op.get("data"):
                oo["data"] = op["data"]
            opts.append(oo)
        if opts:
            o["options"] = opts
        dhcpo[t2].append(o)
    for t2, lst in dhcpo.items():
        pols.setdefault(t2, {})["policies.dhcp_option_policies"] = lst
    # ip-sla monitoring policy (fvIPSLAMonitoringPol) : le moteur générique ne mappe que `name`
    # (content = merge(...) non parsable par attr_map) -> capture dédiée, écrase l'entrée partielle.
    ipsla = defaultdict(list)
    for p in apic.get_class("fvIPSLAMonitoringPol"):
        t2 = _seg(p["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        if p.get("slaType") and p["slaType"] != "icmp":          # défaut icmp
            o["sla_type"] = p["slaType"]
        if p.get("slaDetectMultiplier") and p["slaDetectMultiplier"] != "3":   # défaut 3
            o["multiplier"] = int(p["slaDetectMultiplier"])
        if p.get("slaFrequency") and p["slaFrequency"] != "60":  # défaut 60
            o["frequency"] = int(p["slaFrequency"])
        if p.get("slaPort") and p["slaPort"] != "0":             # défaut 0
            o["port"] = int(p["slaPort"])
        if p.get("slaType") == "http":                            # champs http seulement si type http
            if p.get("httpMethod"):  o["http_method"] = p["httpMethod"]
            if p.get("httpVersion"): o["http_version"] = p["httpVersion"]
            if p.get("httpUri"):     o["http_uri"] = p["httpUri"]
        ipsla[t2].append(o)
    for t2, lst in ipsla.items():
        pols.setdefault(t2, {})["policies.ip_sla_policies"] = lst
    # track-member (fvTrackMember) + track-list (fvTrackList) -> tenant.policies.*  [modules #34/#33]
    # NON couverts par le moteur générique : leur module pointe local.track_lists (liste dérivée),
    # pas le flatten _raw -> _tenant_flat_table ne les associe pas. Capture dédiée + enfants/refs.
    ipsla_ref = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("fvRsIpslaMonPol")}
    for tm in apic.get_class("fvTrackMember"):
        t2 = _seg(tm["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"name": tm["name"]}
        if tm.get("descr"):
            o["description"] = tm["descr"]
        if tm.get("dstIpAddr"):
            o["destination_ip"] = tm["dstIpAddr"]
        sd = tm.get("scopeDn", "")
        mm = re.search(r"/out-(.+)$", sd)
        if mm:
            o["scope_type"] = "l3out"; o["scope"] = mm.group(1)
        else:
            mm = re.search(r"/BD-(.+)$", sd)
            if mm:
                o["scope_type"] = "bd"; o["scope"] = mm.group(1)
        mm = re.search(r"ipslaMonitoringPol-(.+)$", ipsla_ref.get(tm["dn"], ""))
        if mm:
            o["ip_sla_policy"] = mm.group(1)
        pols.setdefault(t2, {}).setdefault("policies.track_members", []).append(o)
    members_by_list = _by_parent(apic.get_class("fvRsOtmListMember"))   # track list DN -> relations
    for tl in apic.get_class("fvTrackList"):
        t2 = _seg(tl["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"name": tl["name"]}
        if tl.get("descr"):
            o["description"] = tl["descr"]
        if tl.get("type") and tl["type"] != "percentage":         # défaut percentage
            o["type"] = tl["type"]
        for fld, key, dflt in (("percentageUp", "percentage_up", "1"),
                               ("percentageDown", "percentage_down", "0"),
                               ("weightUp", "weight_up", "1"),
                               ("weightDown", "weight_down", "0")):
            if tl.get(fld) and tl[fld] != dflt:
                o[key] = int(tl[fld])
        mems = []
        for r in members_by_list.get(tl["dn"], []):
            mm = re.search(r"trackmember-(.+)$", r.get("tDn", ""))
            if mm:
                mems.append(mm.group(1))
        if mems:
            o["track_members"] = mems
        pols.setdefault(t2, {}).setdefault("policies.track_lists", []).append(o)
    out = list(system)
    # imported contracts (vzCPIf) : name + source (tenant/contract) via vzRsIf
    vzrsif = {_parent(x["dn"]): x for x in apic.get_class("vzRsIf")}   # cif DN -> rsif
    imported = defaultdict(list)
    for cif in apic.get_class("vzCPIf"):
        tnm = _seg(cif["dn"], "tn")
        if tnm not in keep:
            continue
        ic = {"name": cif["name"]}
        rs = vzrsif.get(cif["dn"])
        if rs and rs.get("tDn"):
            mm = re.search(r"tn-([^/]+)/brc-(.+)$", rs["tDn"])
            if mm:
                ic["tenant"] = mm.group(1); ic["contract"] = mm.group(2)
        if "contract" not in ic:            # sans source (vzRsIf) le module ne peut
            continue                        # PAS le creer (tenant/contract requis) -> ignore
        imported[tnm].append(ic)
    # oob contracts (vzOOBBrCP sous tn-mgmt) -> enrichit le tenant systeme mgmt
    oob = []
    for c in apic.get_class("vzOOBBrCP"):
        if _seg(c["dn"], "tn") != "mgmt" or c.get("name") == "default":
            continue
        o = {"name": c["name"]}
        if c.get("nameAlias"):
            o["alias"] = c["nameAlias"]
        if c.get("descr"):
            o["description"] = c["descr"]
        if c.get("scope") and c["scope"] != "context":      # defaut context
            o["scope"] = c["scope"]
        # subjects + filtres (memes classes vzSubj/vzRsSubjFiltAtt que les contrats
        # tenant, deja chargees) — sans eux le contrat OOB serait re-pousse VIDE
        # (trafic mgmt coupe) [audit 2026-07-03]
        subs = []
        for s in subjs.get(c["dn"], []):
            so = {"name": s["name"]}
            if s.get("nameAlias"):
                so["alias"] = s["nameAlias"]
            if s.get("descr"):
                so["description"] = s["descr"]
            _set(so, "filters", [_subj_filter_entry(rs) for rs in subjf.get(s["dn"], [])])
            subs.append(so)
        _set(o, "subjects", subs)
        oob.append(o)
    for s in system:
        if s["name"] == "mgmt" and oob:
            s["oob_contracts"] = oob
    # oob endpoint groups (mgmtOoB sous tn-mgmt) -> tenant mgmt.oob_endpoint_groups
    oob_prov = _by_parent(apic.get_class("mgmtRsOoBProv"))    # par mgmtOoB DN
    oob_sr = _by_parent(apic.get_class("mgmtStaticRoute"))    # par mgmtOoB DN
    ooepgs = []
    for e in apic.get_class("mgmtOoB"):
        if _seg(e["dn"], "tn") != "mgmt" or e.get("name") == "default":
            continue
        eo = {"name": e["name"]}
        prov = [r["tnVzOOBBrCPName"] for r in oob_prov.get(e["dn"], []) if r.get("tnVzOOBBrCPName")]
        if prov:
            eo["oob_contracts"] = {"providers": prov}     # bloc imbriqué (data model)
        sr = [r["prefix"] for r in oob_sr.get(e["dn"], []) if r.get("prefix")]
        if sr:
            eo["static_routes"] = sr
        ooepgs.append(eo)
    for s in system:
        if s["name"] == "mgmt" and ooepgs:
            s["oob_endpoint_groups"] = ooepgs
    # inband endpoint groups (mgmtInB sous tn-mgmt) -> tenant mgmt.inband_endpoint_groups
    inb_bd = {a["dn"].rsplit("/rsmgmtBD", 1)[0]: a.get("tnFvBDName")
              for a in apic.get_class("mgmtRsMgmtBD")}
    inb_sub = _by_parent(apic.get_class("fvSubnet"))
    inb_cons = _by_parent(apic.get_class("fvRsCons"))
    inb_prov = _by_parent(apic.get_class("fvRsProv"))
    inb_consif = _by_parent(apic.get_class("fvRsConsIf"))                  # [audit 2026-07-06]
    inb_route = _by_parent(apic.get_class("mgmtStaticRoute"))
    inbepgs = []
    for e in apic.get_class("mgmtInB"):
        if _seg(e["dn"], "tn") != "mgmt":
            continue
        eo = {"name": e["name"]}
        if e.get("encap", "").startswith("vlan-"):
            eo["vlan"] = int(e["encap"].replace("vlan-", ""))
        if inb_bd.get(e["dn"]):
            eo["bridge_domain"] = inb_bd[e["dn"]]
        subs = []
        for s2 in inb_sub.get(e["dn"], []):
            su = {"ip": s2["ip"]}
            if s2.get("descr"):
                su["description"] = s2["descr"]
            scope = (s2.get("scope") or "").split(",")            # scope public/shared [audit]
            if "public" in scope:                                 # defaut private (false)
                su["public"] = True
            if "shared" in scope:                                 # defaut false
                su["shared"] = True
            subs.append(su)
        if subs:
            eo["subnets"] = subs
        _set(eo, "static_routes", sorted(r["prefix"] for r in inb_route.get(e["dn"], []) if r.get("prefix")))
        cons = [r["tnVzBrCPName"] for r in inb_cons.get(e["dn"], []) if r.get("tnVzBrCPName")]
        prov = [r["tnVzBrCPName"] for r in inb_prov.get(e["dn"], []) if r.get("tnVzBrCPName")]
        consif = [r["tnVzCPIfName"] for r in inb_consif.get(e["dn"], []) if r.get("tnVzCPIfName")]
        if cons or prov or consif:
            eo["contracts"] = {}
            if cons:
                eo["contracts"]["consumers"] = cons
            if prov:
                eo["contracts"]["providers"] = prov
            if consif:
                eo["contracts"]["imported_consumers"] = consif
        inbepgs.append(eo)
    for s in system:
        if s["name"] == "mgmt" and inbepgs:
            s["inb_endpoint_groups"] = inbepgs
    # external mgmt instances (mgmtInstP sous tn-mgmt) -> tenant mgmt.ext_mgmt_instances
    ext_sub = _by_parent(apic.get_class("mgmtSubnet"))       # par mgmtInstP DN
    ext_cons = _by_parent(apic.get_class("mgmtRsOoBCons"))   # par mgmtInstP DN
    extmgmt = []
    for e in apic.get_class("mgmtInstP"):
        if _seg(e["dn"], "tn") != "mgmt":
            continue
        eo = {"name": e["name"]}
        subs = [s2["ip"] for s2 in ext_sub.get(e["dn"], []) if s2.get("ip")]
        if subs:
            eo["subnets"] = subs
        cons = [c["tnVzOOBBrCPName"] for c in ext_cons.get(e["dn"], []) if c.get("tnVzOOBBrCPName")]
        if cons:
            eo["oob_contracts"] = {"consumers": cons}
        extmgmt.append(eo)
    for s in system:
        if s["name"] == "mgmt" and extmgmt:
            s["ext_mgmt_instances"] = extmgmt
    # mpls custom qos (qosMplsCustomPol sous tn-infra) -> enrichit le tenant systeme
    # infra (patron mgmt #25). NB vxlan custom qos : classes qosVxlan* absentes en
    # 6.0(7e) (unresolved class) -> pas de capture. [#92]
    mpls_ing = _by_parent(apic.get_class("qosMplsIngressRule"))
    mpls_eg = _by_parent(apic.get_class("qosMplsEgressRule"))
    mplspols = []
    for p in apic.get_class("qosMplsCustomPol"):
        if _seg(p["dn"], "tn") != "infra" or p.get("name") == "default":
            continue
        po = {"name": p["name"]}
        if p.get("nameAlias"):
            po["alias"] = p["nameAlias"]
        if p.get("descr"):
            po["description"] = p["descr"]
        ing = []
        for r in mpls_ing.get(p["dn"], []):
            ro = {"exp_from": _num(r["from"]), "exp_to": _num(r["to"])}
            if r.get("prio") not in ("", None, "unspecified"):
                ro["priority"] = r["prio"]
            if r.get("target") not in ("", None, "unspecified"):
                ro["dscp_target"] = _num(r["target"])
            if r.get("targetCos") not in ("", None, "unspecified"):
                ro["cos_target"] = _num(r["targetCos"])
            ing.append(ro)
        _set(po, "ingress_rules", ing)
        eg = []
        for r in mpls_eg.get(p["dn"], []):
            ro = {"dscp_from": _num(r["from"]), "dscp_to": _num(r["to"])}
            if r.get("targetExp") not in ("", None, "unspecified"):
                ro["exp_target"] = _num(r["targetExp"])
            if r.get("targetCos") not in ("", None, "unspecified"):
                ro["cos_target"] = _num(r["targetCos"])
            eg.append(ro)
        _set(po, "egress_rules", eg)
        mplspols.append(po)
    for s in system:
        if s["name"] == "infra" and mplspols:
            s.setdefault("policies", {})["mpls_custom_qos_policies"] = mplspols
    # service redirect health groups (vnsRedirectHealthGroup) -> tenant.services.redirect_health_groups
    hgs = defaultdict(list)
    for hg in apic.get_class("vnsRedirectHealthGroup"):
        t2 = _seg(hg["dn"], "tn")
        if t2 not in keep:
            continue
        ho = {"name": hg["name"]}
        if hg.get("descr"):
            ho["description"] = hg["descr"]
        hgs[t2].append(ho)
    # service redirect policies (vnsSvcRedirectPol, PBR) -> tenant.services.redirect_policies
    rdest = _by_parent(apic.get_class("vnsRedirectDest"))      # par vnsSvcRedirectPol DN
    rhg = {_parent(x["dn"]): x.get("tDn") for x in apic.get_class("vnsRsRedirectHealthGroup")}  # par dest DN
    redir = defaultdict(list)
    for p in apic.get_class("vnsSvcRedirectPol"):
        t2 = _seg(p["dn"], "tn")
        if t2 not in keep:
            continue
        po = {"name": p["name"]}
        if p.get("descr"):
            po["description"] = p["descr"]
        if p.get("nameAlias"):
            po["alias"] = p["nameAlias"]
        if p.get("AnycastEnabled") == "yes":
            po["anycast"] = True
        if p.get("destType") and p["destType"] != "L3":
            po["type"] = p["destType"]
        if p.get("hashingAlgorithm") and p["hashingAlgorithm"] != "sip-dip-prototype":
            po["hashing"] = p["hashingAlgorithm"]
        if p.get("thresholdEnable") == "yes":
            po["threshold"] = True
        if p.get("maxThresholdPercent") and p["maxThresholdPercent"] != "0":
            po["max_threshold"] = int(p["maxThresholdPercent"])
        if p.get("minThresholdPercent") and p["minThresholdPercent"] != "0":
            po["min_threshold"] = int(p["minThresholdPercent"])
        if p.get("programLocalPodOnly") == "yes":
            po["pod_aware"] = True
        if p.get("resilientHashEnabled") == "yes":
            po["resilient_hashing"] = True
        if p.get("srcMacRewriteEnabled") == "yes":     # data model défaut null ; 'no'=auto-APIC -> ignoré
            po["rewrite_source_mac"] = True
        if p.get("thresholdDownAction") and p["thresholdDownAction"] != "permit":
            po["threshold_down_action"] = p["thresholdDownAction"]
        dests = []
        for d in rdest.get(p["dn"], []):
            de = {"ip": d["ip"]}
            if d.get("destName"):
                de["name"] = d["destName"]
            if d.get("descr"):
                de["description"] = d["descr"]
            if d.get("mac") and d["mac"] != "00:00:00:00:00:00":
                de["mac"] = d["mac"]
            if d.get("ip2") and d["ip2"] != "0.0.0.0":
                de["ip_2"] = d["ip2"]
            hgref = rhg.get(d["dn"])
            if hgref:
                mm = re.search(r"redirectHealthGroup-(.+)$", hgref)
                if mm:
                    de["redirect_health_group"] = mm.group(1)
            dests.append(de)
        if dests:
            po["l3_destinations"] = dests
        redir[t2].append(po)
    # service redirect BACKUP policies (vnsBackupPol) -> tenant.services.redirect_backup_policies  [module #31]
    # même structure que redirect_policies mais : objet plat (name/descr) + clé dest = destination_name
    bkp = defaultdict(list)
    for p in apic.get_class("vnsBackupPol"):
        t2 = _seg(p["dn"], "tn")
        if t2 not in keep:
            continue
        po = {"name": p["name"]}
        if p.get("descr"):
            po["description"] = p["descr"]
        dests = []
        for d in rdest.get(p["dn"], []):                       # rdest groupe vnsRedirectDest par parent DN
            de = {"ip": d["ip"]}
            if d.get("destName"):
                de["destination_name"] = d["destName"]         # clé destination_name (≠ redirect_policies)
            if d.get("descr"):
                de["description"] = d["descr"]
            if d.get("mac") and d["mac"] != "00:00:00:00:00:00":
                de["mac"] = d["mac"]
            if d.get("ip2") and d["ip2"] != "0.0.0.0":
                de["ip_2"] = d["ip2"]
            hgref = rhg.get(d["dn"])
            if hgref:
                mm = re.search(r"redirectHealthGroup-(.+)$", hgref)
                if mm:
                    de["redirect_health_group"] = mm.group(1)
            dests.append(de)
        if dests:
            po["l3_destinations"] = dests
        bkp[t2].append(po)
    # service EPG policies (vnsSvcEPgPol) -> tenant.services.service_epg_policies  [module #32]
    svcepg = defaultdict(list)
    for p in apic.get_class("vnsSvcEPgPol"):
        t2 = _seg(p["dn"], "tn")
        if t2 not in keep:
            continue
        po = {"name": p["name"]}
        if p.get("descr"):
            po["description"] = p["descr"]
        if p.get("prefGrMemb") == "include":          # défaut = exclude (preferred_group false)
            po["preferred_group"] = True
        svcepg[t2].append(po)
    # ── L4L7 PHYSICAL [#107-#109] : l4l7-device + service-graph-template (mode
    # single-device) + device-selection-policy. Objets logiques purs (aucun
    # deploiement requis). VIRTUAL/vmm + multi-device NON captures (hors sim).
    cdevs = _by_parent(apic.get_class("vnsCDev"))
    cifs = _by_parent(apic.get_class("vnsCIf"))
    cpaths = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsCIfPathAtt")}
    lifs = _by_parent(apic.get_class("vnsLIf"))
    liftgts = _by_parent(apic.get_class("vnsRsCIfAttN"))
    physdom = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsALDevToPhysDomP")}
    vmmdom = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsALDevToDomP")}  # VMM [audit 2026-07-06]
    ldevs = defaultdict(list)
    for d in apic.get_class("vnsLDevVip"):
        t2 = _seg(d["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"name": d["name"]}
        if d.get("nameAlias"):
            o["alias"] = d["nameAlias"]
        if d.get("contextAware") and d["contextAware"] != "single-Context":
            o["context_aware"] = d["contextAware"]
        if d.get("devtype") and d["devtype"] != "PHYSICAL":
            o["type"] = d["devtype"]
        if d.get("funcType") and d["funcType"] != "GoTo":
            o["function"] = d["funcType"]
        if d.get("isCopy") == "yes":
            o["copy_device"] = True
        if d.get("managed") == "yes":
            o["managed"] = True
        if d.get("promMode") == "yes":
            o["promiscuous_mode"] = True
        if d.get("svcType") and d["svcType"] != "FW":
            o["service_type"] = d["svcType"]
        if d.get("trunking") == "yes":
            o["trunking"] = True
        if d.get("activeActive") == "yes":
            o["active_active"] = True
        if physdom.get(d["dn"]):
            o["physical_domain"] = physdom[d["dn"]].replace("uni/phys-", "")
        # VMM domain (device VIRTUAL) : uni/vmmp-<provider>/dom-<domain> [audit 2026-07-06]
        mm = re.search(r"uni/vmmp-([^/]+)/dom-(.+)$", vmmdom.get(d["dn"], ""))
        if mm:
            o["vmm_provider"], o["vmm_domain"] = mm.group(1), mm.group(2)
        cl = []
        for c in cdevs.get(d["dn"], []):
            co = {"name": c["name"]}
            if c.get("nameAlias"):
                co["alias"] = c["nameAlias"]
            if c.get("vcenterName"):                          # device VIRTUAL/VMM
                co["vcenter_name"] = c["vcenterName"]
            if c.get("vmName"):
                co["vm_name"] = c["vmName"]
            il = []
            for ci in cifs.get(c["dn"], []):
                io = {"name": ci["name"]}
                if ci.get("nameAlias"):
                    io["alias"] = ci["nameAlias"]
                if ci.get("vnicName"):                        # interface VM (VMM)
                    io["vnic_name"] = ci["vnicName"]
                if ci.get("encap", "").startswith("vlan-"):   # vlan (active_active)
                    io["vlan"] = int(ci["encap"].replace("vlan-", ""))
                pe = _span_path_entry(cpaths.get(ci["dn"], ""))  # port/PC/vPC/FEX/sub-port
                if pe:
                    if pe.get("pod_id") == 1:
                        pe.pop("pod_id")                      # defaut 1 omis
                    io.update(pe)
                il.append(io)
            _set(co, "interfaces", il)
            cl.append(co)
        _set(o, "concrete_devices", cl)
        ll = []
        for li in lifs.get(d["dn"], []):
            lo = {"name": li["name"]}
            if li.get("nameAlias"):                            # [audit 2026-07-06]
                lo["alias"] = li["nameAlias"]
            if li.get("encap", "").startswith("vlan-"):
                lo["vlan"] = int(li["encap"].replace("vlan-", ""))
            cil = []
            for x in liftgts.get(li["dn"], []):
                mm = re.search(r"/cDev-([^/]+)/cIf-\[([^\]]+)\]", x.get("tDn", ""))
                if mm:
                    cil.append({"device": mm.group(1), "interface_name": mm.group(2)})
            _set(lo, "concrete_interfaces", cil)
            ll.append(lo)
        _set(o, "logical_interfaces", ll)
        ldevs[t2].append(o)
    absnodes = _by_parent(apic.get_class("vnsAbsNode"))
    node2dev = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsNodeToLDev")}
    absconns = _by_parent(apic.get_class("vnsAbsConnection"))   # adjacency/direct_connect [audit 2026-07-06]
    sgts = defaultdict(list)
    for g in apic.get_class("vnsAbsGraph"):
        t2 = _seg(g["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        if g.get("nameAlias"):
            o["alias"] = g["nameAlias"]
        nl = absnodes.get(g["dn"], [])
        if len(nl) == 1:                                     # mode single-device
            n = nl[0]
            if n.get("funcTemplateType") and n["funcTemplateType"] != "FW_ROUTED":
                o["template_type"] = n["funcTemplateType"]
            if n.get("routingMode") == "Redirect":
                o["redirect"] = True
            if n.get("shareEncap") == "yes":
                o["share_encapsulation"] = True
            dev = {}
            mm = re.search(r"tn-([^/]+)/lDevVip-(.+)$", node2dev.get(n["dn"], ""))
            if mm:
                dev["name"] = mm.group(2)
                if mm.group(1) != t2:
                    dev["tenant"] = mm.group(1)
            if n.get("name") and n["name"] != "N1":
                dev["node_name"] = n["name"]
            if dev:
                o["device"] = dev
            # attrs single-device restants [audit 2026-07-06]
            if n.get("funcType") and n["funcType"] != "GoTo":
                o["device_function"] = n["funcType"]
            if n.get("isCopy") == "yes":
                o["device_copy"] = True
            if n.get("managed") == "yes":
                o["device_managed"] = True
            # connections C1 (consumer) / C2 (provider) : adjType + directConnect
            for cn2 in absconns.get(g["dn"], []):
                if cn2.get("adjType") and cn2["adjType"] != "L3":   # defaut L3
                    o["device_adjacency_type"] = cn2["adjType"]
                if cn2.get("directConnect") == "yes":               # defaut no
                    key = ("consumer_direct_connect" if cn2.get("name") == "C1"
                           else "provider_direct_connect")
                    o[key] = True
        elif len(nl) > 1:                                    # multi-device : non capture
            warnings.append(f"service-graph-template '{g['name']}' ({t2}): mode "
                            "multi-device non capture -> a completer a la main")
        sgts[t2].append(o)
    lifctxs = _by_parent(apic.get_class("vnsLIfCtx"))
    ctx2lif = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsLIfCtxToLIf")}
    ctx2bd = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsLIfCtxToBD")}
    ctx2rp = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsLIfCtxToSvcRedirectPol")}
    ctx2instp = {_parent(x["dn"]): x for x in apic.get_class("vnsRsLIfCtxToInstP")}
    ctx2svcepg = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsLIfCtxToSvcEPgPol")}
    ctx2custqos = {_parent(x["dn"]): x for x in apic.get_class("vnsRsLIfCtxToCustQosPol")}

    def _dsp_side(lc, t2):
        """vnsLIfCtx -> bloc consumer/provider/copy du data model DSP [audit 2026-07-06]."""
        so = {}
        mm = re.search(r"/(?:lIf|lDevIfLIf)-(.+)$", ctx2lif.get(lc["dn"], ""))
        if mm:
            so["logical_interface"] = mm.group(1)
        mm = re.search(r"tn-([^/]+)/BD-(.+)$", ctx2bd.get(lc["dn"], ""))
        if mm:
            so["bridge_domain"] = {"name": mm.group(2)}
            if mm.group(1) != t2:
                so["bridge_domain"]["tenant"] = mm.group(1)
        mm = re.search(r"tn-([^/]+)/svcCont/svcRedirectPol-(.+)$", ctx2rp.get(lc["dn"], ""))
        if mm:
            so["redirect_policy"] = {"name": mm.group(2)}
            if mm.group(1) != t2:
                so["redirect_policy"]["tenant"] = mm.group(1)
        # external endpoint group (vnsRsLIfCtxToInstP) + redistribute flags
        ip = ctx2instp.get(lc["dn"])
        if ip and ip.get("tDn"):
            mm = re.search(r"tn-([^/]+)/out-([^/]+)/instP-(.+)$", ip["tDn"])
            if mm:
                eeg = {"name": mm.group(3), "l3out": mm.group(2)}
                if mm.group(1) != t2:
                    eeg["tenant"] = mm.group(1)
                rd = set((ip.get("redistribute") or "").split(","))
                rmap = {k: k in rd for k in ("bgp", "ospf", "connected", "static")}
                if any(rmap.values()):
                    eeg["redistribute"] = {k: v for k, v in rmap.items() if v}
                so["external_endpoint_group"] = eeg
        # service epg policy (vnsRsLIfCtxToSvcEPgPol) : string (toujours same-tenant)
        mm = re.search(r"/svcCont/svcEPgPol-(.+)$", ctx2svcepg.get(lc["dn"], ""))
        if mm:
            so["service_epg_policy"] = mm.group(1)
        cq = ctx2custqos.get(lc["dn"])
        if cq and cq.get("tnQosCustomPolName"):
            so["custom_qos_policy"] = cq["tnQosCustomPolName"]
        if lc.get("l3Dest") == "no":                     # defaut true
            so["l3_destination"] = False
        if lc.get("permitLog") == "yes":                 # defaut false
            so["permit_logging"] = True
        return so

    dsps = defaultdict(list)
    for c in apic.get_class("vnsLDevCtx"):
        t2 = _seg(c["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"contract": c.get("ctrctNameOrLbl"),
             "service_graph_template": c.get("graphNameOrLbl")}
        if c.get("nodeNameOrLbl") and c["nodeNameOrLbl"] != "N1":
            o["node_name"] = c["nodeNameOrLbl"]
        multi = False
        for lc in lifctxs.get(c["dn"], []):
            side = lc.get("connNameOrLbl")
            if side in ("consumer", "provider", "copy"):
                so = _dsp_side(lc, t2)
                if side == "copy":            # bloc copy = copy_service dans le data model
                    if so:
                        o["copy_service"] = so
                elif so:
                    o[side] = so
            else:
                multi = True                  # side nomme != std -> mode multi-device
        if multi:
            warnings.append(f"device-selection-policy '{c.get('ctrctNameOrLbl')}': mode "
                            "multi-device (devices[]) non capture -> a completer a la main")
        dsps[t2].append(o)
    for name, t in tenants.items():
        _set(t, "vrfs", vrfs[name]); _set(t, "bridge_domains", bds[name])
        _set(t, "application_profiles", aps[name]); _set(t, "filters", filters[name])
        _set(t, "contracts", contracts[name]); _set(t, "l3outs", l3outs[name])
        _set(t, "imported_contracts", imported[name])
        svc = {}
        if hgs[name]:
            svc["redirect_health_groups"] = hgs[name]
        if redir[name]:
            svc["redirect_policies"] = redir[name]
        if bkp[name]:
            svc["redirect_backup_policies"] = bkp[name]
        if svcepg[name]:
            svc["service_epg_policies"] = svcepg[name]
        if ldevs[name]:
            svc["l4l7_devices"] = ldevs[name]
        if sgts[name]:
            svc["service_graph_templates"] = sgts[name]
        if dsps[name]:
            svc["device_selection_policies"] = dsps[name]
        if svc:
            t["services"] = svc
        for sub, objs in pols.get(name, {}).items():          # place a tenant.<subpath>
            node = t
            for p in sub.split(".")[:-1]:
                node = node.setdefault(p, {})
            node[sub.split(".")[-1]] = objs
        out.append(t)
    return out

# ═══════════════════════════════════════════════════════ ecriture YAML
def _write_section(filename, top_key, payload, comment, extra_apic=None):
    import yaml
    path = os.path.join(DATA_DIR, filename)
    existing = {}
    if os.path.isfile(path):
        existing = yaml.safe_load(open(path)) or {}
    apic = dict(extra_apic) if extra_apic else {}
    # REMPLACEMENT COMPLET de la section (pas de merge) : la capture est une PHOTO
    # de la fabric. L'ancien merge superficiel laissait survivre des cles perimees
    # quand la fabric avait perdu des objets (ex : fabric remise a vide) -> data/
    # incoherent, erreurs d'evaluation terraform (Invalid index). [bug corrige 2026-07-02]
    apic[top_key] = payload
    head = (f"# {comment}\n# Generated by tools/nac.py on {datetime.date.today()} "
            f"(read-only). Check with `nac.py plan` before `sync`.\n")
    with open(path, "w") as f:
        f.write(head + "---\n" + yaml.safe_dump({"apic": apic}, sort_keys=False, allow_unicode=True))
    return os.path.relpath(path, ROOT)

# ═══════════════════════════════════════════════════════ sous-commandes
def _deep_merge(dst, src):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        elif isinstance(v, list) and isinstance(dst.get(k), list):
            names = {o.get("name") for o in dst[k] if isinstance(o, dict)}
            dst[k].extend(o for o in v if not (isinstance(o, dict) and o.get("name") in names))
        else:
            dst[k] = v

def capture_leaf_selectors(apic: Apic):
    """Sélecteurs d'interface (infraHPortS) par leaf interface profile (nom).
    Exclut les profils système (system-port-profile-node-X, auto-générés)."""
    base = {x["dn"]: x for x in apic.get_class("infraRsAccBaseGrp")}    # <hps>/rsaccBaseGrp -> policy_group
    blks = _by_parent(apic.get_class("infraPortBlk"))                   # port blocks par infraHPortS DN
    out = defaultdict(list)
    for hp in apic.get_class("infraHPortS"):
        prof = _seg(hp["dn"], "accportprof")
        if not prof or prof.startswith("system-"):
            continue
        sel = {"name": hp["name"]}
        if hp.get("descr"):
            sel["description"] = hp["descr"]
        bg = base.get(hp["dn"] + "/rsaccBaseGrp")
        if bg and bg.get("tDn"):
            mm = re.search(r"funcprof/(accportgrp|accbundle|brkoutportgrp)-(.+)$", bg["tDn"])
            if mm:
                sel["policy_group_type"] = {"accportgrp": "access", "brkoutportgrp": "breakout"}.get(mm.group(1), "pc")
                sel["policy_group"] = mm.group(2)
        pblks = []
        for b in blks.get(hp["dn"], []):
            pb = {"name": b["name"], "from_port": int(b["fromPort"])}
            if b.get("descr"):
                pb["description"] = b["descr"]
            if b.get("fromCard") and b["fromCard"] != "1":            # defaut 1
                pb["from_module"] = int(b["fromCard"])
            if b.get("toCard") and b["toCard"] != b.get("fromCard", "1"):  # defaut = from_module
                pb["to_module"] = int(b["toCard"])
            if b.get("toPort") and b["toPort"] != b["fromPort"]:      # defaut = from_port
                pb["to_port"] = int(b["toPort"])
            pblks.append(pb)
        if pblks:
            sel["port_blocks"] = pblks
        out[prof].append(sel)
    return out

def capture_fex_profiles(apic: Apic):
    """fex interface profiles (infraFexP ; infraFexBndlGrp homonyme implicite) +
    selecteurs (infraHPortS sous fexprof-, miroir de capture_leaf_selectors) +
    port_blocks. Le type du policy_group vient de la definition du PG dans data
    (lookup cablage), pas du selecteur. -> access_policies.fex_interface_profiles.
    [#102-#103]"""
    base = {x["dn"]: x for x in apic.get_class("infraRsAccBaseGrp")}
    blks = _by_parent(apic.get_class("infraPortBlk"))
    sels = defaultdict(list)
    for hp in apic.get_class("infraHPortS"):
        prof = _seg(hp["dn"], "fexprof")
        if not prof:
            continue
        sel = {"name": hp["name"]}
        if hp.get("descr"):
            sel["description"] = hp["descr"]
        bg = base.get(hp["dn"] + "/rsaccBaseGrp")
        if bg and bg.get("tDn"):
            mm = re.search(r"funcprof/(?:accportgrp|accbundle)-(.+)$", bg["tDn"])
            if mm:
                sel["policy_group"] = mm.group(1)
        pblks = []
        for b in blks.get(hp["dn"], []):
            pb = {"name": b["name"], "from_port": int(b["fromPort"])}
            if b.get("descr"):
                pb["description"] = b["descr"]
            if b.get("fromCard") and b["fromCard"] != "1":
                pb["from_module"] = int(b["fromCard"])
            if b.get("toCard") and b["toCard"] != b.get("fromCard", "1"):
                pb["to_module"] = int(b["toCard"])
            if b.get("toPort") and b["toPort"] != b["fromPort"]:
                pb["to_port"] = int(b["toPort"])
            pblks.append(pb)
        _set(sel, "port_blocks", pblks)
        sels[prof].append(sel)
    out = []
    for f in apic.get_class("infraFexP"):
        o = {"name": f["name"]}
        if sels.get(f["name"]):
            o["selectors"] = sels[f["name"]]
        out.append(o)
    return out

MACSEC_PSK_PLACEHOLDER = "AB12" * 16   # PSK write-only (ignore_changes), hex requis

def capture_secretful_policies(apic: Apic):
    """objets a secret write-only, geres SAUF leur secret (ignore_changes cote
    modules NaC) : remote_locations (fileRemotePath), key_rings (pkiKeyRing),
    macsec keychains (macsecKeyChainPol+macsecKeyPol, PSK=placeholder) et macsec
    interface policies (macsecIfPol/macsecFabIfPol, AUCUN secret). L'adoption de
    l'existant passe par `adopt` (le garde-fou SECRET_CLASSES bloque sync).
    [#113-#116]"""
    out = {}
    # remote locations — userPasswd/cles ssh JAMAIS captures (write-only)
    epgs = {_parent(r["dn"]): r.get("tDn", "")
            for r in apic.get_class("fileRsARemoteHostToEpg")
            if r.get("dn", "").startswith("uni/fabric/path-")}
    rls = []
    for p in apic.get_class("fileRemotePath"):
        o = {"name": p["name"], "hostname_ip": p.get("host"), "protocol": p.get("protocol")}
        if p.get("descr"):
            o["description"] = p["descr"]
        if p.get("authType") == "useSshKeyContents":
            o["auth_type"] = "ssh_keys"
        if p.get("remotePath") and p["remotePath"] != "/":
            o["path"] = p["remotePath"]
        if p.get("remotePort") not in (None, "", "0"):
            o["port"] = _num(p["remotePort"])
        if p.get("userName"):
            o["username"] = p["userName"]
        if "/oob-" in epgs.get(p["dn"], ""):
            o["mgmt_epg"] = "oob"
        rls.append(o)
    if rls:
        out["remote_locations"] = rls
    # key rings — cert/key JAMAIS captures ; exclut le keyring systeme (uid 0)
    krs = []
    for k in apic.get_class("pkiKeyRing"):
        if k.get("uid") == "0":
            continue
        o = {"name": k["name"]}
        if k.get("descr"):
            o["description"] = k["descr"]
        if k.get("tp"):
            o["ca_certificate"] = k["tp"]
        if k.get("modulus"):
            o["modulus"] = k["modulus"]
        krs.append(o)
    if krs:
        out["key_rings"] = krs
    # macsec keychains (access uni/infra + fabric uni/fabric) — PSK = placeholder
    keys_by = _by_parent(apic.get_class("macsecKeyPol"))
    kc_a, kc_f = [], []
    for c in apic.get_class("macsecKeyChainPol"):
        o = {"name": c["name"]}
        if c.get("descr"):
            o["description"] = c["descr"]
        kps = []
        for kp in keys_by.get(c["dn"], []):
            e = {"name": kp.get("name") or kp["keyName"], "key_name": kp["keyName"],
                 "pre_shared_key": MACSEC_PSK_PLACEHOLDER}
            if kp.get("descr"):
                e["description"] = kp["descr"]
            if kp.get("endTime") and kp["endTime"] != "infinite":
                e["end_time"] = kp["endTime"]
            kps.append(e)                         # start_time : ignore_changes, omis
        _set(o, "key_policies", kps)
        (kc_a if "/infra/" in c["dn"] else kc_f).append(o)
    if kc_a:
        out["macsec_keychain_access"] = kc_a
    if kc_f:
        out["macsec_keychain_fabric"] = kc_f
    # macsec interface policies — aucun secret (refs keychain + parameters)
    kc_ref = {_parent(r["dn"]): r.get("tDn", "") for r in apic.get_class("macsecRsToKeyChainPol")}
    pp_ref = {_parent(r["dn"]): r.get("tDn", "") for r in apic.get_class("macsecRsToParamPol")}
    mi_a, mi_f = [], []
    for cls, bucket in (("macsecIfPol", mi_a), ("macsecFabIfPol", mi_f)):
        rows = apic.try_class(cls)
        if rows is None:
            continue
        for p in rows:
            if p.get("uid") == "0" or p.get("name") == "default":   # policies systeme
                continue
            o = {"name": p["name"], "admin_state": p.get("adminSt") == "enabled"}
            if p.get("descr"):
                o["description"] = p["descr"]
            mm = re.search(r"keychainp-(.+)$", kc_ref.get(p["dn"], ""))
            if mm:
                o["macsec_keychain_policy"] = mm.group(1)
            mm = re.search(r"(?:paramp|fabparamp)-(.+)$", pp_ref.get(p["dn"], ""))
            if mm:
                o["macsec_parameters_policy"] = mm.group(1)
            bucket.append(o)
    if mi_a:
        out["macsec_if_access"] = mi_a
    if mi_f:
        out["macsec_if_fabric"] = mi_f
    return out

def capture_port_configurations(apic: Apic, warnings: list):
    """NOUVEAU paradigme d'interfaces (new_interface_configuration=true) :
    infraPortConfig / fabricPortConfig -> interface_policies.nodes[].interfaces[] ;
    infraNodeConfig / fabricNodeConfig -> node_policies.nodes[].{access,fabric}_policy_group.
    Retourne (ifaces_par_noeud, nodecfg_par_noeud, roles_par_noeud). Le role
    leaf/spine est requis par le cablage — SANS danger car aci_node_registration
    est DESACTIVE par defaut (DISABLE_MODULES). [#110-#112]"""
    ifaces, roles = defaultdict(list), {}
    for cls, is_fabric in (("infraPortConfig", False), ("fabricPortConfig", True)):
        for p in apic.get_class(cls):
            if p.get("subPort") not in (None, "", "0"):
                warnings.append(f"sub-port {p.get('dn')} non capture (sub_ports non supporte)")
                continue
            nid = int(p["node"])
            o = {"port": int(p["port"])}
            if p.get("card") and p["card"] != "1":
                o["module"] = int(p["card"])
            if is_fabric:
                o["fabric"] = True
            if p.get("description"):
                o["description"] = p["description"]
            if p.get("shutdown") == "yes":
                o["shutdown"] = True
            if not is_fabric and p.get("brkoutMap") and p["brkoutMap"] != "none":
                o["breakout"] = p["brkoutMap"]
            if not is_fabric and p.get("connectedFex") not in (None, "", "unspecified"):
                o["fex_id"] = int(p["connectedFex"])
            mm = re.search(r"/(?:accportgrp|accbundle|spaccportgrp|leportgrp|spportgrp)-(.+)$",
                           p.get("assocGrp", ""))
            if mm:
                o["policy_group"] = mm.group(1)
            if p.get("role"):
                roles[nid] = p["role"]
            ifaces[nid].append(o)
    nodecfg = {}
    for cls, key in (("infraNodeConfig", "access_policy_group"),
                     ("fabricNodeConfig", "fabric_policy_group")):
        for n in apic.get_class(cls):
            g = n.get("assocGrp", "")
            mm = re.search(r"/(?:accnodepgrp|spaccnodepgrp|lenodepgrp|spnodepgrp)-(.+)$", g)
            if mm:
                nid = int(n["node"])
                nodecfg.setdefault(nid, {})[key] = mm.group(1)
                roles.setdefault(nid, "spine" if ("spaccnodepgrp" in g or "spnodepgrp" in g) else "leaf")
    return ifaces, nodecfg, roles

def capture_node_addresses(apic: Apic, warnings: list):
    """adresses mgmt statiques (mgmtRsOoBStNode / mgmtRsInBStNode) -> node_policies
    {nodes: [{id, role: unspecified, oob_/inb_address...}], oob/inb_endpoint_group}.
    EXCLUT : node-1 (l'APIC lui-meme — son adresse OOB EST l'acces a la fabric) et
    tout noeud ENREGISTRE (fabricNode) : l'emettre exigerait role leaf/spine, ce qui
    declencherait node_registration + les profils switch auto. role: unspecified =
    sciemment HORS de tous les filtres for_each du cablage. [#104-#105]"""
    registered = set()
    for n in apic.get_class("fabricNode"):
        mm = re.search(r"node-(\d+)$", n.get("dn", ""))
        if mm:
            registered.add(int(mm.group(1)))
    nodes, epg = {}, {}
    for cls, key in (("mgmtRsOoBStNode", "oob"), ("mgmtRsInBStNode", "inb")):
        for r in apic.get_class(cls):
            mm = re.search(r"node-(\d+)\]", r.get("dn", ""))
            if not mm:
                continue
            nid = int(mm.group(1))
            if nid == 1:
                continue                                   # l'APIC : ne JAMAIS capturer
            if nid in registered:
                warnings.append(f"static mgmt address of REGISTERED node {nid} "
                                "not captured (would require leaf/spine role -> node_registration)")
                continue
            me = re.search(r"/(?:oob|inb)-([^/]+)/rs", r["dn"])
            if me:
                epg[key] = me.group(1)
            o = nodes.setdefault(nid, {"id": nid, "role": "unspecified"})
            if r.get("addr") and r["addr"] != "0.0.0.0":
                o[f"{key}_address"] = r["addr"]
            if r.get("gw") and r["gw"] != "0.0.0.0":
                o[f"{key}_gateway"] = r["gw"]
            if r.get("v6Addr") and r["v6Addr"] != "::":
                o[f"{key}_v6_address"] = r["v6Addr"]
            if r.get("v6Gw") and r["v6Gw"] != "::":
                o[f"{key}_v6_gateway"] = r["v6Gw"]
    out = {}
    for key, k2 in (("oob", "oob_endpoint_group"), ("inb", "inb_endpoint_group")):
        if epg.get(key) and epg[key] != "default":
            out[k2] = epg[key]
    if nodes:
        out["nodes"] = [nodes[k] for k in sorted(nodes)]
    return out

def capture_monitoring_policies(apic: Apic, pol_class="monInfraPol", target_class="monInfraTarget"):
    """monitoring policies (monInfraPol access / monFabricPol fabric) : name/descr +
    fault_severity_policies (<target> scope -> faultSevAsnP) + snmp_trap_policies
    (snmpSrc + snmpRsDestGroup) + syslog_policies (syslogSrc incl/minSev +
    syslogRsDestGroup). Exclut 'default'/'common'. [audit 2026-07-06]"""
    targets = _by_parent(apic.get_class(target_class))       # par <pol> DN
    faults = _by_parent(apic.get_class("faultSevAsnP"))       # par <target> DN
    snmpsrc = _by_parent(apic.get_class("snmpSrc"))          # par <pol> DN
    snmpdest = {_parent(x["dn"]): x for x in apic.get_class("snmpRsDestGroup")}
    slsrc = _by_parent(apic.get_class("syslogSrc"))          # par <pol> DN
    sldest = {_parent(x["dn"]): x for x in apic.get_class("syslogRsDestGroup")}
    out = []
    for mp in apic.get_class(pol_class):
        if mp.get("name") in ("default", "common"):
            continue
        po = {"name": mp["name"]}
        if mp.get("descr"):
            po["description"] = mp["descr"]
        # snmp trap policies (snmpSrc + dest group)
        snmps = []
        for s in snmpsrc.get(mp["dn"], []):
            e = {"name": s["name"]}
            d = snmpdest.get(s["dn"])
            if d and "/snmpgroup-" in d.get("tDn", ""):
                e["destination_group"] = d["tDn"].rsplit("/snmpgroup-", 1)[1]
            snmps.append(e)
        _set(po, "snmp_trap_policies", snmps)
        # syslog policies (syslogSrc incl flags + minSev + dest group) : helper partage
        _set(po, "syslog_policies", [_syslog_src_entry(s, sldest.get(s["dn"]))
                                     for s in slsrc.get(mp["dn"], [])])
        fsp = []
        for tg in targets.get(mp["dn"], []):
            flist = []
            for f in faults.get(tg["dn"], []):
                fd = {"fault_id": f["code"]}
                if f.get("initial") and f["initial"] != "inherit":
                    fd["initial_severity"] = f["initial"]
                if f.get("target") and f["target"] != "inherit":
                    fd["target_severity"] = f["target"]
                if f.get("descr"):
                    fd["description"] = f["descr"]
                flist.append(fd)
            if flist:
                fsp.append({"class": tg.get("scope"), "faults": flist})
        if fsp:
            po["fault_severity_policies"] = fsp
        out.append(po)
    return out

def capture_fabric_selectors(apic: Apic, sel_class, rs_class, rs_rn, prof_seg, pg_seg,
                             blk_class="fabricPortBlk"):
    """selecteurs d'interface FABRIC (leaf fabricLFPortS / spine fabricSFPortS) par
    profil. Miroir de capture_leaf_selectors, classes fabric. Exclut profils system-*.
    Réutilisé pour l'access spine (infraSHPortS) qui partage la structure mono-type-PG
    mais utilise infraPortBlk (passer blk_class)."""
    base = {x["dn"]: x for x in apic.get_class(rs_class)}   # -> policy_group
    blks = _by_parent(apic.get_class(blk_class))
    out = defaultdict(list)
    for hp in apic.get_class(sel_class):
        prof = _seg(hp["dn"], prof_seg)
        if not prof or prof.startswith("system-"):
            continue
        sel = {"name": hp["name"]}
        if hp.get("descr"):
            sel["description"] = hp["descr"]
        bg = base.get(hp["dn"] + "/" + rs_rn)
        if bg and bg.get("tDn"):
            mm = re.search(rf"{pg_seg}-(.+)$", bg["tDn"])
            if mm:
                sel["policy_group"] = mm.group(1)
        pblks = []
        for b in blks.get(hp["dn"], []):
            pb = {"name": b["name"], "from_port": int(b["fromPort"])}
            if b.get("descr"):
                pb["description"] = b["descr"]
            if b.get("fromCard") and b["fromCard"] != "1":
                pb["from_module"] = int(b["fromCard"])
            if b.get("toCard") and b["toCard"] != b.get("fromCard", "1"):
                pb["to_module"] = int(b["toCard"])
            if b.get("toPort") and b["toPort"] != b["fromPort"]:
                pb["to_port"] = int(b["toPort"])
            pblks.append(pb)
        if pblks:
            sel["port_blocks"] = pblks
        out[prof].append(sel)
    return out

def capture_span_filter_groups(apic: Apic):
    """span-filter-group (spanFilterGrp) + entries (spanFilterEntry) -> access_policies.span.filter_groups.
    PIÈGE : le module construit le DN de spanFilterEntry avec la valeur BRUTE (proto-${ip_protocol})
    mais le content avec le mot-clé (ipProto=tcp) ; APIC stocke le DN canonique en mots-clés
    (proto-tcp). Conséquence : la forme numérique ('6') est INSTABLE (le DN recalculé proto-6 ≠
    proto-tcp -> forces replacement). On capture donc la forme MOT-CLÉ telle que stockée par APIC
    (tcp/http/https…), qui round-trippe de façon stable (le data model l'accepte aussi)."""
    ents_by_grp = _by_parent(apic.get_class("spanFilterEntry"))
    out = []
    for g in apic.get_class("spanFilterGrp"):
        if not g["dn"].startswith("uni/infra/"):       # access only (uni/infra/filtergrp-)
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        ents = []
        for e in ents_by_grp.get(g["dn"], []):
            en = {}
            if e.get("name"):
                en["name"] = e["name"]
            if e.get("descr"):
                en["description"] = e["descr"]
            if e.get("srcAddr"):
                en["source_ip"] = e["srcAddr"]
            if e.get("dstAddr"):
                en["destination_ip"] = e["dstAddr"]
            if e.get("ipProto") and e["ipProto"] != "unspecified":
                en["ip_protocol"] = e["ipProto"]
            sfp, stp = e.get("srcPortFrom"), e.get("srcPortTo")
            if sfp and sfp != "unspecified":
                en["source_from_port"] = sfp
                if stp and stp != sfp:
                    en["source_to_port"] = stp
            dfp, dtp = e.get("dstPortFrom"), e.get("dstPortTo")
            if dfp and dfp != "unspecified":
                en["destination_from_port"] = dfp
                if dtp and dtp != dfp:
                    en["destination_to_port"] = dtp
            ents.append(en)
        if ents:
            o["entries"] = ents
        out.append(o)
    return out

def capture_span_destination_groups(apic: Apic, scope="uni/infra/"):
    """span-destination-group (spanDestGrp) -> {access|fabric}_policies.span.destination_groups.
    Variante ERSPAN-to-EPG (spanRsDestEpg) : tenant/ap/epg + ip/source_prefix + dscp/flow/mtu/ttl/ver.
    scope=uni/infra/ (access #37) ou uni/fabric/ (fabric #41) — la classe spanDestGrp est partagée."""
    dests = _by_parent(apic.get_class("spanDest"))                         # par spanDestGrp DN
    epg = {_parent(x["dn"]): x for x in apic.get_class("spanRsDestEpg")}   # par spanDest DN
    destpath = {_parent(x["dn"]): x for x in apic.get_class("spanRsDestPathEp")}  # [audit 2026-07-06]
    out = []
    for g in apic.get_class("spanDestGrp"):
        if not g["dn"].startswith(scope) or g.get("uid") == "0":         # scope + hors système
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        for d in dests.get(g["dn"], []):
            # destination ERSPAN-to-EPG OU port physique local
            pth = destpath.get(d["dn"])
            if pth:
                pe = _span_path_entry(pth.get("tDn", ""))
                if pe:
                    o.update(pe)
                    if pth.get("mtu") and pth["mtu"] != "1518":   # defaut 1518
                        o["mtu"] = int(pth["mtu"])
                break
            e = epg.get(d["dn"])
            if not e:
                continue
            mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", e.get("tDn", ""))
            if mm:
                o["tenant"], o["application_profile"], o["endpoint_group"] = mm.groups()
            if e.get("ip"):
                o["ip"] = e["ip"]
            if e.get("srcIpPrefix"):
                o["source_prefix"] = e["srcIpPrefix"]
            if e.get("dscp") and e["dscp"] != "unspecified":
                o["dscp"] = e["dscp"]
            if e.get("flowId") and e["flowId"] != "1":
                o["flow_id"] = int(e["flowId"])
            if e.get("mtu") and e["mtu"] != "1518":
                o["mtu"] = int(e["mtu"])
            if e.get("ttl") and e["ttl"] != "64":
                o["ttl"] = int(e["ttl"])
            vm = re.match(r"ver(\d+)", e.get("ver", ""))
            if vm and vm.group(1) != "2":                                  # défaut ver2
                o["version"] = int(vm.group(1))
            if e.get("verEnforced") == "yes":                              # défaut no
                o["enforce_version"] = True
            break                                                          # un seul spanDest par groupe
        out.append(o)
    return out

def capture_span_source_groups(apic: Apic):
    """access-span-source-group (spanSrcGrp) -> access_policies.span.source_groups. Classe AMBIGUË
    access(uni/infra)/fabric(uni/fabric) -> exclue du moteur plat, filtre uni/infra. name/desc +
    admin_state (adminSt enabled/disabled, défaut disabled) + filter_group (spanRsSrcGrpToFilterGrp,
    réf #36) + destination label (spanSpanLbl, réf dest group #37) + sources (spanSrc + EPG/L3Out)."""
    srcs = _by_parent(apic.get_class("spanSrc"))                              # par srcgrp DN
    srcepg = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcToEpg")}  # par spanSrc DN
    srcpath = _by_parent(apic.get_class("spanRsSrcToPathEp"))                 # par spanSrc DN [#audit]
    srcl3 = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcToL3extOut")}
    fgrp = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcGrpToFilterGrp")}  # par srcgrp DN
    lbl = _by_parent(apic.get_class("spanSpanLbl"))                           # par srcgrp DN
    out = []
    for g in apic.get_class("spanSrcGrp"):
        if not g["dn"].startswith("uni/infra/") or g.get("uid") == "0":      # access only, hors système
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        if g.get("adminSt") == "enabled":                    # défaut disabled (admin_state false)
            o["admin_state"] = True
        fg = fgrp.get(g["dn"])                               # fgrp indexé par parent (srcgrp DN)
        if fg:
            mm = re.search(r"filtergrp-(.+)$", fg.get("tDn", ""))
            if mm:
                o["filter_group"] = mm.group(1)
        for l in lbl.get(g["dn"], []):
            dest = {"name": l["name"]}
            if l.get("descr"):
                dest["description"] = l["descr"]
            o["destination"] = dest
            break
        sl = []
        for s in srcs.get(g["dn"], []):
            so = {"name": s["name"]}
            if s.get("descr"):
                so["description"] = s["descr"]
            if s.get("dir") and s["dir"] != "both":          # défaut both
                so["direction"] = s["dir"]
            if s.get("spanOnDrop") == "yes":                 # défaut no
                so["span_drop"] = True
            e = srcepg.get(s["dn"])
            if e:
                mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", e.get("tDn", ""))
                if mm:
                    so["tenant"], so["application_profile"], so["endpoint_group"] = mm.groups()
            l3 = srcl3.get(s["dn"])
            if l3:
                mm = re.search(r"tn-([^/]+)/out-(.+)$", l3.get("tDn", ""))
                if mm:
                    so["tenant"], so["l3out"] = mm.group(1), mm.group(2)
                vm = re.match(r"vlan-(\d+)", l3.get("encap", ""))
                if vm:
                    so["vlan"] = int(vm.group(1))
            # access paths (ports physiques/PC/vPC/FEX) [audit 2026-07-06]
            aps = [pe for rs in srcpath.get(s["dn"], [])
                   if (pe := _span_path_entry(rs.get("tDn", ""))) is not None]
            _set(so, "access_paths", aps)
            sl.append(so)
        if sl:
            o["sources"] = sl
        out.append(o)
    return out

def capture_fabric_span_source_groups(apic: Apic):
    """fabric-span-source-group (spanSrcGrp uni/fabric) -> fabric_policies.span.source_groups.
    Diffère de l'access (#40) : pas de filter_group ; bindings source = VRF (spanRsSrcToCtx) /
    bridge_domain (spanRsSrcToBD) / fabric_paths (spanRsSrcToPathEp). admin_state défaut=enabled."""
    srcs = _by_parent(apic.get_class("spanSrc"))                             # par srcgrp DN
    ctx = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcToCtx")}    # par spanSrc DN
    bd = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcToBD")}
    lbl = _by_parent(apic.get_class("spanSpanLbl"))                          # par srcgrp DN
    out = []
    for g in apic.get_class("spanSrcGrp"):
        if not g["dn"].startswith("uni/fabric/") or g.get("uid") == "0":    # fabric only, hors système
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        if g.get("adminSt") == "disabled":                   # défaut enabled (admin_state true)
            o["admin_state"] = False
        for l in lbl.get(g["dn"], []):
            dest = {"name": l["name"]}
            if l.get("descr"):
                dest["description"] = l["descr"]
            o["destination"] = dest
            break
        sl = []
        for s in srcs.get(g["dn"], []):
            so = {"name": s["name"]}
            if s.get("descr"):
                so["description"] = s["descr"]
            if s.get("dir") and s["dir"] != "both":
                so["direction"] = s["dir"]
            if s.get("spanOnDrop") == "yes":
                so["span_drop"] = True
            c = ctx.get(s["dn"])
            if c:
                mm = re.search(r"tn-([^/]+)/ctx-(.+)$", c.get("tDn", ""))
                if mm:
                    so["tenant"], so["vrf"] = mm.groups()
            b = bd.get(s["dn"])
            if b:
                mm = re.search(r"tn-([^/]+)/BD-(.+)$", b.get("tDn", ""))
                if mm:
                    so["tenant"], so["bridge_domain"] = mm.groups()
            sl.append(so)
        if sl:
            o["sources"] = sl
        out.append(o)
    return out

def capture_vspan_destination_groups(apic: Apic):
    """vspan-destination-group (spanVDestGrp) -> access_policies.vspan.destination_groups.
    destinations (spanVDest) + ERSPAN summary (spanVEpgSummary: ip/dscp/flow/mtu/ttl) +
    éventuel vport (spanRsDestToVPort: tenant/ap/epg/endpoint)."""
    vdest = _by_parent(apic.get_class("spanVDest"))                          # par vdestgrp DN
    summ = {_parent(x["dn"]): x for x in apic.get_class("spanVEpgSummary")}  # par vdest DN
    vport = {_parent(x["dn"]): x for x in apic.get_class("spanRsDestToVPort")}
    out = []
    for g in apic.get_class("spanVDestGrp"):
        if not g["dn"].startswith("uni/infra/") or g.get("uid") == "0":  # access only, exclut défauts système (3 scopes)
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        dl = []
        for d in vdest.get(g["dn"], []):
            de = {"name": d["name"]}
            if d.get("descr"):
                de["description"] = d["descr"]
            s = summ.get(d["dn"])
            if s:
                if s.get("dstIp") and s["dstIp"] != "0.0.0.0":
                    de["ip"] = s["dstIp"]
                if s.get("dscp") and s["dscp"] != "unspecified":
                    de["dscp"] = s["dscp"]
                if s.get("flowId") and s["flowId"] != "1":
                    de["flow_id"] = int(s["flowId"])
                if s.get("mtu") and s["mtu"] != "1518":
                    de["mtu"] = int(s["mtu"])
                if s.get("ttl") and s["ttl"] != "64":
                    de["ttl"] = int(s["ttl"])
            vp = vport.get(d["dn"])
            if vp:
                mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-([^/]+)/cep-(.+)$", vp.get("tDn", ""))
                if mm:
                    de["tenant"], de["application_profile"], de["endpoint_group"], de["endpoint"] = mm.groups()
            dl.append(de)
        if dl:
            o["destinations"] = dl
        out.append(o)
    return out

def capture_vspan_sessions(apic: Apic):
    """vspan-session (spanVSrcGrp) -> access_policies.vspan.sessions. NON capté par le moteur plat
    (for_each sur liste dérivée local.vspan_sessions). name/descr + admin_state (adminSt start/stop,
    défaut start) + destination label (spanSpanLbl) + sources (spanVSrc + spanRsSrcToEpg)."""
    lbl = _by_parent(apic.get_class("spanSpanLbl"))                           # par vsrcgrp DN
    vsrc = _by_parent(apic.get_class("spanVSrc"))                             # par vsrcgrp DN
    srcepg = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcToEpg")}  # par vsrc DN
    out = []
    for g in apic.get_class("spanVSrcGrp"):
        if not g["dn"].startswith("uni/infra/") or g.get("uid") == "0":  # access only, exclut défauts système (3 scopes)
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        if g.get("adminSt") == "stop":                       # défaut start (admin_state true)
            o["admin_state"] = False
        for l in lbl.get(g["dn"], []):
            dest = {"name": l["name"]}
            if l.get("descr"):
                dest["description"] = l["descr"]
            o["destination"] = dest
            break
        srcs = []
        for s in vsrc.get(g["dn"], []):
            so = {"name": s["name"]}
            if s.get("descr"):
                so["description"] = s["descr"]
            if s.get("dir") and s["dir"] != "both":          # défaut both
                so["direction"] = s["dir"]
            e = srcepg.get(s["dn"])
            if e:
                mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", e.get("tDn", ""))
                if mm:
                    so["tenant"], so["application_profile"], so["endpoint_group"] = mm.groups()
            srcs.append(so)
        if srcs:
            o["sources"] = srcs
        out.append(o)
    return out

def capture_leaf_switch_profiles(apic: Apic):
    """access-leaf-switch-profile (infraNodeP) -> access_policies.leaf_switch_profiles. name +
    selectors (infraLeafS : name + policy via infraRsAccNodePGrp + node_blocks infraNodeBlk from/to)
    + interface_profiles (infraRsAccPortP). Exclut profils/sélecteurs system-*. Adopte le brownfield. [#50]"""
    leafs = _by_parent(apic.get_class("infraLeafS"))             # par nprof DN
    blks = _by_parent(apic.get_class("infraNodeBlk"))            # par leafS DN
    pg = {_parent(x["dn"]): x.get("tDn") for x in apic.get_class("infraRsAccNodePGrp")}  # par leafS DN
    ifp = defaultdict(list)
    for r in apic.get_class("infraRsAccPortP"):
        ifp[_parent(r["dn"])].append(r.get("tDn", ""))           # par nprof DN
    out = []
    for p in apic.get_class("infraNodeP"):
        name = _seg(p["dn"], "nprof")
        if not name or name.startswith("system-") or name == "default":
            continue
        o = {"name": p["name"]}
        sels = []
        for s in leafs.get(p["dn"], []):
            if s["name"].startswith("system-"):
                continue
            so = {"name": s["name"]}
            tdn = pg.get(s["dn"])
            if tdn:
                mm = re.search(r"accnodepgrp-(.+)$", tdn)
                if mm:
                    so["policy"] = mm.group(1)
            nbs = []
            for b in blks.get(s["dn"], []):
                if b["name"].startswith("system-"):
                    continue
                nb = {"name": b["name"], "from": _num(b["from_"])}
                if b.get("to_") and b["to_"] != b["from_"]:      # défaut = from
                    nb["to"] = _num(b["to_"])
                nbs.append(nb)
            if nbs:
                so["node_blocks"] = nbs
            sels.append(so)
        if sels:
            o["selectors"] = sels
        ifs = []
        for t in ifp.get(p["dn"], []):
            mm = re.search(r"accportprof-(.+)$", t)
            if mm and not mm.group(1).startswith("system-"):
                ifs.append(mm.group(1))
        if ifs:
            o["interface_profiles"] = ifs
        out.append(o)
    return out

def capture_leaf_switch_pgs(apic: Apic):
    """access-leaf-switch-policy-group (infraAccNodePGrp) -> access_policies.leaf_switch_policy_groups.
    name + refs policies (infraRs* -> tn*Name) : forwarding_scale/bfd_ipv4/bfd_ipv6/cdp/lldp. [#49]"""
    refs = [("infraRsTopoctrlFwdScaleProfPol", "tnTopoctrlFwdScaleProfilePolName", "forwarding_scale_policy"),
            ("infraRsBfdIpv4InstPol", "tnBfdIpv4InstPolName", "bfd_ipv4_policy"),
            ("infraRsBfdIpv6InstPol", "tnBfdIpv6InstPolName", "bfd_ipv6_policy"),
            ("infraRsLeafPGrpToCdpIfPol", "tnCdpIfPolName", "cdp_policy"),
            ("infraRsLeafPGrpToLldpIfPol", "tnLldpIfPolName", "lldp_policy")]
    relmaps = [(field, {_parent(x["dn"]): x.get(attr) for x in apic.get_class(cls)})
               for cls, attr, field in refs]
    out = []
    for g in apic.get_class("infraAccNodePGrp"):
        o = {"name": g["name"]}
        for field, m in relmaps:
            v = m.get(g["dn"])
            if v:                                            # tn*Name vide = pas de réf
                o[field] = v
        out.append(o)
    return out

def capture_spine_switch_pgs(apic: Apic):
    """access-spine-switch-policy-group (infraSpineAccNodePGrp) -> access_policies.spine_switch_policy_groups.
    Miroir spine de #49 : refs bfd_ipv4/bfd_ipv6/cdp/lldp (pas de forwarding_scale). [#51]"""
    refs = [("infraRsSpineBfdIpv4InstPol", "tnBfdIpv4InstPolName", "bfd_ipv4_policy"),
            ("infraRsSpineBfdIpv6InstPol", "tnBfdIpv6InstPolName", "bfd_ipv6_policy"),
            ("infraRsSpinePGrpToCdpIfPol", "tnCdpIfPolName", "cdp_policy"),
            ("infraRsSpinePGrpToLldpIfPol", "tnLldpIfPolName", "lldp_policy")]
    relmaps = [(field, {_parent(x["dn"]): x.get(attr) for x in apic.get_class(cls)})
               for cls, attr, field in refs]
    out = []
    for g in apic.get_class("infraSpineAccNodePGrp"):
        o = {"name": g["name"]}
        for field, m in relmaps:
            v = m.get(g["dn"])
            if v:
                o[field] = v
        out.append(o)
    return out

def capture_spine_switch_profiles(apic: Apic):
    """access-spine-switch-profile (infraSpineP) -> access_policies.spine_switch_profiles. Miroir spine
    de #50 : selectors (infraSpineS) + policy (infraRsSpineAccNodePGrp) + node_blocks (infraNodeBlk) +
    interface_profiles (infraRsSpAccPortP -> spaccportprof). Exclut profils/sélecteurs system-*. [#51]"""
    sels_by = _by_parent(apic.get_class("infraSpineS"))                     # par spprof DN
    blks = _by_parent(apic.get_class("infraNodeBlk"))                       # par spineS DN
    pg = {_parent(x["dn"]): x.get("tDn") for x in apic.get_class("infraRsSpineAccNodePGrp")}
    ifp = defaultdict(list)
    for r in apic.get_class("infraRsSpAccPortP"):
        ifp[_parent(r["dn"])].append(r.get("tDn", ""))                      # par spprof DN
    out = []
    for p in apic.get_class("infraSpineP"):
        name = _seg(p["dn"], "spprof")
        if not name or name.startswith("system-") or name == "default":   # spprof-default = système (uid=0)
            continue
        o = {"name": p["name"]}
        sels = []
        for s in sels_by.get(p["dn"], []):
            if s["name"].startswith("system-"):
                continue
            so = {"name": s["name"]}
            tdn = pg.get(s["dn"])
            if tdn:
                mm = re.search(r"spaccnodepgrp-(.+)$", tdn)
                if mm:
                    so["policy"] = mm.group(1)
            nbs = []
            for b in blks.get(s["dn"], []):
                if b["name"].startswith("system-"):
                    continue
                nb = {"name": b["name"], "from": _num(b["from_"])}
                if b.get("to_") and b["to_"] != b["from_"]:
                    nb["to"] = _num(b["to_"])
                nbs.append(nb)
            if nbs:
                so["node_blocks"] = nbs
            sels.append(so)
        if sels:
            o["selectors"] = sels
        ifs = []
        for t in ifp.get(p["dn"], []):
            mm = re.search(r"spaccportprof-(.+)$", t)
            if mm and not mm.group(1).startswith("system-"):
                ifs.append(mm.group(1))
        if ifs:
            o["interface_profiles"] = ifs
        out.append(o)
    return out

def capture_fabric_leaf_switch_pgs(apic: Apic):
    """fabric-leaf-switch-policy-group (fabricLeNodePGrp) -> fabric_policies.leaf_switch_policy_groups.
    refs psu_policy (fabricRsPsuInstPol) + node_control_policy (fabricRsNodeCtrl). [#52]"""
    refs = [("fabricRsPsuInstPol", "tnPsuInstPolName", "psu_policy"),
            ("fabricRsNodeCtrl", "tnFabricNodeControlName", "node_control_policy")]
    relmaps = [(field, {_parent(x["dn"]): x.get(attr) for x in apic.get_class(cls)})
               for cls, attr, field in refs]
    out = []
    for g in apic.get_class("fabricLeNodePGrp"):
        o = {"name": g["name"]}
        for field, m in relmaps:
            v = m.get(g["dn"])
            if v:
                o[field] = v
        out.append(o)
    return out

def capture_fabric_leaf_switch_profiles(apic: Apic):
    """fabric-leaf-switch-profile (fabricLeafP) -> fabric_policies.leaf_switch_profiles. selectors
    (fabricLeafS) + policy (fabricRsLeNodePGrp) + node_blocks (fabricNodeBlk) + interface_profiles
    (fabricRsLePortP -> leportp). Exclut system-*/default. Miroir fabric de #50. [#52]"""
    sels_by = _by_parent(apic.get_class("fabricLeafS"))                     # par leprof DN
    blks = _by_parent(apic.get_class("fabricNodeBlk"))                      # par leafS DN
    pg = {_parent(x["dn"]): x.get("tDn") for x in apic.get_class("fabricRsLeNodePGrp")}
    ifp = defaultdict(list)
    for r in apic.get_class("fabricRsLePortP"):
        ifp[_parent(r["dn"])].append(r.get("tDn", ""))                      # par leprof DN
    out = []
    for p in apic.get_class("fabricLeafP"):
        name = _seg(p["dn"], "leprof")
        if not name or name.startswith("system-") or name == "default":
            continue
        o = {"name": p["name"]}
        sels = []
        for s in sels_by.get(p["dn"], []):
            if s["name"].startswith("system-"):
                continue
            so = {"name": s["name"]}
            tdn = pg.get(s["dn"])
            if tdn:
                mm = re.search(r"lenodepgrp-(.+)$", tdn)
                if mm:
                    so["policy"] = mm.group(1)
            nbs = []
            for b in blks.get(s["dn"], []):
                if b["name"].startswith("system-"):
                    continue
                nb = {"name": b["name"], "from": _num(b["from_"])}
                if b.get("to_") and b["to_"] != b["from_"]:
                    nb["to"] = _num(b["to_"])
                nbs.append(nb)
            if nbs:
                so["node_blocks"] = nbs
            sels.append(so)
        if sels:
            o["selectors"] = sels
        ifs = []
        for t in ifp.get(p["dn"], []):
            mm = re.search(r"leportp-(.+)$", t)
            if mm and not mm.group(1).startswith("system-"):
                ifs.append(mm.group(1))
        if ifs:
            o["interface_profiles"] = ifs
        out.append(o)
    return out

def capture_fabric_spine_switch_pgs(apic: Apic):
    """fabric-spine-switch-policy-group (fabricSpNodePGrp) -> fabric_policies.spine_switch_policy_groups.
    refs psu_policy/node_control_policy (miroir spine fabric de #52). [#53]"""
    refs = [("fabricRsPsuInstPol", "tnPsuInstPolName", "psu_policy"),
            ("fabricRsNodeCtrl", "tnFabricNodeControlName", "node_control_policy")]
    relmaps = [(field, {_parent(x["dn"]): x.get(attr) for x in apic.get_class(cls)})
               for cls, attr, field in refs]
    out = []
    for g in apic.get_class("fabricSpNodePGrp"):
        o = {"name": g["name"]}
        for field, m in relmaps:
            v = m.get(g["dn"])
            if v:
                o[field] = v
        out.append(o)
    return out

def capture_fabric_spine_switch_profiles(apic: Apic):
    """fabric-spine-switch-profile (fabricSpineP) -> fabric_policies.spine_switch_profiles. selectors
    (fabricSpineS) + policy (fabricRsSpNodePGrp) + node_blocks (fabricNodeBlk) + interface_profiles
    (fabricRsSpPortP -> spportp). Exclut system-*/default. Miroir spine fabric de #52. [#53]"""
    sels_by = _by_parent(apic.get_class("fabricSpineS"))                    # par spprof DN
    blks = _by_parent(apic.get_class("fabricNodeBlk"))                      # par spineS DN
    pg = {_parent(x["dn"]): x.get("tDn") for x in apic.get_class("fabricRsSpNodePGrp")}
    ifp = defaultdict(list)
    for r in apic.get_class("fabricRsSpPortP"):
        ifp[_parent(r["dn"])].append(r.get("tDn", ""))                      # par spprof DN
    out = []
    for p in apic.get_class("fabricSpineP"):
        name = _seg(p["dn"], "spprof")
        if not name or name.startswith("system-") or name == "default":
            continue
        o = {"name": p["name"]}
        sels = []
        for s in sels_by.get(p["dn"], []):
            if s["name"].startswith("system-"):
                continue
            so = {"name": s["name"]}
            tdn = pg.get(s["dn"])
            if tdn:
                mm = re.search(r"spnodepgrp-(.+)$", tdn)
                if mm:
                    so["policy"] = mm.group(1)
            nbs = []
            for b in blks.get(s["dn"], []):
                if b["name"].startswith("system-"):
                    continue
                nb = {"name": b["name"], "from": _num(b["from_"])}
                if b.get("to_") and b["to_"] != b["from_"]:
                    nb["to"] = _num(b["to_"])
                nbs.append(nb)
            if nbs:
                so["node_blocks"] = nbs
            sels.append(so)
        if sels:
            o["selectors"] = sels
        ifs = []
        for t in ifp.get(p["dn"], []):
            mm = re.search(r"spportp-(.+)$", t)
            if mm and not mm.group(1).startswith("system-"):
                ifs.append(mm.group(1))
        if ifs:
            o["interface_profiles"] = ifs
        out.append(o)
    return out

def capture_syslog_policies(apic: Apic):
    """syslog-policy (syslogGroup) -> fabric_policies.monitoring.syslogs. Group (format ternaire
    enhanced-log<->rfc5424-ts, show_milli/tz bools) + sous-singletons syslogProf(admin_state)/
    syslogFile(local_*)/syslogConsole(console_*) + destinations (syslogRemoteDest + mgmt_epg via
    fileRsARemoteHostToEpg). Plusieurs ternaires non parsés par attr_map -> capture dédiée."""
    prof = {_parent(x["dn"]): x for x in apic.get_class("syslogProf")}       # slgroup DN
    filo = {_parent(x["dn"]): x for x in apic.get_class("syslogFile")}
    cons = {_parent(x["dn"]): x for x in apic.get_class("syslogConsole")}
    dests = _by_parent(apic.get_class("syslogRemoteDest"))                   # slgroup DN
    epg = {_parent(x["dn"]): x for x in apic.get_class("fileRsARemoteHostToEpg")}  # rdst DN
    out = []
    for g in apic.get_class("syslogGroup"):
        if g.get("name") == "default":
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        fmt = "enhanced-log" if g.get("format") == "rfc5424-ts" else g.get("format")
        if fmt and fmt != "aci":                              # défaut aci
            o["format"] = fmt
        if g.get("includeMilliSeconds") == "yes":             # défaut no (false)
            o["show_millisecond"] = True
        if g.get("includeTimeZone") == "yes":
            o["show_timezone"] = True
        p = prof.get(g["dn"])
        if p and p.get("adminState") == "disabled":           # défaut enabled
            o["admin_state"] = False
        f = filo.get(g["dn"])
        if f:
            if f.get("adminState") == "disabled":
                o["local_admin_state"] = False
            if f.get("severity") and f["severity"] != "information":   # défaut information
                o["local_severity"] = f["severity"]
        c = cons.get(g["dn"])
        if c:
            if c.get("adminState") == "disabled":
                o["console_admin_state"] = False
            if c.get("severity") and c["severity"] != "alerts":        # défaut alerts
                o["console_severity"] = c["severity"]
        dl = []
        for d in dests.get(g["dn"], []):
            de = {"hostname_ip": d["host"]}
            if d.get("name"):
                de["name"] = d["name"]
            if d.get("protocol"):
                de["protocol"] = d["protocol"]
            if d.get("port"):
                de["port"] = _num(d["port"])
            if d.get("adminState") == "disabled":
                de["admin_state"] = False
            if d.get("forwardingFacility"):
                de["facility"] = d["forwardingFacility"]
            if d.get("severity"):
                de["severity"] = d["severity"]
            ref = epg.get(d["dn"])
            if ref and ref.get("tDn"):
                if "/oob-" in ref["tDn"]:
                    de["mgmt_epg"] = "oob"
                elif "/inb-" in ref["tDn"]:
                    de["mgmt_epg"] = "inb"
            dl.append(de)
        if dl:
            o["destinations"] = dl
        out.append(o)
    return out

def capture_macsec_param_policies(apic: Apic):
    """macsec parameters policies (macsecParamPol, type access) -> access_policies.
    interface_policies.macsec_parameters_policies. Pas de clé secrète. Exclut 'default'."""
    out = []
    for p in apic.get_class("macsecParamPol"):
        if p.get("name") == "default":
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        if p.get("cipherSuite") and p["cipherSuite"] != "gcm-aes-xpn-256":
            o["cipher_suite"] = p["cipherSuite"]
        if p.get("confOffset") and p["confOffset"] != "offset-0":
            o["confidentiality_offset"] = p["confOffset"]
        if p.get("keySvrPrio") and p["keySvrPrio"] != "16":
            o["key_server_priority"] = int(p["keySvrPrio"])
        if p.get("replayWindow") and p["replayWindow"] != "64":
            o["window_size"] = int(p["replayWindow"])
        if p.get("sakExpiryTime") and p["sakExpiryTime"] not in ("disabled", "0"):
            o["key_expiry_time"] = int(p["sakExpiryTime"])
        if p.get("secPolicy") and p["secPolicy"] != "should-secure":
            o["security_policy"] = p["secPolicy"]
        out.append(o)
    return out

def capture_snmp_policies(apic: Apic):
    """SNMP policies fabric (snmpPol uni/fabric-<name>) + communities + trap_forwarders
    + clients (snmpClientGrpP + entries snmpClientP + mgmt_epg snmpRsEpg [audit 2026-07-06]).
    Users (snmpUserP) = SECRETS (authKey/privKey) -> omis. Exclut le pol système
    'default'. -> fabric_policies.pod_policies.snmp_policies."""
    comms = _by_parent(apic.get_class("snmpCommunityP"))
    traps = _by_parent(apic.get_class("snmpTrapFwdServerP"))
    clgrps = _by_parent(apic.get_class("snmpClientGrpP"))     # par snmpPol DN
    clients_p = _by_parent(apic.get_class("snmpClientP"))     # par snmpClientGrpP DN
    cl_epg = {_parent(x["dn"]): x for x in apic.get_class("snmpRsEpg")}
    out = []
    for p in apic.get_class("snmpPol"):
        if not p.get("dn", "").startswith("uni/fabric/snmppol-"):
            continue
        if p.get("name") == "default":                       # pol système
            continue
        o = {"name": p["name"], "admin_state": p.get("adminSt") == "enabled"}
        if p.get("loc"):
            o["location"] = p["loc"]
        if p.get("contact"):
            o["contact"] = p["contact"]
        cs = sorted(c["name"] for c in comms.get(p["dn"], []) if c.get("name"))
        if cs:
            o["communities"] = cs
        tf = []
        for t in traps.get(p["dn"], []):
            tx = {"ip": t["addr"]}
            if t.get("port") and t["port"] != "162":         # defaut 162
                tx["port"] = int(t["port"])
            tf.append(tx)
        if tf:
            o["trap_forwarders"] = tf
        cl = []
        for g in clgrps.get(p["dn"], []):
            c = {"name": g["name"]}
            if g.get("descr"):
                c["description"] = g["descr"]
            # data model : cle unique mgmt_epg = "oob"/"inb" (le NOM de l'EPG est derive
            # de node_policies.oob/inb_endpoint_group par le cablage) [audit 2026-07-06]
            epg = cl_epg.get(g["dn"])                         # dict keye par parent (clgrp)
            c["mgmt_epg"] = "oob" if (epg and "/oob-" in epg.get("tDn", "")) else "inb"
            _set(c, "entries", [{"ip": e["addr"], "name": e["name"]}
                                for e in clients_p.get(g["dn"], []) if e.get("addr")])
            cl.append(c)
        if cl:
            o["clients"] = cl
        out.append(o)
    return out

def capture_infra_dhcp_relay_policies(apic: Apic):
    """infra dhcp relay (dhcpRelayP owner=infra, uni/infra/relayp-) + providers (dhcpRsProv).
    Miroir infra du dhcp-relay tenant #66. -> access_policies.dhcp_relay_policies."""
    prov_by = _by_parent(apic.get_class("dhcpRsProv"))
    out = []
    for p in apic.get_class("dhcpRelayP"):
        if "/infra/" not in p.get("dn", ""):
            continue
        if p.get("name") == "default":                        # relayp-default système
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        provs = []
        for rs in prov_by.get(p["dn"], []):
            pr = {"ip": rs.get("addr")}
            tdn = rs.get("tDn", "")
            mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", tdn)
            if mm:
                pr["type"] = "epg"
                pr["tenant"], pr["application_profile"], pr["endpoint_group"] = mm.groups()
            else:
                mm = re.search(r"tn-([^/]+)/out-([^/]+)/instP-(.+)$", tdn)
                if mm:
                    pr["type"] = "l3out"
                    pr["tenant"], pr["l3out"], pr["external_endpoint_group"] = mm.groups()
            provs.append(pr)
        if provs:
            o["providers"] = provs
        out.append(o)
    return out

def capture_dns_policies(apic: Apic):
    """DNS policies fabric (dnsProfile uni/fabric/dnsp-) + providers (dnsProv) +
    domains (dnsDomain). mgmt_epg (rsProfileToEpg) = binding default inb -> omis
    (recréé par le défaut du module, idempotent). Exclut 'default'.
    -> fabric_policies.dns_policies."""
    provs = _by_parent(apic.get_class("dnsProv"))
    doms = _by_parent(apic.get_class("dnsDomain"))
    out = []
    for p in apic.get_class("dnsProfile"):
        if not p.get("dn", "").startswith("uni/fabric/dnsp-"):
            continue
        if p.get("name") == "default":
            continue
        o = {"name": p["name"]}
        pl = []
        for pr in provs.get(p["dn"], []):
            px = {"ip": pr["addr"]}
            if pr.get("preferred") == "yes":                 # defaut no
                px["preferred"] = True
            pl.append(px)
        if pl:
            o["providers"] = pl
        dl = []
        for d in doms.get(p["dn"], []):
            dx = {"name": d["name"]}
            if d.get("isDefault") == "no":                   # defaut yes
                dx["default"] = False
            dl.append(dx)
        if dl:
            o["domains"] = dl
        out.append(o)
    return out

def capture_geolocation(apic: Apic):
    """geolocation (geoSite uni/fabric/site- + hiérarchie building/floor/room/row/rack
    + geoRsNodeLocation -> node ids). Exclut le site 'default' (chaîne système uid 0).
    -> fabric_policies.geolocation.sites. [#91]"""
    def _rows(cn):
        # l'APIC auto-cree une chaine default (building/floor/room/rack) uid=0
        # sous chaque site -> exclue, comme le site-default systeme
        return [x for x in apic.get_class(cn) if x.get("uid") != "0"]
    bl = _by_parent(_rows("geoBuilding"))
    fl = _by_parent(_rows("geoFloor"))
    rm = _by_parent(_rows("geoRoom"))
    rw = _by_parent(_rows("geoRow"))
    rk = _by_parent(_rows("geoRack"))
    nd = _by_parent(apic.get_class("geoRsNodeLocation"))
    def _o(x):
        o = {"name": x["name"]}
        if x.get("descr"):
            o["description"] = x["descr"]
        return o
    sites = []
    for s in _rows("geoSite"):
        so = _o(s)
        buildings = []
        for b in bl.get(s["dn"], []):
            bo = _o(b)
            floors = []
            for f in fl.get(b["dn"], []):
                fo = _o(f)
                rooms = []
                for r in rm.get(f["dn"], []):
                    ro = _o(r)
                    rows = []
                    for w in rw.get(r["dn"], []):
                        wo = _o(w)
                        racks = []
                        for k in rk.get(w["dn"], []):
                            ko = _o(k)
                            nodes = [int(m.group(1)) for n in nd.get(k["dn"], [])
                                     if (m := re.search(r"node-(\d+)", n.get("tDn", "")))]
                            _set(ko, "nodes", nodes)
                            racks.append(ko)
                        _set(wo, "racks", racks)
                        rows.append(wo)
                    _set(ro, "rows", rows)
                    rooms.append(ro)
                _set(fo, "rooms", rooms)
                floors.append(fo)
            _set(bo, "floors", floors)
            buildings.append(bo)
        _set(so, "buildings", buildings)
        sites.append(so)
    return sites

AAA_PWD_PLACEHOLDER = "Placeholder123!"
OSPF_KEY_PLACEHOLDER = "NacKey12"      # authKey ospfIfP write-only (8 car. max si auth simple)   # pwd aaaUser REQUIS par le cablage, write-only (ignore_changes)

def capture_aaa_settings(apic: Apic):
    """politique AAA globale -> fabric_policies.aaa : realms par defaut/console
    (aaaDefaultAuth/aaaConsoleAuth), security_domains (aaaDomain, hors systeme) et
    management_settings (profil mots de passe aaaUserEp/aaaPwdStrengthProfile/
    aaaPwdProfile, web token pkiWebTokenData, login block aaaBlockLoginProfile).
    Defauts NaC omis — sans cette capture, un sync ecraserait le durcissement AAA
    d'une fabric brownfield par les defauts. [audit 2026-07-03]"""
    out, ms = {}, {}
    def _one(cn):
        rows = apic.get_class(cn)
        return rows[0] if rows else {}
    da = _one("aaaDefaultAuth")
    if da.get("realm") and da["realm"] != "local":
        out["default_realm"] = da["realm"]
        if da.get("providerGroup"):
            out["default_login_domain"] = da["providerGroup"]
    if da.get("fallbackCheck") == "true":                    # defaut false
        out["default_fallback_check"] = True
    ca = _one("aaaConsoleAuth")
    if ca.get("realm") and ca["realm"] != "local":
        out["console_realm"] = ca["realm"]
        if ca.get("providerGroup"):
            out["console_login_domain"] = ca["providerGroup"]
        # BUG UPSTREAM terraform-aci-aaa/main.tf:24 : le providerGroup console
        # teste default_realm au lieu de console_realm pour le cas ldap -> un
        # sync effacerait le provider group console LDAP (acces console casse).
        # Signale a Cisco ; en attendant on refuse de gerer ce cas.
        # [audit adversarial 2026-07-06 M2]
        if ca["realm"] == "ldap" and da.get("realm") != "ldap":
            out.pop("console_realm"); out.pop("console_login_domain", None)
            log.warning("console_realm=ldap NON capture (bug module Cisco aaa : "
                        "providerGroup console teste default_realm) -> gere a la main")
    doms = []
    for d in apic.get_class("aaaDomain"):
        if d.get("uid") == "0":                              # all/common/mgmt systeme
            continue
        o = {"name": d["name"]}
        if d.get("descr"):
            o["description"] = d["descr"]
        if d.get("restrictedRbacDomain") == "yes":
            o["restricted_rbac_domain"] = True
        doms.append(o)
    if doms:
        out["security_domains"] = doms
    ue = _one("aaaUserEp")
    if ue.get("pwdStrengthCheck") == "yes":                  # defaut false
        ms["password_strength_check"] = True
        sp = _one("aaaPwdStrengthProfile")
        prof = {}
        if sp.get("pwdMinLength") not in (None, "", "8"):
            prof["password_mininum_length"] = int(sp["pwdMinLength"])
        if sp.get("pwdMaxLength") not in (None, "", "64"):
            prof["password_maximum_length"] = int(sp["pwdMaxLength"])
        if sp.get("pwdStrengthTestType") and sp["pwdStrengthTestType"] != "default":
            prof["password_strength_test_type"] = sp["pwdStrengthTestType"]
            if sp["pwdStrengthTestType"] == "custom" and sp.get("pwdClassFlags"):
                prof["password_class_flags"] = sorted(sp["pwdClassFlags"].split(","))
        if prof:
            ms["password_strength_profile"] = prof
    pp = _one("aaaPwdProfile")
    if pp.get("changeDuringInterval") == "disable":          # defaut enable
        ms["password_change_during_interval"] = False
    for attr, key, dflt in (("changeInterval", "password_change_interval", "48"),
                            ("changeCount", "password_change_count", "2"),
                            ("noChangeInterval", "password_no_change_interval", "24"),
                            ("historyCount", "password_history_count", "5")):
        if pp.get(attr) not in (None, "", dflt):
            ms[key] = int(pp[attr])
    wt = _one("pkiWebTokenData")
    for attr, key, dflt in (("webtokenTimeoutSeconds", "web_token_timeout", "600"),
                            ("maximumValidityPeriod", "web_token_max_validity", "24"),
                            ("uiIdleTimeoutSeconds", "web_session_idle_timeout", "1200")):
        if wt.get(attr) not in (None, "", dflt):
            ms[key] = int(wt[attr])
    if wt.get("sessionRecordFlags") and "refresh" not in wt["sessionRecordFlags"]:
        ms["include_refresh_session_records"] = False        # defaut true
    bl = _one("aaaBlockLoginProfile")
    if bl.get("enableLoginBlock") == "enable":               # defaut disable
        ms["enable_login_block"] = True
    for attr, key, dflt in (("blockDuration", "login_block_duration", "60"),
                            ("maxFailedAttempts", "login_max_failed_attempts", "5"),
                            ("maxFailedAttemptsWindow", "login_max_failed_attempts_window", "5")):
        if bl.get(attr) not in (None, "", dflt):
            ms[key] = int(bl[attr])
    if ms:
        out["management_settings"] = ms
    return out

def capture_aaa_security(apic: Apic):
    """objets AAA nommes -> fabric_policies.aaa.{radius_providers, tacacs_providers,
    users, ca_certificates, login_domains}. SECRETS non round-trippables : key /
    monitoringPassword omis (ignore_changes) ; pwd user = placeholder constant
    (requis par le cablage). certChain (pkiTP) est PUBLIC -> round-trip complet.
    Exclut uid==0 (admin, logindomain fallback). mgmt_epg des providers : capture
    'oob' seulement (inb = defaut recree par le module). [#96-#100]"""
    out = {}
    epgs = {_parent(r["dn"]): r.get("tDn", "") for r in apic.get_class("aaaRsSecProvToEpg")}
    def providers(cls, def_port):
        rows = []
        for p in apic.get_class(cls):
            o = {"hostname_ip": p["name"]}
            if p.get("descr"):
                o["description"] = p["descr"]
            if p.get("authProtocol") and p["authProtocol"] != "pap":
                o["protocol"] = p["authProtocol"]
            port = p.get("authPort") or p.get("port")
            if port and int(port) != def_port:
                o["port"] = int(port)
            if p.get("retries") not in (None, "", "1"):
                o["retries"] = _num(p["retries"])
            if p.get("timeout") not in (None, "", "5"):
                o["timeout"] = _num(p["timeout"])
            if p.get("monitorServer") == "enabled":
                o["monitoring"] = True
                if p.get("monitoringUser"):
                    o["monitoring_username"] = p["monitoringUser"]
            if "/oob-" in epgs.get(p["dn"], ""):
                o["mgmt_epg"] = "oob"
            rows.append(o)
        return rows
    rad = providers("aaaRadiusProvider", 1812)
    if rad:
        out["radius_providers"] = rad
    tac = providers("aaaTacacsPlusProvider", 49)
    if tac:
        out["tacacs_providers"] = tac
    # l'APIC auto-cree un userdomain 'common' + role 'read-all' uid=0 sous chaque
    # user -> exclus (meme piege que la chaine default geolocation #91)
    doms = _by_parent([d for d in apic.get_class("aaaUserDomain") if d.get("uid") != "0"])
    roles = _by_parent([r for r in apic.get_class("aaaUserRole") if r.get("uid") != "0"])
    # certs X.509 + cles SSH publiques : donnees PUBLIQUES lisibles (comme
    # pkiTP.certChain) -> round-trip complet [audit 2026-07-03]
    certs_by = _by_parent(apic.get_class("aaaUserCert"))
    sshk_by = _by_parent(apic.get_class("aaaSshAuth"))
    users = []
    for u in apic.get_class("aaaUser"):
        if u.get("uid") == "0":
            continue
        o = {"username": u["name"], "password": AAA_PWD_PLACEHOLDER}
        if u.get("descr"):
            o["description"] = u["descr"]
        if u.get("accountStatus") and u["accountStatus"] != "active":
            o["status"] = u["accountStatus"]
        if u.get("email"):
            o["email"] = u["email"]
        if u.get("expires") == "yes":
            o["expires"] = True
        if u.get("expiration") and u["expiration"] != "never":
            o["expire_date"] = u["expiration"]
        if u.get("firstName"):
            o["first_name"] = u["firstName"]
        if u.get("lastName"):
            o["last_name"] = u["lastName"]
        if u.get("phone"):
            o["phone"] = u["phone"]
        if u.get("certAttribute"):
            o["certificate_name"] = u["certAttribute"]
        dl = []
        for d in doms.get(u["dn"], []):
            do = {"name": d["name"]}
            rl = []
            for r in roles.get(d["dn"], []):
                ro = {"name": r["name"]}
                if r.get("privType") == "readPriv":       # defaut write (writePriv)
                    ro["privilege_type"] = "read"
                rl.append(ro)
            _set(do, "roles", rl)
            dl.append(do)
        _set(o, "domains", dl)
        _set(o, "certificates", [{"name": c["name"], "data": (c.get("data") or "").strip()}
                                 for c in certs_by.get(u["dn"], [])])
        _set(o, "ssh_keys", [{"name": k["name"], "data": (k.get("data") or "").strip()}
                             for k in sshk_by.get(u["dn"], [])])
        users.append(o)
    if users:
        out["users"] = users
    cas = []
    for c in apic.get_class("pkiTP"):
        o = {"name": c["name"]}
        if c.get("descr"):
            o["description"] = c["descr"]
        if c.get("certChain"):
            o["certificate_chain"] = c["certChain"].strip()
        cas.append(o)
    if cas:
        out["ca_certificates"] = cas
    # ldap (aaa.ldap : providers + group_map_rules + group_maps) [#101]
    # password (key/rootdn) + monitoring_password = SECRETS omis (ignore_changes)
    lprovs = []
    for p in apic.get_class("aaaLdapProvider"):
        o = {"hostname_ip": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        if p.get("port") not in (None, "", "389"):
            o["port"] = _num(p["port"])
        if p.get("rootdn"):
            o["bind_dn"] = p["rootdn"]
        if p.get("basedn"):
            o["base_dn"] = p["basedn"]
        if p.get("timeout") not in (None, "", "30"):
            o["timeout"] = _num(p["timeout"])
        if p.get("retries") not in (None, "", "1"):
            o["retries"] = _num(p["retries"])
        if p.get("enableSSL") == "yes":
            o["enable_ssl"] = True
        if p.get("filter") and p["filter"] != "sAMAccountName=$userid":
            o["filter"] = p["filter"]
        if p.get("attribute") and p["attribute"] != "CiscoAVPair":
            o["attribute"] = p["attribute"]
        if p.get("SSLValidationLevel") and p["SSLValidationLevel"] != "strict":
            o["ssl_validation_level"] = p["SSLValidationLevel"]
        if p.get("monitorServer") == "enabled":
            o["server_monitoring"] = True
            if p.get("monitoringUser") and p["monitoringUser"] != "default":
                o["monitoring_username"] = p["monitoringUser"]
        if "/oob-" in epgs.get(p["dn"], ""):
            o["mgmt_epg"] = "oob"
        lprovs.append(o)
    lrules = []
    for r in apic.get_class("aaaLdapGroupMapRule"):
        o = {"name": r["name"]}
        if r.get("descr"):
            o["description"] = r["descr"]
        if r.get("groupdn"):
            o["group_dn"] = r["groupdn"]
        dl = []
        for d in doms.get(r["dn"], []):                   # meme filtre uid!=0 que users
            do = {"name": d["name"]}
            rl = []
            for x in roles.get(d["dn"], []):
                ro = {"name": x["name"]}
                if x.get("privType") == "readPriv":
                    ro["privilege_type"] = "read"
                rl.append(ro)
            _set(do, "roles", rl)
            dl.append(do)
        _set(o, "security_domains", dl)
        lrules.append(o)
    lrefs = _by_parent(apic.get_class("aaaLdapGroupMapRuleRef"))
    lmaps = []
    for g in apic.get_class("aaaLdapGroupMap"):
        o = {"name": g["name"]}
        rl = [{"name": x["name"]} for x in lrefs.get(g["dn"], [])]
        _set(o, "rules", rl)
        lmaps.append(o)
    ldap = {}
    if lprovs:
        ldap["providers"] = lprovs
    if lrules:
        ldap["group_map_rules"] = lrules
    if lmaps:
        ldap["group_maps"] = lmaps
    if ldap:
        out["ldap"] = ldap
    auth = {_parent(r["dn"]): r for r in apic.get_class("aaaDomainAuth")}
    refs = _by_parent(apic.get_class("aaaProviderRef"))
    grp_seg = {"radius": "radiusext/radiusprovidergroup-",
               "tacacs": "tacacsext/tacacsplusprovidergroup-",
               "ldap": "ldapext/ldapprovidergroup-"}
    lds = []
    for d in apic.get_class("aaaLoginDomain"):
        if d.get("uid") == "0":                           # logindomain 'fallback' systeme
            continue
        o = {"name": d["name"]}
        if d.get("descr"):
            o["description"] = d["descr"]
        au = auth.get(d["dn"])
        realm = au.get("realm") if au else None
        if realm and realm in grp_seg:
            o["realm"] = realm
            gdn = f"uni/userext/{grp_seg[realm]}{d['name']}"
            pl = []
            for r in refs.get(gdn, []):
                po = {"hostname_ip": r["name"]}
                if r.get("order") not in (None, "", "0"):
                    po["priority"] = _num(r["order"])
                pl.append(po)
            _set(o, f"{realm}_providers", pl)
        lds.append(o)
    if lds:
        out["login_domains"] = lds
    return out

def capture_vpc_groups(apic: Apic):
    """vpc protection groups (fabricExplicitGEp + fabricNodePEp + fabricRsVpcInstPol)
    -> node_policies.vpc_groups.groups (le mode fabricProtPol vient du moteur
    singleton). [#94]"""
    peps = _by_parent(apic.get_class("fabricNodePEp"))
    pols = {_parent(r["dn"]): r.get("tnVpcInstPolName")
            for r in apic.get_class("fabricRsVpcInstPol")}
    out = []
    for g in apic.get_class("fabricExplicitGEp"):
        o = {"name": g["name"], "id": _num(g["id"])}
        sw = sorted(int(p["id"]) for p in peps.get(g["dn"], []))
        if len(sw) == 2:
            o["switch_1"], o["switch_2"] = sw
        if pols.get(g["dn"]):
            o["policy"] = pols[g["dn"]]
        out.append(o)
    return out

def capture_mst_policies(apic: Apic):
    """mst region policies (stpMstRegionPol sous uni/infra/mstpInstPol-default/) +
    instances (stpMstDomPol) + vlan_ranges (fvnsEncapBlk, aussi utilisee sous les
    vlan pools -> indexee par parent, seuls les blocs sous stpMstDomPol matchent).
    -> access_policies.switch_policies.mst_policies. [#93]"""
    doms = _by_parent(apic.get_class("stpMstDomPol"))
    blks = _by_parent(apic.get_class("fvnsEncapBlk"))
    out = []
    for p in apic.get_class("stpMstRegionPol"):
        if p.get("name") == "default":
            continue
        o = {"name": p["name"]}
        if p.get("regName"):
            o["region"] = p["regName"]
        if p.get("rev"):
            o["revision"] = _num(p["rev"])
        insts = []
        for d in doms.get(p["dn"], []):
            io = {"name": d["name"], "id": _num(d["id"])}
            rngs = []
            for b in blks.get(d["dn"], []):
                fr = int(b["from"].replace("vlan-", ""))
                to = int(b["to"].replace("vlan-", ""))
                r = {"from": fr}
                if to != fr:
                    r["to"] = to
                rngs.append(r)
            _set(io, "vlan_ranges", rngs)
            insts.append(io)
        _set(o, "instances", insts)
        out.append(o)
    return out

def capture_date_time_policies(apic: Apic):
    """date-time policies fabric (datetimePol uni/fabric/time-) + ntp_servers
    (datetimeNtpProv). ntp_keys (datetimeNtpAuthKey) = SECRETS omis ; mgmt_epg
    (rsNtpProvToEpg) = binding default inb omis (recréé par défaut, idempotent).
    Exclut 'default'. -> fabric_policies.pod_policies.date_time_policies."""
    provs = _by_parent(apic.get_class("datetimeNtpProv"))
    out = []
    for p in apic.get_class("datetimePol"):
        if not p.get("dn", "").startswith("uni/fabric/time-"):
            continue
        if p.get("name") == "default":
            continue
        o = {"name": p["name"],
             "ntp_admin_state": p.get("adminSt") == "enabled",
             "ntp_auth_state": p.get("authSt") == "enabled",
             "apic_ntp_server_state": p.get("serverState") == "enabled",
             "apic_ntp_server_master_mode": p.get("masterMode") == "enabled"}
        if p.get("StratumValue"):
            o["apic_ntp_server_master_stratum"] = int(p["StratumValue"])
        srv = []
        for s in provs.get(p["dn"], []):
            srv.append({"hostname_ip": s["name"],
                        "preferred": s.get("preferred") == "yes"})
        if srv:
            o["ntp_servers"] = srv
        out.append(o)
    return out

def capture_fabric_pod_policy_groups(apic: Apic):
    """fabric pod policy groups (fabricPodPGrp uni/fabric/funcprof/podpgrp-) +
    relations snmp/time/comm/macsec/bgp-rr. -> fabric_policies.pod_policy_groups."""
    rels = {
        "fabricRsSnmpPol":        ("tnSnmpPolName", "snmp_policy"),
        "fabricRsTimePol":        ("tnDatetimePolName", "date_time_policy"),
        "fabricRsCommPol":        ("tnCommPolName", "management_access_policy"),
        "fabricRsMacsecPol":      ("tnMacsecFabIfPolName", "macsec_policy"),
        "fabricRsPodPGrpBGPRRP":  ("tnBgpInstPolName", "bgp_route_reflector_policy"),
    }
    relmap = {}
    for cls, (attr, key) in rels.items():
        for x in apic.get_class(cls):
            relmap.setdefault(_parent(x["dn"]), {})[key] = x.get(attr, "")
    out = []
    for p in apic.get_class("fabricPodPGrp"):
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        for key, val in relmap.get(p["dn"], {}).items():
            if val:                                          # ignore relations vides
                o[key] = val
        out.append(o)
    return out

# flags CSV comm* <-> cles YAML management_access_policies (valeur = defaut NaC)
_SSH_CIPHERS = (("aes128_ctr", "aes128-ctr", True), ("aes128_gcm", "aes128-gcm@openssh.com", True),
                ("aes192_ctr", "aes192-ctr", True), ("aes256_ctr", "aes256-ctr", True),
                ("aes256_gcm", "aes256-gcm@openssh.com", True),
                ("chacha", "chacha20-poly1305@openssh.com", False))
_SSH_MACS = (("hmac_sha1", "hmac-sha1", False), ("hmac_sha2_256", "hmac-sha2-256", True),
             ("hmac_sha2_512", "hmac-sha2-512", True))
_SSH_KEX = (("curve25519_sha256", "curve25519-sha256", True),
            ("curve25519_sha256_libssh", "curve25519-sha256@libssh.org", True),
            ("dh1_sha1", "diffie-hellman-group1-sha1", False),
            ("dh14_sha1", "diffie-hellman-group14-sha1", False),
            ("dh14_sha256", "diffie-hellman-group14-sha256", True),
            ("dh16_sha512", "diffie-hellman-group16-sha512", True),
            ("ecdh_sha2_nistp256", "ecdh-sha2-nistp256", True),
            ("ecdh_sha2_nistp384", "ecdh-sha2-nistp384", True),
            ("ecdh_sha2_nistp521", "ecdh-sha2-nistp521", True))
_TLS = (("tlsv1", "TLSv1", False), ("tlsv1_1", "TLSv1.1", False),
        ("tlsv1_2", "TLSv1.2", True), ("tlsv1_3", "TLSv1.3", False))

def _flags_diff(csv, table, dst):
    """csv APIC -> cles YAML pour chaque flag qui differe du defaut NaC."""
    have = set((csv or "").split(","))
    for key, val, dflt in table:
        if (val in have) != dflt:
            dst[key] = val in have

def capture_qos_classes(apic: Apic):
    """QoS fabric par level (qosClass + sched/pfcpol/cong/buffer sous
    uni/infra/qosinst-default) -> access_policies.qos.qos_classes[]. N'emet que
    les levels ayant au moins un attribut hors defaut NaC (bw 20% niveaux 1-3,
    0% niveaux 4-6). [audit 2026-07-03]"""
    sub = {c: {_parent(x["dn"]): x for x in apic.get_class(c)}
           for c in ("qosSched", "qosPfcPol", "qosCong", "qosBuffer")}
    out = []
    for c in apic.get_class("qosClass"):
        mm = re.search(r"^uni/infra/qosinst-default/class-level(\d+)$", c.get("dn", ""))
        if not mm:
            continue
        lvl = int(mm.group(1))
        e = {"level": lvl}
        if c.get("admin") == "disabled":                       # defaut enabled
            e["admin_state"] = False
        if c.get("mtu") not in (None, "", "9216"):
            e["mtu"] = int(c["mtu"])
        s = sub["qosSched"].get(c["dn"]) or {}
        if s.get("bw") not in (None, "", "20" if lvl <= 3 else "0"):
            e["bandwidth_percent"] = int(s["bw"])
        if s.get("meth") == "sp":                              # defaut wrr
            e["scheduling"] = "strict-priority"
        p = sub["qosPfcPol"].get(c["dn"]) or {}
        if p.get("adminSt") == "yes":                          # defaut no
            e["pfc_state"] = True
        if p.get("noDropCos"):
            e["no_drop_cos"] = p["noDropCos"]
        if p.get("enableScope") and p["enableScope"] != "tor":
            e["pfc_scope"] = p["enableScope"]
        g = sub["qosCong"].get(c["dn"]) or {}
        if g.get("algo") and g["algo"] != "tail-drop":
            e["congestion_algorithm"] = g["algo"]
        if g.get("ecn") == "enabled":
            e["ecn"] = True
        if g.get("forwardNonEcn") == "enabled":
            e["forward_non_ecn"] = True
        for attr, key, dflt in (("wredMaxThreshold", "wred_max_threshold", "100"),
                                ("wredMinThreshold", "wred_min_threshold", "0"),
                                ("wredProbability", "wred_probability", "0"),
                                ("wredWeight", "weight", "0")):
            if g.get(attr) not in (None, "", dflt):
                e[key] = int(g[attr])
        b = sub["qosBuffer"].get(c["dn"]) or {}
        if b.get("min") not in (None, "", "0"):
            e["minimum_buffer"] = int(b["min"])
        if len(e) > 1:                                         # au moins un hors defaut
            out.append(e)
    return sorted(out, key=lambda x: x["level"])

def capture_management_access_policies(apic: Apic):
    """management access policies fabric (commPol uni/fabric/comm-) + sous-objets
    telnet/ssh/https/http, y compris le DURCISSEMENT : ciphers/macs/kex SSH,
    versions TLS, dh, keyring (commRsKeyRing) et allow_origins — sans quoi un sync
    remettrait une fabric durcie aux defauts permissifs [audit 2026-07-03].
    Exclut 'default'. -> fabric_policies.pod_policies.management_access_policies."""
    tel = {_parent(x["dn"]): x for x in apic.get_class("commTelnet")}
    ssh = {_parent(x["dn"]): x for x in apic.get_class("commSsh")}
    htps = {_parent(x["dn"]): x for x in apic.get_class("commHttps")}
    htp = {_parent(x["dn"]): x for x in apic.get_class("commHttp")}
    kr = {_parent(x["dn"], 2): x for x in apic.get_class("commRsKeyRing")}
    out = []
    for p in apic.get_class("commPol"):
        if not p.get("dn", "").startswith("uni/fabric/comm-"):
            continue
        if p.get("name") == "default":
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        t = tel.get(p["dn"])
        if t:
            o["telnet"] = {"admin_state": t.get("adminSt") == "enabled",
                           "port": int(t["port"])}
        s = ssh.get(p["dn"])
        if s:
            sd = {"admin_state": s.get("adminSt") == "enabled",
                  "password_auth": s.get("passwordAuth") == "enabled",
                  "port": int(s["port"])}
            _flags_diff(s.get("sshCiphers"), _SSH_CIPHERS, sd)
            _flags_diff(s.get("sshMacs"), _SSH_MACS, sd)
            _flags_diff(s.get("kexAlgos"), _SSH_KEX, sd)
            o["ssh"] = sd
        h = htps.get(p["dn"])
        if h:
            hd = {"admin_state": h.get("adminSt") == "enabled",
                  "client_cert_auth_state": h.get("clientCertAuthState") == "enabled",
                  "port": int(h["port"])}
            if h.get("dhParam") and h["dhParam"] != "none":
                hd["dh"] = int(h["dhParam"])
            _flags_diff(h.get("sslProtocols"), _TLS, hd)
            if h.get("accessControlAllowOrigins"):
                hd["allow_origins"] = h["accessControlAllowOrigins"]
            rs = kr.get(p["dn"])
            if rs and rs.get("tnPkiKeyRingName") and rs["tnPkiKeyRingName"] != "default":
                hd["key_ring"] = rs["tnPkiKeyRingName"]
            o["https"] = hd
        hh = htp.get(p["dn"])
        if hh:
            hto = {"admin_state": hh.get("adminSt") == "enabled",
                   "port": int(hh["port"])}
            if hh.get("accessControlAllowOrigins"):
                hto["allow_origins"] = hh["accessControlAllowOrigins"]
            o["http"] = hto
        out.append(o)
    return out

def capture_common_monitoring(apic: Apic):
    """common monitoring policy (uni/fabric/moncommon) : sources syslog (syslogSrc + incl
    flags + minSev + syslogRsDestGroup->slgroup). snmp_traps = réfs snmp-trap group (déféré)
    -> omis. -> entrée {name: common, syslogs:[...]} dans fabric_policies.monitoring.policies."""
    sl_dest = {_parent(x["dn"]): x for x in apic.get_class("syslogRsDestGroup")
               if "/moncommon/" in x.get("dn", "")}
    syslogs = []
    for s in apic.get_class("syslogSrc"):
        if "/moncommon/" not in s.get("dn", ""):
            continue
        o = {"name": s["name"]}
        incl = set(filter(None, s.get("incl", "").split(",")))
        allf = "all" in incl
        for flag in ("audit", "events", "faults", "session"):
            o[flag] = allf or flag in incl
        if s.get("minSev"):
            o["minimum_severity"] = s["minSev"]
        d = sl_dest.get(s["dn"])
        if d:
            mm = re.search(r"slgroup-(.+)$", d.get("tDn", ""))
            if mm:
                o["destination_group"] = mm.group(1)
        syslogs.append(o)
    return {"name": "common", "syslogs": syslogs} if syslogs else None

def capture_config_exports(apic: Apic):
    """config exports (configExportP) -> fabric_policies.config_exports. Exclut systeme
    (uid==0 ex DailyAutoBackup) et les default* (defaultOneTime = mécanisme snapshot)."""
    sched = {_parent(x["dn"]): x.get("tnTrigSchedPName") for x in apic.get_class("configRsExportScheduler")}
    rpath = {_parent(x["dn"]): x.get("tnFileRemotePathName") for x in apic.get_class("configRsRemotePath")}
    out = []
    for p in apic.get_class("configExportP"):
        if p.get("uid") == "0" or p.get("name", "").startswith("default"):
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        if p.get("format") and p["format"] != "json":      # defaut json
            o["format"] = p["format"]
        if p.get("snapshot") == "yes":                      # defaut no
            o["snapshot"] = True
        if sched.get(p["dn"]):
            o["scheduler"] = sched[p["dn"]]
        if rpath.get(p["dn"]):
            o["remote_location"] = rpath[p["dn"]]
        out.append(o)
    return out

def capture_psu_policies(apic: Apic):
    """psu policies (psuInstPol) -> fabric_policies.switch_policies.psu_policies.
    admin_state via adminRdnM (comb/rdn/ps-rdn). Exclut 'default'."""
    rmap = {"comb": "combined", "rdn": "nnred", "ps-rdn": "n1red"}
    out = []
    for p in apic.get_class("psuInstPol"):
        if p.get("name") == "default":
            continue
        o = {"name": p["name"]}
        a = rmap.get(p.get("adminRdnM"))
        if a and a != "combined":                  # defaut combined
            o["admin_state"] = a
        out.append(o)
    return out

def capture_bfd_policies(apic: Apic):
    """bfd switch policies globales (bfdIpv4InstPol/bfdIpv6InstPol) -> access_policies.
    switch_policies.bfd_ipv4_policies / bfd_ipv6_policies. Exclut 'default'."""
    fields = (("detectMult", "detection_multiplier", "3"),
              ("minTxIntvl", "min_transmit_interval", "50"),
              ("minRxIntvl", "min_receive_interval", "50"),
              ("slowIntvl", "slow_timer_interval", "2000"),
              # startupIntvl : défaut null côté data model, auto-rempli (10) par l'APIC -> NON capturé
              ("echoRxIntvl", "echo_receive_interval", "50"))
    res = {}
    for cls, key in (("bfdIpv4InstPol", "bfd_ipv4_policies"), ("bfdIpv6InstPol", "bfd_ipv6_policies")):
        lst = []
        for p in apic.get_class(cls):
            if p.get("name") == "default":
                continue
            o = {"name": p["name"]}
            if p.get("descr"):
                o["description"] = p["descr"]
            for af, yf, dflt in fields:
                if p.get(af) and p[af] != dflt:
                    o[yf] = int(p[af])
            if p.get("echoSrcAddr") and p["echoSrcAddr"] != "0.0.0.0":
                o["echo_frame_source_address"] = p["echoSrcAddr"]
            lst.append(o)
        if lst:
            res[key] = lst
    return res

def capture_update_groups(apic: Apic):
    """node_policies.update_groups : firmware+maintenance groups (firmwareFwGrp /
    maintMaintGrp, même nom) + scheduler (maintRsPolScheduler) + target_version
    (maintMaintP.version) + membres (fabricNodeBlk -> nodes[].update_group).
    Exclut 'default'. Retourne (groupes, {node_id: groupe}). [audit 2026-07-03]"""
    sched = {}
    for rs in apic.get_class("maintRsPolScheduler"):
        name = _seg(rs["dn"], "maintpol")
        if name and rs.get("tnTrigSchedPName"):
            sched[name] = rs["tnTrigSchedPName"]
    versions = {p["name"]: p.get("version") for p in apic.get_class("maintMaintP")}
    # membres : fabricNodeBlk sous fwgrp-<name> (miroir sous maintgrp, meme contenu)
    members = defaultdict(set)
    for blk in apic.get_class("fabricNodeBlk"):
        name = _seg(blk["dn"], "fwgrp")
        if not name or name == "default":
            continue
        try:
            frm, to = int(blk.get("from_", 0)), int(blk.get("to_", 0))
        except (TypeError, ValueError):
            continue
        members[name].update(range(frm, (to or frm) + 1))
    out, ug_nodes = [], {}
    for g in apic.get_class("firmwareFwGrp"):
        name = g.get("name")
        if not name or name == "default":
            continue
        ug = {"name": name}
        if versions.get(name):
            ug["target_version"] = versions[name]
        if sched.get(name) and sched[name] != "default":     # defaut scheduler 'default'
            ug["scheduler"] = sched[name]
        out.append(ug)
        for nid in members.get(name, ()):
            ug_nodes[nid] = name
    return out, ug_nodes

def capture_schedulers(apic: Apic):
    """fabric schedulers (trigSchedP) : name/descr + recurring_windows (trigRecurrWindowP).
    Exclut les schedulers SYSTEME (uid=0 : ConstSchedP, EveryEightHours...)."""
    wins = _by_parent(apic.get_class("trigRecurrWindowP"))   # par trigSchedP DN
    out = []
    for s in apic.get_class("trigSchedP"):
        if s.get("uid") == "0":                              # systeme
            continue
        so = {"name": s["name"]}
        if s.get("descr"):
            so["description"] = s["descr"]
        rws = []
        for w in wins.get(s["dn"], []):
            rw = {"name": w["name"]}
            if w.get("day") and w["day"] != "every-day":     # defaut every-day
                rw["day"] = w["day"]
            if w.get("hour") and w["hour"] != "0":           # defaut 0
                rw["hour"] = int(w["hour"])
            if w.get("minute") and w["minute"] != "0":       # defaut 0
                rw["minute"] = int(w["minute"])
            rws.append(rw)
        if rws:
            so["recurring_windows"] = rws
        out.append(so)
    return out

def capture_interface_nodes(apic: Apic):
    """interface_policies.nodes[] : fusionne par (node,module,port) les attributs
    port-level — type (infraRsPortDirection) et shutdown (fabricRsOosPath), y
    compris sub-ports (eth m/p/s -> interfaces[].sub_ports) et ports FEX
    (extpaths -> nodes[].fexes[].interfaces) [audit 2026-07-03]."""
    ifs = defaultdict(dict)     # (node,module,port) -> {attrs}
    fexes = defaultdict(dict)   # (node,fex) -> {(module,port) -> attrs}
    for x in apic.get_class("infraRsPortDirection"):
        mm = re.search(r"paths-(\d+)/pathep-\[eth(\d+)/(\d+)\]", x.get("tDn", ""))
        if mm:
            k = (int(mm.group(1)), int(mm.group(2)), int(mm.group(3)))
            ifs[k]["type"] = "uplink" if x.get("direc") == "UpLink" else "downlink"
    for x in apic.get_class("fabricRsOosPath"):
        dn = x.get("dn", "")
        mf = re.search(r"paths-(\d+)/extpaths-(\d+)/pathep-\[eth(\d+)/(\d+)\]", dn)
        ms = re.search(r"paths-(\d+)/pathep-\[eth(\d+)/(\d+)/(\d+)\]", dn)
        mp = re.search(r"paths-(\d+)/pathep-\[eth(\d+)/(\d+)\]", dn)
        if mf:                                   # port FEX
            node, fex, mod, port = (int(g) for g in mf.groups())
            fexes[(node, fex)][(mod, port)] = {"shutdown": True}
        elif ms:                                 # sub-port (breakout)
            node, mod, port, sub = (int(g) for g in ms.groups())
            ifs[(node, mod, port)].setdefault("sub_ports", {})[sub] = \
                {"port": sub, "shutdown": True}
        elif mp:
            k = (int(mp.group(1)), int(mp.group(2)), int(mp.group(3)))
            ifs[k]["shutdown"] = True
    by_node = defaultdict(dict)
    for (node, mod, port), attrs in sorted(ifs.items()):
        sp = attrs.pop("sub_ports", None)
        e = {"module": mod, "port": port, **attrs}
        if sp:
            e["sub_ports"] = [sp[s] for s in sorted(sp)]
        by_node[node].setdefault("interfaces", []).append(e)
    for (node, fex), ports in sorted(fexes.items()):
        by_node[node].setdefault("fexes", []).append(
            {"id": fex, "interfaces": [{"module": m, "port": p, **a}
                                       for (m, p), a in sorted(ports.items())]})
    return [{"id": n, **v} for n, v in sorted(by_node.items())]

def _capture_tree(apic):
    """Construit la PHOTO complete de la fabric EN MEMOIRE (aucune ecriture).
    Retourne (flat, tns, warnings). Utilisee par capture (qui ecrit data/) et
    par drift (qui compare sans rien toucher)."""
    warnings = []
    # 1. passe PLATE (list-classes : leaf/switch profiles, interface policies, vpc/mst...)
    flat = capture_flat(apic)
    # 1b. SINGLETONS (global_settings, coop, isis, control_plane_mtu... a leurs vraies valeurs)
    for section, tree in capture_singletons(apic).items():
        _deep_merge(flat[section], tree)
    # 2. passe HIERARCHIQUE : enrichit access (vlan pools+ranges, domaines, aaep) + tenants
    ap = capture_access(apic, warnings)
    _deep_merge(flat["access_policies"], ap)
    # 2b. selecteurs d'interface (infraHPortS) -> enrichit les leaf_interface_profiles par nom
    sels = capture_leaf_selectors(apic)
    for prof in flat["access_policies"].get("leaf_interface_profiles", []):
        if prof["name"] in sels:
            prof["selectors"] = sels[prof["name"]]
    # 2c. monitoring policies : access (monInfraPol) + fabric (monFabricPol)
    mon = capture_monitoring_policies(apic, "monInfraPol", "monInfraTarget")
    if mon:
        flat["access_policies"].setdefault("monitoring", {})["policies"] = mon
    monf = capture_monitoring_policies(apic, "monFabricPol", "monFabricTarget")
    if monf:
        flat["fabric_policies"].setdefault("monitoring", {})["policies"] = monf
    common_mon = capture_common_monitoring(apic)                            # [#87]
    if common_mon:
        flat["fabric_policies"].setdefault("monitoring", {}).setdefault("policies", []).append(common_mon)
    slg = capture_syslog_policies(apic)                                    # [#48]
    if slg:
        flat["fabric_policies"].setdefault("monitoring", {})["syslogs"] = slg
    flspg = capture_fabric_leaf_switch_pgs(apic)                            # [#52]
    if flspg:
        flat["fabric_policies"]["leaf_switch_policy_groups"] = flspg
    flsprof = capture_fabric_leaf_switch_profiles(apic)                    # [#52]
    if flsprof:
        flat["fabric_policies"]["leaf_switch_profiles"] = flsprof
    fsspg = capture_fabric_spine_switch_pgs(apic)                          # [#53]
    if fsspg:
        flat["fabric_policies"]["spine_switch_policy_groups"] = fsspg
    fssprof = capture_fabric_spine_switch_profiles(apic)                  # [#53]
    if fssprof:
        flat["fabric_policies"]["spine_switch_profiles"] = fssprof
    lspg = capture_leaf_switch_pgs(apic)                                    # [#49]
    if lspg:
        flat["access_policies"]["leaf_switch_policy_groups"] = lspg
    lsprof = capture_leaf_switch_profiles(apic)                            # [#50]
    if lsprof:
        flat["access_policies"]["leaf_switch_profiles"] = lsprof
    sspg = capture_spine_switch_pgs(apic)                                  # [#51]
    if sspg:
        flat["access_policies"]["spine_switch_policy_groups"] = sspg
    ssprof = capture_spine_switch_profiles(apic)                          # [#51]
    if ssprof:
        flat["access_policies"]["spine_switch_profiles"] = ssprof
    # selecteurs d'interface fabric (leaf + spine) -> enrichit les profils par nom
    fsels = capture_fabric_selectors(apic, "fabricLFPortS", "fabricRsLePortPGrp",
                                     "rslePortPGrp", "leportp", "leportgrp")
    for prof in flat["fabric_policies"].get("leaf_interface_profiles", []):
        if prof["name"] in fsels:
            prof["selectors"] = fsels[prof["name"]]
    ssels = capture_fabric_selectors(apic, "fabricSFPortS", "fabricRsSpPortPGrp",
                                     "rsspPortPGrp", "spportp", "spportgrp")
    for prof in flat["fabric_policies"].get("spine_interface_profiles", []):
        if prof["name"] in ssels:
            prof["selectors"] = ssels[prof["name"]]
    # access SPINE selectors (infraSHPortS) -> enrichit access_policies.spine_interface_profiles  [#35]
    asels = capture_fabric_selectors(apic, "infraSHPortS", "infraRsSpAccGrp",
                                     "rsspAccGrp", "spaccportprof", "spaccportgrp",
                                     blk_class="infraPortBlk")
    for prof in flat["access_policies"].get("spine_interface_profiles", []):
        if prof["name"] in asels:
            prof["selectors"] = asels[prof["name"]]
    # span filter groups (spanFilterGrp + entries) -> access_policies.span.filter_groups  [#36]
    sfg = capture_span_filter_groups(apic)
    if sfg:
        flat["access_policies"].setdefault("span", {})["filter_groups"] = sfg
    sdg = capture_span_destination_groups(apic)                            # [#37]
    if sdg:
        flat["access_policies"].setdefault("span", {})["destination_groups"] = sdg
    vdg = capture_vspan_destination_groups(apic)                           # [#38]
    if vdg:
        flat["access_policies"].setdefault("vspan", {})["destination_groups"] = vdg
    vss = capture_vspan_sessions(apic)                                     # [#39]
    if vss:
        flat["access_policies"].setdefault("vspan", {})["sessions"] = vss
    ssrcg = capture_span_source_groups(apic)                               # [#40]
    if ssrcg:
        flat["access_policies"].setdefault("span", {})["source_groups"] = ssrcg
    fdg = capture_span_destination_groups(apic, "uni/fabric/")             # [#41] fabric span dest
    if fdg:
        flat["fabric_policies"].setdefault("span", {})["destination_groups"] = fdg
    fsg = capture_fabric_span_source_groups(apic)                          # [#41] fabric span source
    if fsg:
        flat["fabric_policies"].setdefault("span", {})["source_groups"] = fsg
    # link-level policies (fabricHIfPol) : compléter autoNeg (ternaire) + portPhyMediaType
    # (conditionnel) que attr_map ne sait pas parser. Émission non-défaut. [#43]
    llp = {p["name"]: p for p in apic.get_class("fabricHIfPol")}
    for e in flat["access_policies"].get("interface_policies", {}).get("link_level_policies", []):
        p = llp.get(e["name"])
        if not p:
            continue
        if p.get("autoNeg") == "on-enforce":             # défaut 'on' (auto=true, auto_enforce=false)
            e["auto_enforce"] = True
        elif p.get("autoNeg") == "off":
            e["auto"] = False
        if p.get("portPhyMediaType") and p["portPhyMediaType"] != "auto":   # défaut auto
            e["physical_media_type"] = p["portPhyMediaType"]
    # priority-flow-control (qosPfcIfPol) : adminSt = auto_state?auto:(admin_state?on:off) [#44]
    # ternaire 3-états non parsé par attr_map. Défaut auto (auto_state=true). Émission non-défaut.
    pfc = {p["name"]: p for p in apic.get_class("qosPfcIfPol")}
    for e in flat["access_policies"].get("interface_policies", {}).get("priority_flow_control_policies", []):
        p = pfc.get(e["name"])
        if not p:
            continue
        if p.get("adminSt") == "on":                         # auto_state false, admin_state true (défaut)
            e["auto_state"] = False
        elif p.get("adminSt") == "off":                      # auto_state false ET admin_state false
            e["auto_state"] = False
            e["admin_state"] = False
    # netflow-record (netflowRecordPol) : match = join(",", sort(var.match_parameters)) — le sort()
    # empêche _RE_JOIN de matcher -> match_parameters non capturé. Enrichissement. [#45]
    nfr = {p["name"]: p for p in apic.get_class("netflowRecordPol") if "/infra/" in p["dn"]}
    for e in flat["access_policies"].get("interface_policies", {}).get("netflow_records", []):
        p = nfr.get(e["name"])
        if p and p.get("match"):
            e["match_parameters"] = sorted(p["match"].split(","))
    # netflow ACCESS exporters/monitors : relations (miroir #68 tenant, scope uni/infra) [#82]
    nfae_ctx = {_parent(x["dn"]): x for x in apic.get_class("netflowRsExporterToCtx") if "/infra/" in x["dn"]}
    nfae_epg = {_parent(x["dn"]): x for x in apic.get_class("netflowRsExporterToEPg") if "/infra/" in x["dn"]}
    nfae = {p["name"]: p for p in apic.get_class("netflowExporterPol") if "/infra/" in p["dn"]}
    for e in flat["access_policies"].get("interface_policies", {}).get("netflow_exporters", []):
        p = nfae.get(e["name"])
        if not p:
            continue
        ctx = nfae_ctx.get(p["dn"])
        if ctx and ctx.get("tDn"):
            e["tenant"] = _seg(ctx["tDn"], "tn"); e["vrf"] = _seg(ctx["tDn"], "ctx")
        epg = nfae_epg.get(p["dn"])
        if epg and epg.get("tDn"):
            tdn = epg["tDn"]; e["tenant"] = _seg(tdn, "tn")
            if "/ap-" in tdn:
                e["epg_type"] = "epg"; e["application_profile"] = _seg(tdn, "ap"); e["endpoint_group"] = _seg(tdn, "epg")
            elif "/out-" in tdn:
                e["epg_type"] = "external_epg"; e["l3out"] = _seg(tdn, "out"); e["external_endpoint_group"] = _seg(tdn, "instP")
    nfam = {p["name"]: p for p in apic.get_class("netflowMonitorPol") if "/infra/" in p["dn"]}
    nfam_rec = {_parent(x["dn"]): x for x in apic.get_class("netflowRsMonitorToRecord") if "/infra/" in x["dn"]}
    nfam_exp = _by_parent([x for x in apic.get_class("netflowRsMonitorToExporter") if "/infra/" in x["dn"]])
    for e in flat["access_policies"].get("interface_policies", {}).get("netflow_monitors", []):
        p = nfam.get(e["name"])
        if not p:
            continue
        rec = nfam_rec.get(p["dn"])
        if rec and rec.get("tnNetflowRecordPolName"):
            e["flow_record"] = rec["tnNetflowRecordPolName"]
        exps = sorted(x["tnNetflowExporterPolName"] for x in nfam_exp.get(p["dn"], [])
                      if x.get("tnNetflowExporterPolName"))
        if exps:
            e["flow_exporters"] = exps
    # port-channel (lacpLagPol) : ctrl = join(",", local.ctrl) — le concat est dans un LOCAL
    # (pas inline) -> non vu par le handler flag de attr_map. Reverse dédié + hash_key. [#81]
    lags = {p["name"]: p for p in apic.get_class("lacpLagPol")}
    lb = {_parent(x["dn"]): x.get("hashFields") for x in apic.get_class("l2LoadBalancePol")}
    PC_FLAGS = {"fast-sel-hot-stdby": "fast_select_standby", "graceful-conv": "graceful_convergence",
                "load-defer": "load_defer", "susp-individual": "suspend_individual",
                "symmetric-hash": "symmetric_hash"}
    for e in flat["access_policies"].get("interface_policies", {}).get("port_channel_policies", []):
        p = lags.get(e["name"])
        if not p:
            continue
        ctrl = set(filter(None, p.get("ctrl", "").split(",")))
        for flag, key in PC_FLAGS.items():
            e[key] = flag in ctrl
        if "symmetric-hash" in ctrl and lb.get(p["dn"]):
            e["hash_key"] = lb[p["dn"]]
    # access-spine + fabric-leaf interface policy groups : base captée par le générique
    # (name), enrichir les relations (infraSpAccPortGrp / fabricLePortPGrp). macsec omis. [#89]
    sp_ll = {_parent(x["dn"]): x.get("tnFabricHIfPolName") for x in apic.get_class("infraRsHIfPol") if "spaccportgrp-" in x.get("dn", "")}
    sp_cdp = {_parent(x["dn"]): x.get("tnCdpIfPolName") for x in apic.get_class("infraRsCdpIfPol") if "spaccportgrp-" in x.get("dn", "")}
    sp_aaep = {_parent(x["dn"]): _seg(x.get("tDn", ""), "attentp") for x in apic.get_class("infraRsAttEntP") if "spaccportgrp-" in x.get("dn", "")}
    for e in flat["access_policies"].get("spine_interface_policy_groups", []):
        dn = "uni/infra/funcprof/spaccportgrp-" + e["name"]
        if sp_ll.get(dn):
            e["link_level_policy"] = sp_ll[dn]
        if sp_cdp.get(dn):
            e["cdp_policy"] = sp_cdp[dn]
        if sp_aaep.get(dn):
            e["aaep"] = sp_aaep[dn]
    fl_ll = {_parent(x["dn"]): x.get("tnFabricFIfPolName") for x in apic.get_class("fabricRsFIfPol")}
    for e in flat["fabric_policies"].get("leaf_interface_policy_groups", []):
        dn = "uni/fabric/funcprof/leportgrp-" + e["name"]
        if fl_ll.get(dn):
            e["link_level_policy"] = fl_ll[dn]
    # storm-control (stormctrlIfPol) : isUcMcBcStormPktCfgValid = configuration_type=="separate"?Valid:Invalid
    # ternaire non parsé par attr_map. Défaut configuration_type=separate (Valid). Émission non-défaut. [#46]
    scp = {p["name"]: p for p in apic.get_class("stormctrlIfPol")}
    for e in flat["access_policies"].get("interface_policies", {}).get("storm_control_policies", []):
        p = scp.get(e["name"])
        if p and p.get("isUcMcBcStormPktCfgValid") == "Invalid":   # Valid=separate (défaut)
            e["configuration_type"] = "all"
    # ptp-profile (ptpProfile) : profileTemplate/ptpoeDstMacRxNoMatch/ptpoeDstMacType = ternaires
    # non parsés par attr_map (intervalles numériques OK en direct). Émission non-défaut. [#47]
    ptpp = {p["name"]: p for p in apic.get_class("ptpProfile")}
    for e in flat["access_policies"].get("ptp_profiles", []):
        p = ptpp.get(e["name"])
        if not p:
            continue
        tmpl = {"telecom_full_path": "telecom", "smpte": "smpte"}.get(p.get("profileTemplate"))  # aes67=défaut
        if tmpl:
            e["template"] = tmpl
        mh = {"replyWithRxMac": "received", "drop": "drop"}.get(p.get("ptpoeDstMacRxNoMatch"))  # replyWithCfgMac=configured(défaut)
        if mh:
            e["mismatch_handling"] = mh
        if p.get("ptpoeDstMacType") == "non-forwardable":          # défaut forwardable
            e["forwardable"] = False
    # 2d. interface_policies.nodes : type (infraRsPortDirection) + shutdown (fabricRsOosPath)
    inodes = capture_interface_nodes(apic)
    if inodes:
        flat["interface_policies"]["nodes"] = inodes
    # 2e. fabric schedulers (trigSchedP, hors systeme)
    scheds = capture_schedulers(apic)
    if scheds:
        flat["fabric_policies"]["schedulers"] = scheds
    # 2f. update groups (firmware/maintenance) -> node_policies.update_groups
    # + appartenance des noeuds (nodes[].update_group) sans laquelle les groupes
    # seraient re-pousses VIDES [audit 2026-07-03]
    ugroups, ug_nodes = capture_update_groups(apic)
    if ugroups:
        flat["node_policies"]["update_groups"] = ugroups
    if ug_nodes:
        npn = {n["id"]: n for n in flat["node_policies"].get("nodes", [])}
        for nid, gname in ug_nodes.items():
            npn.setdefault(nid, {"id": nid})["update_group"] = gname
        flat["node_policies"]["nodes"] = [npn[k] for k in sorted(npn)]
    # 2f-bis. bgp route reflectors (bgpRRNodePEp, rr/ interne, extrr/ externe)
    # -> fabric_policies.fabric_bgp_rr / fabric_bgp_ext_rr [audit 2026-07-03]
    rrs, extrrs = [], []
    for r in apic.get_class("bgpRRNodePEp"):
        (extrrs if "/extrr/" in r["dn"] else rrs).append(int(r["id"]))
    if rrs:
        flat["fabric_policies"]["fabric_bgp_rr"] = sorted(rrs)
    if extrrs:
        flat["fabric_policies"]["fabric_bgp_ext_rr"] = sorted(extrrs)
    # 2g. bfd switch policies -> access_policies.switch_policies
    bfd = capture_bfd_policies(apic)
    if bfd:
        flat["access_policies"].setdefault("switch_policies", {}).update(bfd)
    # 2h. psu policies -> fabric_policies.switch_policies
    psu = capture_psu_policies(apic)
    if psu:
        flat["fabric_policies"].setdefault("switch_policies", {})["psu_policies"] = psu
    # 2i. config exports -> fabric_policies.config_exports
    cexp = capture_config_exports(apic)
    if cexp:
        flat["fabric_policies"]["config_exports"] = cexp
    # 2i-bis. SNMP policies fabric -> fabric_policies.pod_policies.snmp_policies [#75]
    snmp = capture_snmp_policies(apic)
    if snmp:
        flat["fabric_policies"].setdefault("pod_policies", {})["snmp_policies"] = snmp
    # 2i-ter. DNS policies fabric -> fabric_policies.dns_policies [#76]
    dns = capture_dns_policies(apic)
    if dns:
        flat["fabric_policies"]["dns_policies"] = dns
    # 2i-duodecies. fex interface profiles + selecteurs [#102-#103]
    fex = capture_fex_profiles(apic)
    if fex:
        flat["access_policies"]["fex_interface_profiles"] = fex
    # 2i-undecies. objets AAA (radius/tacacs/users/ca-certs/login-domains) [#96-#100]
    aaa_set = capture_aaa_settings(apic)
    if aaa_set:
        flat["fabric_policies"].setdefault("aaa", {}).update(aaa_set)
    aaa_sec = capture_aaa_security(apic)
    if aaa_sec:
        flat["fabric_policies"].setdefault("aaa", {}).update(aaa_sec)
    # 2i-nonies. mst policies -> access_policies.switch_policies.mst_policies [#93]
    mst = capture_mst_policies(apic)
    if mst:
        flat["access_policies"].setdefault("switch_policies", {})["mst_policies"] = mst
    # 2i-decies. vpc groups -> node_policies.vpc_groups.groups [#94]
    vg = capture_vpc_groups(apic)
    if vg:
        flat["node_policies"].setdefault("vpc_groups", {})["groups"] = vg
    # 2i-terdecies. adresses mgmt statiques (noeuds NON enregistres) [#104-#105]
    na = capture_node_addresses(apic, warnings)
    if na:
        flat["node_policies"].update(na)
    # 2i-octies. geolocation -> fabric_policies.geolocation.sites [#91]
    geo = capture_geolocation(apic)
    if geo:
        flat["fabric_policies"]["geolocation"] = {"sites": geo}
    # 2i-septies. infra dhcp relay -> access_policies.dhcp_relay_policies [#84]
    idr = capture_infra_dhcp_relay_policies(apic)
    if idr:
        flat["access_policies"]["dhcp_relay_policies"] = idr
    # 2i-quater. date-time policies fabric -> pod_policies.date_time_policies [#77]
    dtp = capture_date_time_policies(apic)
    if dtp:
        flat["fabric_policies"].setdefault("pod_policies", {})["date_time_policies"] = dtp
    # 2i-quinquies. fabric pod policy groups -> fabric_policies.pod_policy_groups [#78]
    podpg = capture_fabric_pod_policy_groups(apic)
    if podpg:
        flat["fabric_policies"]["pod_policy_groups"] = podpg
    # 2i-sexies. management access policies -> pod_policies.management_access_policies [#79]
    mgmta = capture_management_access_policies(apic)
    if mgmta:
        flat["fabric_policies"].setdefault("pod_policies", {})["management_access_policies"] = mgmta
    # 2i-septies. qos classes fabric -> access_policies.qos.qos_classes [audit 2026-07-03]
    qcls = capture_qos_classes(apic)
    if qcls:
        flat["access_policies"].setdefault("qos", {})["qos_classes"] = qcls
    # 2j. macsec parameters policies -> access_policies.interface_policies
    macsec = capture_macsec_param_policies(apic)
    if macsec:
        flat["access_policies"].setdefault("interface_policies", {})["macsec_parameters_policies"] = macsec
    # 2i-quindecies. objets a secret write-only (geres SAUF le secret) [#113-#116]
    sec = capture_secretful_policies(apic)
    if sec.get("remote_locations"):
        flat["fabric_policies"]["remote_locations"] = sec["remote_locations"]
    if sec.get("key_rings"):
        flat["fabric_policies"].setdefault("aaa", {})["key_rings"] = sec["key_rings"]
    if sec.get("macsec_keychain_access"):
        flat["access_policies"].setdefault("interface_policies", {})[
            "macsec_keychain_policies"] = sec["macsec_keychain_access"]
    if sec.get("macsec_keychain_fabric"):
        flat["fabric_policies"]["macsec_keychain_policies"] = sec["macsec_keychain_fabric"]
    if sec.get("macsec_if_access"):
        flat["access_policies"].setdefault("interface_policies", {})[
            "macsec_interfaces_policies"] = sec["macsec_if_access"]
    if sec.get("macsec_if_fabric"):
        flat["fabric_policies"]["macsec_interfaces_policies"] = sec["macsec_if_fabric"]
    # 2i-quaterdecies. NOUVEAU paradigme d'interfaces + auto-detection [#110-#112]
    np_ifaces, np_nodes, np_roles = capture_port_configurations(apic, warnings)
    new_style = bool(np_ifaces or np_nodes)
    classic_style = bool(flat["access_policies"].get("leaf_interface_profiles")
                         or flat["access_policies"].get("spine_interface_profiles")
                         or flat["fabric_policies"].get("leaf_interface_profiles"))
    if new_style:
        # deduplication : le shutdown nouveau-style cree AUSSI un fabricRsOosPath
        # cote APIC, que le lecteur classique recapture -> le port config est
        # proprietaire du port, on retire l'entree classique equivalente
        owned = {(nid, i.get("module", 1), i["port"]) for nid, il in np_ifaces.items() for i in il}
        by_id = {n["id"]: n for n in flat["interface_policies"].get("nodes", [])}
        for n in by_id.values():
            n["interfaces"] = [i for i in n.get("interfaces", [])
                               if (n["id"], i.get("module", 1), i["port"]) not in owned]
        for nid, il in np_ifaces.items():
            by_id.setdefault(nid, {"id": nid}).setdefault("interfaces", []).extend(il)
        for n in by_id.values():                 # cle interfaces vide -> retiree
            if not n.get("interfaces"):
                n.pop("interfaces", None)
        flat["interface_policies"]["nodes"] = [n for _, n in sorted(by_id.items())
                                               if n.get("interfaces") or n.get("fexes")]
        npn = {n["id"]: n for n in flat["node_policies"].get("nodes", [])}
        for nid in sorted(set(np_roles) | set(np_nodes)):
            e = npn.setdefault(nid, {"id": nid})
            e["role"] = np_roles.get(nid, "leaf")
            e.update(np_nodes.get(nid, {}))
        flat["node_policies"]["nodes"] = [npn[k] for k in sorted(npn)]
        if classic_style:
            warnings.append("MIXED fabric: both interface styles coexist; "
                            "new_interface_configuration flag NOT set (classic style "
                            "managed, per-port style captured read-only)")
        else:
            # fabric 100% nouveau style -> poser le drapeau (ecrit dans la
            # section interface_policies par cmd_capture)
            flat["interface_policies"]["__new_paradigm__"] = True
    tns = capture_tenants(apic, warnings)
    return flat, tns, warnings

def cmd_capture(args):
    apic = Apic(*load_creds())
    ver = apic.login()
    log.info("Connected to APIC %s (v%s) — READ-ONLY.", apic.url, ver)
    flat, tns, warnings = _capture_tree(apic)
    # FAIL-CLOSED : une photo TRONQUEE (classe illisible : timeout/403/503) ecrite
    # dans data/ remettrait les DEFAUTS au sync (ex : vzAny.preferred_group ->
    # disabled = perte des contrats vzAny du VRF). On n'ecrit RIEN.
    # [audit adversarial 2026-07-06 M3]
    if apic.read_failures:
        log.error("ABORTED: capture incomplete — %d class(es) unreadable on the APIC, "
                  "refusing to write a truncated snapshot:", len(apic.read_failures))
        for f in apic.read_failures[:10]:
            log.error("   %s", f)
        return 1
    # 3. ecriture par section — TOUTES les sections connues, TOUJOURS, meme vides :
    # la capture est une PHOTO complete. Sauter une section vide/absente laisserait
    # survivre l'ancien fichier (objets disparus de la fabric -> data/ perime).
    # [bug corrige 2026-07-02]
    # drapeau du paradigme d'interfaces : cle apic.new_interface_configuration,
    # portee par le fichier interface_policies.nac.yaml (les cles apic.* de tous
    # les fichiers data/ sont fusionnees par le module NaC)
    new_flag = bool((flat.get("interface_policies") or {}).pop("__new_paradigm__", False))
    if new_flag:
        log.info("  per-port interface paradigm detected -> new_interface_configuration: true")
    for section, fname in SECTION_OUT.items():
        _write_section(fname, section, flat.get(section) or {},
                       f"Captured {section} (full attributes, derived from the NaC modules).",
                       extra_apic={"new_interface_configuration": True}
                       if (new_flag and section == "interface_policies") else None)
    p2 = _write_section("tenants.nac.yaml", "tenants", tns,
                        "Captured tenants (full attributes).")
    # toggles : desactive les singletons a secret (sinon terraform echoue a les creer)
    import yaml
    with open(os.path.join(DATA_DIR, "modules.nac.yaml"), "w") as f:
        f.write("# Disabled modules: secret-bearing objects that cannot be captured (key required).\n"
                "# Generated by tools/nac.py.\n---\n"
                + yaml.safe_dump({"modules": DISABLE_MODULES}, sort_keys=False))
    log.info("  access_policies : %s", ", ".join(
        f"{k}={len(v) if isinstance(v, list) else 1}" for k, v in flat["access_policies"].items()))
    for section in ("fabric_policies", "node_policies", "pod_policies"):
        if flat.get(section):
            log.info("  %s : %s", section, ", ".join(
                f"{k}={len(v) if isinstance(v, list) else 1}" for k, v in flat[section].items()))
    napp = len([t for t in tns if t.get("managed") is not False])
    log.info("  %s : %d application tenant(s)", p2, napp)
    for t in tns:
        if t.get("managed") is False:
            continue
        log.info("     %s: %s", t["name"],
                 ", ".join(f"{k}={len(v)}" for k, v in t.items() if isinstance(v, list)))
    if warnings:
        log.warning("  ⚠️  %d incomplete object(s) skipped:", len(warnings))
        for w in warnings:
            log.warning("     - %s", w)
    return 0

def _run(cmd, **kw):
    import subprocess
    return subprocess.run(cmd, cwd=ROOT, **kw)

def cmd_validate(args):
    candidates = [os.path.join(ROOT, ".venv", "bin", "nac-validate"),
                  os.path.join(os.path.dirname(sys.executable), "nac-validate")]
    exe = next((c for c in candidates if os.path.exists(c)), "nac-validate")
    try:
        return _run([exe, "data/"]).returncode
    except FileNotFoundError:
        log.warning("nac-validate not found -> schema validation SKIPPED "
                    "(pip install nac-validate to enable it)")
        return 0

def cmd_plan(args):
    return _run(["terraform", "plan", "-input=false"]).returncode

# classes portant un secret write-only : les CREER par-dessus un objet existant
# POSTerait un placeholder PAR-DESSUS le vrai secret (ignore_changes ne protege
# qu'APRES l'entree dans le state). Adoption de l'existant = `adopt` uniquement.
SECRET_CLASSES = {"aaaUser", "aaaRadiusProvider", "aaaTacacsPlusProvider",
                  "aaaLdapProvider", "fileRemotePath", "pkiKeyRing",
                  "macsecKeyChainPol", "mcpInstPol", "licenseLicPolicy", "snmpTrapDest",
                  "ospfIfP",     # authKey placeholder quand l'auth OSPF est active
                  "bfdMhNodeP",  # key BFD multihop write-only (auth active) [audit 2026-07-06]
                  # ENFANT du keychain : un CREATE isole (keychain deja en state)
                  # POSTerait le PSK placeholder par-dessus la vraie cle [audit 2026-07-03]
                  "macsecKeyPol",
                  # le cablage nac-aci envoie key="" (pas null) au create -> viderait
                  # la cle HSRP MD5 d'une fabric brownfield [audit 2026-07-03]
                  "hsrpGroupPol",
                  # singleton uni/exportcryptkey : un create authore a la main
                  # remplacerait la passphrase AES reelle [audit 2026-07-03]
                  "pkiExportEncryptionKey",
                  # defensifs (jamais emis par capture, mais authoring manuel possible)
                  "snmpUserP", "vmmUsrAccP", "fvPeeringP", "datetimeNtpAuthKey",
                  # password jamais capture ni envoye (null omis) — defense en
                  # profondeur si un usager ecrit un password: dans le YAML pour
                  # un peer qui existe deja [audit adversarial 2026-07-06 F6]
                  "bgpPeerP"}

def _plan_changes():
    """terraform plan -> resource_changes (JSON, fiable) ou None si le plan echoue."""
    import subprocess, json
    pf = os.path.join(ROOT, ".guard.tfplan")
    r = subprocess.run(["terraform", "plan", "-input=false", f"-out={pf}"],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        return None
    show = subprocess.run(["terraform", "show", "-json", pf],
                          cwd=ROOT, capture_output=True, text=True)
    os.remove(pf)
    if show.returncode:
        return None
    return json.loads(show.stdout).get("resource_changes", [])

def _secret_overwrite_check(changes=None):
    """Garde-fou anti-ecrasement de secret : liste les CREATE du plan qui visent
    une classe a secret ET dont l'objet existe deja sur la fabric.
    FAIL-CLOSED : toute erreur (plan, lecture APIC) retourne None = BLOQUANT —
    on ne suppose JAMAIS qu'un objet n'existe pas parce que l'APIC n'a pas
    repondu (timeout/403/503 = la condition realiste qui menait a l'ecrasement).
    [audit adversarial 2026-07-06 C1]"""
    if changes is None:
        changes = _plan_changes()
    if changes is None:
        return None                                   # plan illisible -> bloquant
    cands = []
    for rc in changes:
        if "create" not in (rc.get("change", {}).get("actions") or []):
            continue
        after = rc["change"].get("after") or {}
        if after.get("class_name") in SECRET_CLASSES and after.get("dn"):
            cands.append((rc["address"], after["class_name"], after["dn"]))
    if not cands:
        return []
    try:
        apic = Apic(*load_creds())
        apic.login()
    except Exception as e:
        log.error("secret guard: APIC login failed (%s)", e)
        return None                                   # fail-closed
    hits = []
    for cls in {c for _, c, _ in cands}:
        try:
            dns = {x.get("dn") for x in apic.get_class(cls)}
        except Exception as e:                        # lecture impossible -> BLOQUANT
            log.error("secret guard: cannot read class %s (%s)", cls, e)
            return None                               # fail-closed [C1]
        hits += [(a, d) for a, c, d in cands if c == cls and d in dns]
    return hits

def cmd_sync(args):
    changes = _plan_changes()                         # source unique, JSON fiable [M4]
    if changes is None:
        log.error("ABORTED: terraform plan failed.")
        return 1
    ndes = sum(1 for rc in changes if "delete" in (rc.get("change", {}).get("actions") or []))
    nadd = sum(1 for rc in changes if "create" in (rc.get("change", {}).get("actions") or []))
    if ndes and not args.force:
        log.error("ABORTED: the plan would DESTROY %d object(s). Make sure data/ reflects the "
                  "fabric (run `nac.py capture`). Use --force to override.", ndes)
        return 1
    if nadd and not args.force:
        hits = _secret_overwrite_check(changes)
        if hits is None:
            log.error("ABORTED: the secret-overwrite guard could not verify the fabric "
                      "(APIC unreachable/unreadable). NOT applying — retry when the APIC "
                      "responds, or use --force knowingly.")
            return 1
        if hits:
            log.error("ABORTED: %d secret-bearing object(s) already EXIST on the fabric; "
                      "creating them would overwrite their real secret with a placeholder. "
                      "Use `nac.py adopt` (import, secret untouched) instead:", len(hits))
            for a, d in hits[:10]:
                log.error("   %s  (%s)", a, d)
            return 1
    if not args.yes:
        ans = input("terraform apply. Continue? [y/N] ")
        if ans.strip().lower() not in ("y", "yes", "o", "oui"):
            log.info("Cancelled."); return 1
    return _run(["terraform", "apply", "-input=false", "-auto-approve"]).returncode

_DRIFT_ID_KEYS = ("name", "id", "ip", "prefix", "hostname_ip", "mac", "username",
                  "vlan", "node_id", "class", "fault_id", "key", "contract",
                  "destination_name", "exp_from", "dscp_from", "from", "device",
                  "interface_name", "tenant", "module", "port")

def _drift_key(item):
    """Cle d'identite d'un element de liste (pour matcher YAML <-> fabric)."""
    if isinstance(item, dict):
        # valeur composite (ex. service_graph_templates[].device = {name: X}) :
        # repr() la rend hashable sans perdre l'identite
        k = tuple((f, item[f] if isinstance(item[f], (str, int, float, bool))
                   else repr(item[f]))
                  for f in _DRIFT_ID_KEYS if f in item)
        return k if k else ("_raw", repr(sorted(item.items(), key=str)))
    return ("_val", repr(item))

def _drift_label(key):
    return key[0][1] if key and isinstance(key[0], tuple) else "?"

def _drift_diff(path, yaml_v, fab_v, only_fabric, only_yaml, changed):
    """Compare recursivement YAML declare vs photo fabric (insensible a l'ordre)."""
    if isinstance(fab_v, dict) or isinstance(yaml_v, dict):
        yd = yaml_v if isinstance(yaml_v, dict) else {}
        fd = fab_v if isinstance(fab_v, dict) else {}
        for k in sorted(set(yd) | set(fd)):
            _drift_diff(f"{path}.{k}", yd.get(k), fd.get(k), only_fabric, only_yaml, changed)
    elif isinstance(fab_v, list) or isinstance(yaml_v, list):
        yl = yaml_v if isinstance(yaml_v, list) else []
        fl = fab_v if isinstance(fab_v, list) else []
        ym = {_drift_key(x): x for x in yl}
        fm = {_drift_key(x): x for x in fl}
        for k in fm:
            if k not in ym:
                only_fabric.append(f"{path}[{_drift_label(k)}]")
        for k in ym:
            if k not in fm:
                only_yaml.append(f"{path}[{_drift_label(k)}]")
        for k in set(ym) & set(fm):
            _drift_diff(f"{path}[{_drift_label(k)}]", ym[k], fm[k],
                        only_fabric, only_yaml, changed)
    else:
        if yaml_v is None and fab_v is not None:
            only_fabric.append(f"{path} = {fab_v!r}")
        elif fab_v is None and yaml_v is not None:
            only_yaml.append(f"{path} = {yaml_v!r}")
        elif _num(yaml_v) != _num(fab_v):
            changed.append(f"{path}: YAML={yaml_v!r}  fabric={fab_v!r}")

def cmd_drift(args):
    """Read-only three-way alignment check: fabric vs YAML vs Terraform state.

    Detects out-of-band changes that `terraform plan` alone CANNOT see —
    in particular objects created directly in the APIC GUI, which exist in
    neither the YAML nor the Terraform state. Writes nothing anywhere.
    Exit code: 0 = in sync, 2 = drift detected."""
    import yaml, subprocess
    apic = Apic(*load_creds())
    ver = apic.login()
    log.info("Connected to APIC %s (v%s) — READ-ONLY.", apic.url, ver)
    log.info(">> Building in-memory photo of the fabric...")
    flat, tns, _ = _capture_tree(apic)
    (flat.get("interface_policies") or {}).pop("__new_paradigm__", None)
    fabric = {sec: (flat.get(sec) or {}) for sec in SECTION_OUT}
    fabric["tenants"] = tns
    declared = {}
    for sec, fname in list(SECTION_OUT.items()) + [("tenants", "tenants.nac.yaml")]:
        fpath = os.path.join(DATA_DIR, fname)
        doc = yaml.safe_load(open(fpath)) if os.path.isfile(fpath) else None
        declared[sec] = ((doc or {}).get("apic") or {}).get(sec)
    only_fabric, only_yaml, changed = [], [], []
    for sec in fabric:
        _drift_diff(sec, declared.get(sec), fabric[sec], only_fabric, only_yaml, changed)
    log.info(">> Checking Terraform state alignment (terraform plan)...")
    pl = subprocess.run(["terraform", "plan", "-input=false", "-no-color"],
                        cwd=ROOT, capture_output=True, text=True)
    m = re.search(r"^(Plan:.*|No changes\..*)$", pl.stdout, re.M)
    state_line = m.group(0).strip() if m else "unavailable (terraform plan failed)"
    state_ok = state_line.startswith("No changes")
    log.info("=" * 64)
    log.info(" DRIFT REPORT")
    log.info("=" * 64)
    for title, items, sign in (
            ("[1] On the fabric but NOT in the YAML (created out-of-band)", only_fabric, "+"),
            ("[2] In the YAML but NOT on the fabric (deleted out-of-band)", only_yaml, "-"),
            ("[3] Attribute differences (modified out-of-band)", changed, "~")):
        log.info("%s: %d", title, len(items))
        for x in items[:20]:
            log.info("     %s %s", sign, x)
        if len(items) > 20:
            log.info("     ... and %d more", len(items) - 20)
    log.info("[4] Terraform state alignment: %s", state_line)
    drift = bool(only_fabric or only_yaml or changed) or not state_ok
    log.info("=" * 64)
    if drift:
        log.info(" VERDICT: DRIFT DETECTED — accept it with `capture` (+ `sync`/`adopt`), "
                 "or overwrite it with `sync`.")
        return 2
    log.info(" VERDICT: IN SYNC — fabric, YAML and Terraform state are aligned.")
    return 0

def cmd_adopt(args):
    """Adoption SANS ECRITURE fabric (terraform import, TF >= 1.5).

    1. terraform plan -out + show -json -> pour chaque objet 'to add', recupere
       son adresse Terraform et son DN APIC (connus au moment du plan).
    2. Genere des blocs `import { to=<adresse> id=<dn> }` dans imports_adopt.tf.
    3. Re-plan (garde-fou destroy) puis apply : une IMPORTATION lit l'objet sur
       la fabric et l'inscrit dans le state — AUCUN POST n'est envoye.
    Les objets sans DN connu au plan (ex: aci_rest 'workaround') sont laisses au
    circuit normal de creation. Le fichier imports_adopt.tf est supprime apres."""
    import subprocess, json
    imports_tf = os.path.join(ROOT, "imports_adopt.tf")
    planfile = os.path.join(ROOT, ".adopt.tfplan")
    if os.path.exists(imports_tf):
        os.remove(imports_tf)
    log.info(">> Analyzing plan (JSON) to discover addresses + DNs...")
    r = subprocess.run(["terraform", "plan", "-input=false", f"-out={planfile}"],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        return r.returncode
    show = subprocess.run(["terraform", "show", "-json", planfile],
                          cwd=ROOT, capture_output=True, text=True)
    os.remove(planfile)
    candidates, skipped = [], []
    for rc in json.loads(show.stdout).get("resource_changes", []):
        if rc.get("change", {}).get("actions") != ["create"]:
            continue
        dn = (rc["change"].get("after") or {}).get("dn")
        if rc.get("type") != "aci_rest_managed" or not dn:
            skipped.append(rc["address"])
            continue
        if ":" in dn:
            # le parseur d'import du provider ACI utilise ':' comme separateur
            # (ex: DN de mac tags) -> non importable, creation normale
            skipped.append(rc["address"])
            continue
        cls = (rc["change"].get("after") or {}).get("class_name")
        candidates.append((rc["address"], dn, cls))
    if not candidates:
        log.info("Nothing to adopt: no importable 'to add' object in the plan.")
        return 0
    # ne generer un bloc import QUE si l'objet existe reellement sur la fabric
    # (sinon 'Cannot import non-existent remote object' fait echouer TOUT le lot).
    # Verification PAR CLASSE (les DN a crochets imbriques passent mal en URL /mo/).
    classes = sorted({c for _, _, c in candidates if c})
    log.info(">> Verifying existence on the APIC (%d DNs, %d classes)...",
             len(candidates), len(classes))
    apic = Apic(*load_creds())
    apic.login()
    # FAIL-CLOSED : une classe illisible (timeout/403/503) rendrait ses objets
    # « absents » -> ils seraient CREES par-dessus l'existant a l'apply (placeholder
    # sur les classes a secret = ecrasement). On ABANDONNE au lieu de deviner.
    # [audit adversarial 2026-07-06 C1]
    fabric_dns = set()
    for cls in classes:
        try:
            fabric_dns.update(x.get("dn", "") for x in apic.get_class(cls))
        except Exception as e:
            log.error("ABORTED: cannot read class %s on the APIC (%s) — existence "
                      "unknown, refusing to guess. Retry when the APIC responds.", cls, e)
            return 1
    blocks = []
    for addr, dn, cls in candidates:
        if dn in fabric_dns:
            blocks.append(f'import {{\n  to = {addr}\n  id = "{dn}"\n}}\n')
        else:
            skipped.append(addr)
    if not blocks:
        log.info("None of the 'to add' objects exist on the fabric: nothing to import, "
                 "use `nac.py sync` to create them.")
        return 0
    with open(imports_tf, "w") as f:
        f.write("# Generated by `nac.py adopt` (write-free adoption) — removed after apply.\n\n"
                + "\n".join(blocks))
    log.info("%d object(s) to IMPORT (read-only).", len(blocks))
    if skipped:
        log.info("%d object(s) not importable (absent from the fabric, DN unknown at plan "
                 "time, or DN containing ':') -> normal creation: %s",
                 len(skipped), ", ".join(skipped[:5]) + ("..." if len(skipped) > 5 else ""))
    try:
        plan2 = subprocess.run(["terraform", "plan", "-input=false", "-no-color"],
                               cwd=ROOT, capture_output=True, text=True)
        if plan2.returncode:
            sys.stderr.write(plan2.stdout + plan2.stderr)
            return plan2.returncode
        m = re.search(r"^Plan:.*$", plan2.stdout, re.M)
        log.info(m.group(0) if m else "Plan unavailable")
        md = re.search(r"(\d+) to destroy", plan2.stdout)
        ndes = int(md.group(1)) if md else 0
        if ndes and not args.force:
            log.error("ABORTED: the plan would DESTROY %d object(s). Run `nac.py capture` "
                      "first, or use --force knowingly.", ndes)
            return 1
        # garde secret aussi ici : l'apply final peut contenir des CREATE residuels
        # (objets non importables : classe illisible, DN avec ':') qui POSTeraient
        # un placeholder par-dessus un vrai secret. [audit 2026-07-03]
        if not args.force:
            hits = _secret_overwrite_check()
            if hits is None:
                log.error("ABORTED: the secret-overwrite guard could not run (internal "
                          "plan failed). Fix the plan first, or use --force knowingly.")
                return 1
            if hits:
                log.error("ABORTED: %d residual CREATE(s) target a secret-bearing object "
                          "that already EXISTS on the fabric (not importable here):",
                          len(hits))
                for a, d in hits[:10]:
                    log.error("   %s  (%s)", a, d)
                return 1
        if not args.yes:
            ans = input("terraform apply (imports = read-only). Continue? [y/N] ")
            if ans.strip().lower() not in ("y", "yes", "o", "oui"):
                log.info("Cancelled.")
                return 1
        rc = _run(["terraform", "apply", "-input=false", "-auto-approve"]).returncode
        if rc == 0:
            log.info("Adoption complete. Verify with `nac.py plan` (expected: No changes).")
        return rc
    finally:
        if os.path.exists(imports_tf):
            os.remove(imports_tf)

def cmd_bootstrap(args):
    log.info("=" * 60)
    log.info(" NaC brownfield collection (READ-ONLY)")
    log.info("=" * 60)
    rc = cmd_capture(args)
    if rc: return rc
    log.info(">> Validation (nac-validate)...")
    cmd_validate(args)
    log.info(">> Preview (terraform plan, changes nothing)...")
    cmd_plan(args)
    if getattr(args, "adopt", False):
        log.info(">> Adoption (--adopt)...")
        return cmd_adopt(args)
    log.info("Collection complete. YAML written to data/. Adopt with `nac.py adopt` "
             "(write-free) or `nac.py sync`.")
    return 0

# ═══════════════════════════════════════════════════════ CLI
def main(argv=None):
    p = argparse.ArgumentParser(prog="nac.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("capture", help="read the fabric -> data/ (read-only)")
    sub.add_parser("validate", help="nac-validate on data/")
    sub.add_parser("plan", help="terraform plan (preview)")
    sp = sub.add_parser("sync", help="terraform apply (destroy guard included)")
    sp.add_argument("-y", "--yes", action="store_true", help="no confirmation prompt")
    sp.add_argument("--force", action="store_true", help="allow even if the plan destroys objects")
    sa = sub.add_parser("adopt", help="write-free adoption (bulk terraform import)")
    sa.add_argument("-y", "--yes", action="store_true", help="no confirmation prompt")
    sa.add_argument("--force", action="store_true", help="allow even if the plan destroys objects")
    sub.add_parser("drift", help="read-only 3-way check: fabric vs YAML vs state (exit 2 on drift)")
    sb = sub.add_parser("bootstrap", help="capture + validate + plan (+ adoption with --adopt)")
    sb.add_argument("--adopt", action="store_true", help="chain the adoption (bulk import)")
    sb.add_argument("-y", "--yes", action="store_true", help="no confirmation prompt")
    sb.add_argument("--force", action="store_true", help="allow even if the plan destroys objects")
    args = p.parse_args(argv)
    _setup_log(args.verbose)
    return {
        "capture": cmd_capture, "validate": cmd_validate, "plan": cmd_plan,
        "sync": cmd_sync, "adopt": cmd_adopt, "drift": cmd_drift,
        "bootstrap": cmd_bootstrap,
    }[args.cmd](args)

if __name__ == "__main__":
    sys.exit(main())
