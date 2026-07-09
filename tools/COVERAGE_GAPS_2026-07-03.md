# Couverture nac.py — passe exhaustive variable par variable (195 modules)

> Généré le 2026-07-03. Méthode : pour chaque module, chaque variable de variables.tf a été
> croisée avec son attribut/classe APIC (main.tf du module) puis avec le code de capture de tools/nac.py.
> Le détail par module (variable | statut | preuve) suit, par lots alphabétiques.


---

# LOT 1

# Couverture brownfield nac.py — batch 1 (27 modules)

Statuts : GÉNÉRIQUE (moteur plat/singleton/tenant-flat), DÉDIÉ (fonction capture_* citée), SECRET (documenté), STRUCTUREL (clé de nommage/câblage, pas d'état propre), **MANQUANT**.

## aaa — À TROUS (majeur)
Singleton (`aaaAuthRealm` primaire) : attr_map ne voit QUE le content du resource primaire ; les 8 autres resources du module (aaaDefaultAuth, aaaConsoleAuth, aaaDomain, aaaUserEp, aaaPwdStrengthProfile, aaaPwdProfile, pkiWebTokenData, aaaBlockLoginProfile) ne sont capturés nulle part (grep aaaDefaultAuth/aaaPwdProfile/pkiWebTokenData : 0 hit). MODULE_COVERAGE l.80 confirme « management_settings/password-profile (enfants) NON mappés ». capture_aaa_security (nac.py:2923) couvre d'AUTRES modules (radius/tacacs/ldap/user/login-domain/ca-cert), pas celui-ci.

| variable | statut | preuve |
|---|---|---|
| remote_user_login_policy | GÉNÉRIQUE singleton | defRolePolicy = var.x, aaaAuthRealm primaire ; _singleton_table var2pf |
| default_fallback_check | **MANQUANT** | aaaDefaultAuth (enfant), aucun capture |
| default_realm | **MANQUANT** | aaaDefaultAuth |
| default_login_domain | **MANQUANT** | aaaDefaultAuth providerGroup (ternaire complexe) |
| console_realm | **MANQUANT** | aaaConsoleAuth |
| console_login_domain | **MANQUANT** | aaaConsoleAuth |
| security_domains | **MANQUANT** | aaaDomain for_each (name/descr/restrictedRbacDomain), 0 hit nac.py |
| password_strength_check | **MANQUANT** | aaaUserEp pwdStrengthCheck |
| min/max_password_length | **MANQUANT** | aaaPwdStrengthProfile |
| password_strength_test_type | **MANQUANT** | aaaPwdStrengthProfile |
| password_class_flags | **MANQUANT** | aaaPwdStrengthProfile (join/sort) |
| password_change_during_interval / _count / _interval / no_change_interval / history_count | **MANQUANT** | aaaPwdProfile |
| web_token_timeout / web_token_max_validity / web_session_idle_timeout / include_refresh_session_records | **MANQUANT** | pkiWebTokenData |
| enable_login_block / login_block_duration / login_max_failed_attempts / _window | **MANQUANT** | aaaBlockLoginProfile |

## aaep — À TROUS
PHASE2, capture dédiée capture_access (nac.py:397, bloc aaeps l.444).

| variable | statut | preuve |
|---|---|---|
| name, description | DÉDIÉ | obj("terraform-aci-aaep","infraAttEntityP") l.448 |
| physical_domains / routed_domains | DÉDIÉ | infraRsDomP tDn "/phys-" et "/l3dom-" l.452 |
| endpoint_groups (tenant/ap/epg/vlan/primary_vlan/mode) | DÉDIÉ | infraRsFuncToEpg sous gen-default l.430 |
| endpoint_groups[].deployment_immediacy (instrImedcy) | **MANQUANT** (mineur) | non lu dans capture_access |
| endpoint_groups[].secondary_vlan | **MANQUANT** (mineur) | encap capturé comme `vlan`, pas de distinction secondary |
| infra_vlan | **MANQUANT** | infraProvAcc/dhcpInfraProvP/binding provacc : le filtre `"/gen-default/" not in dn` l.427 l'ignore ; infraProvAcc 0 hit nac.py |
| vmware_vmm_domains / nutanix_vmm_domains | **MANQUANT** | infraRsDomP tDn "/vmmp-" tombe dans `else []` l.452 (cohérent : modules vmm en PHASE2 non capturés) |

## access-fex-interface-profile — COUVERT
| name | DÉDIÉ | capture_fex_profiles nac.py:1837, boucle infraFexP l.1875 |

## access-fex-interface-selector — COUVERT
capture_fex_profiles (nac.py:1837, sélecteurs fexprof-).
| interface_profile | STRUCTUREL (clé du profil) | — |
| name / description | DÉDIÉ | l.1851-1854 (NB : descr jeté par l'APIC sur hports fex — documenté #103) |
| policy_group | DÉDIÉ | infraRsAccBaseGrp tDn l.1856 |
| policy_group_type | DÉDIÉ (par design) | type dérivé du PG dans data au push (docstring l.1840) |
| port_blocks | DÉDIÉ | infraPortBlk l.1862 |

## access-leaf-interface-policy-group — À TROUS
_capture_pgs (nac.py:477) : name, type(access/pc/vpc via lagT), 12 relations PG_RELATIONS, aaep.
| name, type(access/pc/vpc) | DÉDIÉ | l.498-503 |
| link_level/cdp/lldp/stp/mcp/l2/port_channel/storm_control/port_security/egress+ingress_dpp/pfc | DÉDIÉ | PG_RELATIONS l.462-475 |
| aaep | DÉDIÉ | infraRsAttEntP l.485 |
| description | **MANQUANT** | descr dans content infraAccGrp mais _capture_pgs n'émet que name/type/rels/aaep |
| type "breakout" + map | **MANQUANT** | _capture_pgs ne requête que infraAccPortGrp/infraAccBndlGrp ; infraBrkoutPortGrp + brkoutMap 0 hit |
| macsec_interface_policy | **MANQUANT** (omission documentée #88 « macsec-if omis ») | infraRsMacsecIfPol absent de PG_RELATIONS |
| port_channel_member_name / port_channel_member_policy | **MANQUANT** | infraAccBndlSubgrp / infraRsLacpInterfacePol 0 hit |
| netflow_monitor_policies | **MANQUANT** | infraRsNetflowMonitorPol 0 hit |

## access-leaf-interface-profile — COUVERT
| name, description | GÉNÉRIQUE flat (infraAccPortP) | content name/descr simples ; _flat_table |

## access-leaf-interface-selector — À TROUS
capture_leaf_selectors (nac.py:1801). RESTE documenté l.23 MODULE_COVERAGE : « sub_port_blocks, fex, port_channel_member_policy ».
| interface_profile | STRUCTUREL | clé de rattachement |
| name / description | DÉDIÉ | l.1812-1814 |
| policy_group_type / policy_group | DÉDIÉ | regex funcprof/(accportgrp|accbundle|brkoutportgrp) l.1817 |
| port_blocks (name/descr/from_module/to_module/from_port/to_port) | DÉDIÉ | infraPortBlk l.1821 |
| fex_id / fex_interface_profile | **MANQUANT** | infraRsAccBaseGrp variante fex (fexId + tDn fexprof/fexbundle) non matchée par la regex |
| sub_port_blocks | **MANQUANT** | infraSubPortBlk / infraRsSubPortAccBndlSubgrp 0 hit |
| port_blocks[].port_channel_member_policy | **MANQUANT** | infraRsAccBndlSubgrp 0 hit |

## access-leaf-switch-policy-group — COUVERT
capture_leaf_switch_pgs (nac.py:2459) : name + forwarding_scale_policy, bfd_ipv4_policy, bfd_ipv6_policy, cdp_policy, lldp_policy (les 5 vars-relations = toutes les vars hors name).

## access-leaf-switch-profile — COUVERT
capture_leaf_switch_profiles (nac.py:2410) : name, selectors (name + policy infraRsAccNodePGrp + node_blocks infraNodeBlk from/to), interface_profiles (infraRsAccPortP).

## access-monitoring-policy — À TROUS
capture_monitoring_policies (nac.py:2068). RESTE documenté l.24 : « snmp_trap_policies, syslog_policies ».
| name / description | DÉDIÉ | l.2078-2081 |
| fault_severity_policies | DÉDIÉ | monInfraTarget scope + faultSevAsnP l.2083 |
| snmp_trap_policies | **MANQUANT** | snmpSrc/snmpRsDestGroup sous monInfraPol non capturés (snmpSrc 0 hit) |
| syslog_policies | **MANQUANT** | syslogSrc capturé UNIQUEMENT sous uni/fabric/moncommon (capture_common_monitoring l.3263, filtre /moncommon/) |

## access-span-destination-group — À TROUS
capture_span_destination_groups (nac.py:2181, scope uni/infra). Variante ERSPAN-to-EPG seule.
| name / description | DÉDIÉ | l.2192-2195 |
| tenant / application_profile / endpoint_group / ip / source_prefix / dscp / flow_id / mtu / ttl / span_version / enforce_version | DÉDIÉ | spanRsDestEpg l.2196-2220 |
| pod_id / node_id / module / port / sub_port / channel | **MANQUANT** | destinations port physique (spanRsDestPathEp port/subport/channel) : classe non requêtée (grep spanRsDestPathEp 0 hit) |

## access-span-filter-group — COUVERT
Base flat (spanFilterGrp) + capture_span_filter_groups (nac.py:2137) : entries complètes (name/description/source_ip/destination_ip/ip_protocol/ports from/to, forme mot-clé documentée).

## access-span-source-group — À TROUS
capture_span_source_groups (nac.py:2222).
| name / description / admin_state | DÉDIÉ | l.2234-2240 |
| filter_group | DÉDIÉ | spanRsSrcGrpToFilterGrp l.2241 |
| destination_name / destination_description | DÉDIÉ | spanSpanLbl l.2246 |
| sources (name/description/direction/span_drop/tenant/ap/epg/l3out/vlan) | DÉDIÉ | spanSrc + spanRsSrcToEpg + spanRsSrcToL3extOut l.2252-2274 |
| sources[].access_paths (node_id/node2_id/fex_id/fex2_id/pod_id/module/port/sub_port/channel/type) | **MANQUANT** | spanRsSrcToPathEp (5 variantes port/subport/channel/fex_port/fex_channel) non requêtée côté access (seul le fabric span l.2283 capture des paths) |

## access-spine-interface-policy-group — À TROUS
Base GÉNÉRIQUE flat (infraSpAccPortGrp, name) + enrichissement #89 (_capture_tree l.3587-3599 : link_level_policy, cdp_policy, aaep filtrés spaccportgrp-).
| name / link_level_policy / cdp_policy / aaep | OK | ci-dessus |
| macsec_interface_policy | **MANQUANT** (omission documentée « macsec omis » l.3587) | infraRsMacsecIfPol non capturé pour les spine PGs |

## access-spine-interface-profile — COUVERT
| name | GÉNÉRIQUE flat (infraSpAccPortP) | content = name seul |

## access-spine-interface-selector — COUVERT
capture_fabric_selectors(infraSHPortS, infraRsSpAccGrp, blk_class=infraPortBlk) — _capture_tree l.3478 [#35] : name, policy_group, port_blocks. (interface_profile structurel ; pas de descr côté APIC — documenté).

## access-spine-switch-policy-group — COUVERT
capture_spine_switch_pgs (nac.py:2479) : name + bfd_ipv4/bfd_ipv6/cdp/lldp (les 4 vars-relations).

## access-spine-switch-profile — COUVERT
capture_spine_switch_profiles (nac.py:2498) : name, selectors (policy + node_blocks), interface_profiles.

## apic-connectivity-preference — COUVERT
Singleton (mgmtConnectivityPrefs) : interface_preference (seule var) dans var2pf + content direct.

## application-profile — COUVERT
capture_tenants, obj fvAp (nac.py:906) : name, alias (nameAlias), description. `annotation` hors content (argument provider) et `tenant` structurel → non comptés.

## atomic-counter — COUVERT
Singleton dbgOngoingAcMode : mode (var2pf) + admin_state via code spécial capture_singletons l.331-336 (méthode C).

## banner — À TROUS
Singleton aaaPreLoginBanner ; var2pf a les 8 vars mais attr_map ne dérive que les expressions simples.
| apic_gui_alias / apic_cli_banner / apic_app_banner / apic_app_banner_severity / switch_cli_banner | GÉNÉRIQUE singleton | guiTextMessage/message/bannerMessage/bannerMessageSeverity/switchMessage = var.x direct |
| apic_gui_banner_message / apic_gui_banner_url | **MANQUANT** (constat confirmé) | guiMessage = ternaire `!= ""` + isGuiMessageText : non parsés par attr_map (MODULE_COVERAGE l.91 : « guiMessage/isGuiMessageText/showBannerMessage = complexes dérivés non mappés ») |
| escape_html | STRUCTUREL | argument d'encodage terraform, pas un attribut fabric |

## bfd-interface-policy — COUVERT
Tenant-flat (bfdIfPol, _tenant_flat_table). Content : name/descr/detectMult/echoRxIntvl/minRxIntvl/minTxIntvl directs ; ctrl et echoAdminSt = ternaires bool matchés par _RE_BOOL. tenant structurel.

## bfd-multihop-node-policy — COUVERT
Tenant-flat (bfdMhNodePol) : 5 attrs directs.

## bfd-policy — COUVERT (1 exception documentée)
capture_bfd_policies (nac.py:3319) : name, type (ipv4/ipv6 par classe), description, detection_multiplier, min_tx/min_rx, slow_timer, echo_rx, echo_frame_source_address.
| startup_timer_interval | NON capturé, DOCUMENTÉ (l.3327) | startupIntvl auto-rempli (10) par l'APIC → capturer créerait un drift ; une valeur custom serait néanmoins perdue |

## bgp-address-family-context-policy — COUVERT
Tenant-flat (bgpCtxAfPol) : ctrl bool (_RE_BOOL), eDist/iDist/localDist/maxEcmp/maxEcmpIbgp directs, maxLocalEcmp = `!= 0 ? x : null` matché par _RE_NUMNULL (nac.py:156).

## bgp-best-path-policy — COUVERT
Tenant-flat (bgpBestPathCtrlPol) : ctrl = join/concat flags → handler "flag" d'attr_map (nac.py:179) → as_path_multipath_relax + ignore_igp_metric.

---

# LOT 2

# Couverture brownfield nac.py — batch 2 (27 modules)

Légende : GÉN = moteur générique (attr_map + table plate/singleton/tenant-flat) · DÉDIÉ = code dédié (ligne nac.py) · SECRET = omis volontairement (documenté) · **MANQUANT** = aucun code ne capture.

## bgp-peer-prefix-policy (bgpPeerPfxPol, tenant.policies) — 100%
| variable | statut | preuve |
|---|---|---|
| tenant/name | clé | DN |
| description, action, max_prefixes, restart_time, threshold | GÉN | main.tf : 6 attrs simples mono-ligne ; tenant-flat (_tenant_flat_table nac.py:507) ; golden #72 |

## bgp-policy (bgpAsP + bgpRRNodePEp) — À TROUS
| variable | statut | preuve |
|---|---|---|
| fabric_bgp_as | DÉDIÉ | capture_singletons, filtre uni/fabric/bgpInstP (nac.py:319) |
| fabric_bgp_rr | **MANQUANT** | `grep bgpRRNodePEp tools/nac.py` = 0 hit (seule la réf pod-pg fabricRsPodPGrpBGPRRP l.3197 existe) |
| fabric_bgp_external_rr | **MANQUANT** | idem (2e ressource bgpRRNodePEp-Ext du module) |

## bgp-route-summarization-policy (bgpRtSummPol) — 100%
tenant/name clés ; description, as_set, summary_only, af_mcast, af_ucast → GÉN (golden #74, flags ctrl/addrTCtrl).

## bgp-timer-policy (bgpCtxPol) — 100%
tenant/name clés ; description, graceful_restart_helper, hold_interval, keepalive_interval, maximum_as_limit, stale_interval → GÉN (golden #73).

## border-gateway-set-policy (vxlanSite) — LIMITE APIC (pas un trou nac.py)
name, vxlan_site_id, external_data_plane_ips : classe vxlanSite non résolue sur APIC 6.0(7e) (HTTP 400) — vérifié 2026-07-02, MODULE_COVERAGE l.93. Rien à capturer sur cette fabric.

## bridge-domain (fvBD) — À TROUS
| variable | statut |
|---|---|
| tenant/name (clés), alias, description, arp_flooding, advertise_host_routes, ip_dataplane_learning, limit_ip_learn_to_subnets, mac, ep_move_detection, clear_remote_mac_entries, virtual_mac, l3_multicast, multi_destination_flooding, unicast_routing, unknown_unicast, unknown_ipv4/ipv6_multicast, annotation | GÉN (obj fvBD, nac.py:809) |
| vrf | DÉDIÉ (fvRsCtx, nac.py:798) |
| multicast_arp_drop | DÉDIÉ (nac.py:810) |
| subnets (champs simples) | DÉDIÉ (fvSubnet, nac.py:812) |
| l3outs | DÉDIÉ (fvRsBDToOut, nac.py:800/815) |
| dhcp_labels | **MANQUANT** (dhcpLbl absent de nac.py) |
| netflow_monitor_policies | **MANQUANT** (fvRsBDToNetflowMonitorPol absent) |
| igmp_interface_policy | **MANQUANT** (igmpIfP/fvRsIgmpsn absents) |
| igmp_snooping_policy | **MANQUANT** (fvRsIgmpsn absent) |
| nd_interface_policy | **MANQUANT** (fvRsBDToNdP absent) |
| endpoint_retention_policy | **MANQUANT** (fvRsBdToEpRet absent) |
| legacy_mode_vlan | **MANQUANT** (fvAccP absent) |
| pim_source_filter / pim_destination_filter | **MANQUANT** |
| vxlan_enabled / border_gateway_set / normalized_vni | **MANQUANT** (famille vxlan* de toute façon limite APIC) |
| subnets.nd_prefix_policy (+ options enfant non simples) | **MANQUANT** |

## ca-certificate (pkiTP) — 100%
name, description, certificate_chain → DÉDIÉ capture_secretful_policies nac.py:3004-3011 (certChain PUBLIC, .strip()). Golden #99.

## cdp-policy (cdpIfPol) — 100%
name (clé), admin_state (ternaire enabled/disabled) → GÉN flat.

## config-export (configExportP) — 100%
name, description, format, snapshot, scheduler (configRsExportScheduler), remote_location (configRsRemotePath) → DÉDIÉ capture_config_exports nac.py:3281. Golden.

## config-passphrase (pkiExportEncryptionKey) — SECRET documenté
config_passphrase : jamais capturé volontairement. Couvert (secret).

## contract (vzBrCP) — À TROUS
| variable | statut |
|---|---|
| tenant/name (clés), alias, description, scope, qos_class, target_dscp | GÉN (obj vzBrCP, nac.py:939) |
| subjects (name/alias/description/reverse_filter_ports/qos_class/target_dscp) | DÉDIÉ (obj vzSubj, nac.py:942) |
| subjects.filters[].filter (nom) | DÉDIÉ (vzRsSubjFiltAtt, nac.py:944) |
| subjects.filters[].action / priority / log / no_stats | **MANQUANT** (seul tnVzFilterName lu) |
| subjects.service_graph | **MANQUANT** (vzRsSubjGraphAtt absent de nac.py) |
| subjects.consumer_to_provider_* / provider_to_consumer_* (vzInTerm/vzOutTerm, vzRsFiltAtt, vzRs{In,Out}TermGraphAtt) | **MANQUANT** |

## control-plane-mtu (infraCPMtuPol) — À TROUS (mineur)
| variable | statut |
|---|---|
| mtu | GÉN singleton (méthode C validée) |
| apic_mtu_apply | **MANQUANT** (ternaire `? "yes" : null` non parsé par attr_map, pas de fixup) |

## coop-policy (coopPol) — 100%
coop_group_policy (type) → GÉN singleton.

## data-plane-policing-policy (qosDppPol) — 100%
23 vars : name/tenant clés ; 22 attrs plats mono-ligne → GÉN (flat access + tenant-flat pour la variante tenant, aci_tenants.tf:3263). Golden 139 attrs, plan No changes.

## date-time-format (datetimeFormat) — 100%
display_format, timezone, show_offset → GÉN singleton.

## date-time-policy (datetimePol) — À TROUS (mineur) + SECRET
| variable | statut |
|---|---|
| name, ntp_admin_state, ntp_auth_state, apic_ntp_server_state, apic_ntp_server_master_mode, apic_ntp_server_master_stratum | DÉDIÉ capture_date_time_policies nac.py:3161 |
| ntp_servers.hostname_ip / preferred | DÉDIÉ (datetimeNtpProv) |
| ntp_servers.mgmt_epg_type / mgmt_epg_name | **MANQUANT** (binding rsNtpProvToEpg omis ; défaut inb recréé — un binding oob serait perdu) |
| ntp_keys + ntp_servers.auth_key_id | SECRET documenté (datetimeNtpAuthKey) |

## device-selection-policy (vnsLDevCtx) — À TROUS
| variable | statut |
|---|---|
| tenant, contract, service_graph_template, node_name | DÉDIÉ nac.py:1708-1716 |
| sgt_device_tenant / sgt_device_name | DÉDIÉ indirect : dérivés dans aci_tenants.tf:4143+ depuis le device du SGT (capturé via vnsRsNodeToLDev, #108) |
| consumer/provider : logical_interface, bridge_domain(+tenant), redirect_policy(+tenant), l3_destination, permit_logging | DÉDIÉ nac.py:1703-1740 (vnsRsLIfCtxToLIf/ToBD/ToSvcRedirectPol) |
| consumer/provider external_endpoint_group(+tenant/l3out) + redistribute_bgp/ospf/connected/static | **MANQUANT** (vnsRsLIfCtxToInstP absent de nac.py) |
| consumer/provider/copy service_epg_policy(+tenant) | **MANQUANT** (vnsRsLIfCtxToSvcEPgPol absent) |
| consumer/provider/copy custom_qos_policy | **MANQUANT** (vnsRsLIfCtxToCustQosPol absent) |
| copy_l3_destination / copy_permit_logging / copy_logical_interface (vnsLIfCtx copy) | **MANQUANT** (seuls connNameOrLbl consumer/provider gardés, nac.py:1721) |
| devices (mode multi-device) | **MANQUANT** (capture n'émet que la forme legacy) |

## dhcp-option-policy (dhcpOptionPol) — 100%
tenant/name clés, description ; options (dhcpOption id/name/data) → DÉDIÉ nac.py:1261+.

## dhcp-relay-policy (dhcpRelayP tenant) — 100%
tenant/name clés, description ; providers_ (ip + type epg→tenant/ap/epg, sinon instP→tenant/l3out/external_endpoint_group) → DÉDIÉ nac.py:1230-1257. NB : capture émet type "l3out", le module route tout ≠"epg" vers instP → fonctionne (validé #66).

## dns-policy (dnsProfile) — À TROUS (mineur)
| variable | statut |
|---|---|
| name ; providers_ (ip/preferred) ; domains (name/default) | DÉDIÉ capture_dns_policies nac.py:2834 |
| mgmt_epg_type / mgmt_epg_name | **MANQUANT** (rsProfileToEpg omis ; défaut inb recréé — un binding oob serait perdu) |

## eigrp-interface-policy (eigrpIfPol) — 100%
tenant/name clés ; description, hello/hold_interval, bandwidth, delay, delay_unit → GÉN direct ; bfd, self_nexthop, passive_interface, split_horizon → GÉN flags ctrl (join+concat mono-ligne, regex flags #54, même patron que igmpIfPol validé #63).

## endpoint-group (fvAEPg) — À TROUS
| variable | statut |
|---|---|
| tenant/application_profile/name (clés), alias, description, annotation, flood_in_encap, intra_epg_isolation, proxy_arp (fwdCtrl), preferred_group, qos_class | GÉN (obj fvAEPg, nac.py:838) |
| bridge_domain | DÉDIÉ (fvRsBd, nac.py:817/841) |
| contract_consumers / contract_providers | DÉDIÉ (fvRsCons/fvRsProv, nac.py:818-848) |
| physical_domains | DÉDIÉ (fvRsDomAtt, nac.py:850-853) |
| vmware_vmm_domains | PARTIEL : noms seuls (nac.py:852) — options du binding (deploy/resolution imedcy, vlan, u-seg…) perdues |
| nutanix_vmm_domains | **MANQUANT** |
| subnets (fvSubnet sous EPG) | **MANQUANT** |
| tags (tagInst) | **MANQUANT** |
| contract_imported_consumers / contract_intra_epgs / contract_masters | **MANQUANT** |
| static_ports / bulk_static_ports (fvRsPathAtt) | **MANQUANT** |
| static_leafs (fvRsNodeAtt) / static_endpoints (fvStCEp) / static_aaeps | **MANQUANT** |
| l4l7_virtual_ips / l4l7_address_pools | **MANQUANT** |
| custom_qos_policy / trust_control_policy / data_plane_policing_policy (réfs) | **MANQUANT** |

## endpoint-ip-tag-policy (fvEpIpTag) — 100%
ip, tenant, vrf (ctxName), tags (tagTag) → DÉDIÉ #61 (nac.py capture_tenant_policies).

## endpoint-loop-protection (epLoopProtectP) — quasi-100% (1 limite)
| variable | statut |
|---|---|
| admin_state, detection_interval, detection_multiplier | GÉN singleton (méthode C validée) |
| bd_learn_disable / port_disable | GÉN flags — LIMITE : un seul flag round-trippe ; les DEUX ensemble → CSV brut non re-parsé (MODULE_COVERAGE l.103) |

## endpoint-mac-tag-policy (fvEpMacTag) — 100%
mac, bridge_domain ('*'↔all), tenant, vrf, tags (tagTag) → DÉDIÉ #55.

## endpoint-retention-policy (fvEpRetPol) — 100%
tenant/name clés ; description, hold_interval, bounce_entry_aging_interval, local/remote_endpoint_aging_interval, move_frequency → GÉN tenant-flat.

## endpoint-security-group (fvESg) — À TROUS
| variable | statut |
|---|---|
| tenant/application_profile/name (clés), description, intra_esg_isolation, preferred_group, shutdown, deployment_immediacy* | GÉN (obj fvESg, nac.py:882) *instrImedcy non supporté APIC 6.0(7e) |
| vrf | DÉDIÉ (fvRsScope, nac.py:883) |
| tag_selectors | DÉDIÉ (fvTagSelector, nac.py:887) |
| ip_subnet_selectors | DÉDIÉ (fvEPSelector, nac.py:896) |
| contract_consumers / contract_providers | **MANQUANT** (fvRsCons/fvRsProv chargés l.818 mais JAMAIS lus dans le bloc ESG l.880-905) |
| contract_imported_consumers (fvRsConsIf) | **MANQUANT** |
| contract_intra_esgs (fvRsIntraEpg) | **MANQUANT** |
| esg_contract_masters (fvRsSecInherited) | **MANQUANT** |
| epg_selectors (fvEPgSelector) | **MANQUANT** (+ contrainte data model : même tenant) |
| normalized_pctag (fvRemoteSGT remotePcTag) | **MANQUANT** |
| ip_external_subnet_selectors | LIMITE APIC 6.0(7e) ('Invalid DN') — documentée |

---

# LOT 3

# Couverture capture brownfield — batch 3 (27 modules)

Légende statut : GÉN = moteur générique (attr_map + _flat_table/_singleton_table/_tenant_flat_table) ;
DÉDIÉ = fonction capture_* dédiée ; SECRET = write-only documenté ; MANQUANT = perte au YAML.

## error-disabled-recovery — À TROUS
Singleton (aci_fabric_policies.tf:177, count + try(local.fabric_policies.err_disabled_recovery.*)).
| variable | statut | preuve |
|---|---|---|
| interval | GÉN singleton | edrErrDisRecoverPol errDisRecovIntvl=var.interval ; _singleton_table nac.py:283 + capture_singletons:307 |
| mcp_loop | **MANQUANT** | enfant edrEventP-event-mcp-loop ; `grep edrEventP tools/nac.py` = 0 hit |
| ep_move | **MANQUANT** | enfant edrEventP-event-ep-move ; idem |
| bpdu_guard | **MANQUANT** | enfant edrEventP-event-bpduguard ; idem |
Impact : les évènements de recovery activés à la main retombent aux défauts NaC au premier sync.

## external-connectivity-policy — À TROUS (quasi non capturé, TODO connu — MODULE_COVERAGE.md:106 non coché)
Singleton count-based (aci_fabric_policies.tf:613). Le moteur singleton capte le PRIMAIRE fvFabricExtConnP
partiellement (var2pf via `try(local.fabric_policies.external_connectivity_policy.X`).
| variable | statut | preuve |
|---|---|---|
| name | **MANQUANT (bloquant)** | `name = "${local...name}${suffix}"` = interpolation, pas `try(local.` → absent de var2pf ; or count exige `external_connectivity_policy.name != null` → module jamais instancié |
| route_target | GÉN singleton (rt) | var2pf ✓, attr_map direct |
| fabric_id | GÉN singleton (id) | var2pf ✓ |
| site_id | GÉN singleton (siteId) | var2pf ✓ |
| peering_type | **MANQUANT** | enfant fvPeeringP (type) ; aucun get_class("fvPeeringP") dans nac.py |
| bgp_password | SECRET documenté | fvPeeringP password, ignore_changes |
| routing_profiles (+subnets) | **MANQUANT** | enfants l3extFabricExtRoutingP / l3extSubnet (uni/tn-infra/fabricExtConnP) ; 0 hit nac.py |
| data_plane_teps | **MANQUANT** | enfants fvPodConnP/fvIp ; dérivés de pod_policies.pods[].data_plane_tep — pods = aci_pod_setup exclu (PHASE2_MODULES nac.py:54) |
| unicast_teps | **MANQUANT** | fvExtRoutableUcastConnP ; idem via pods[].unicast_tep |
Impact : config GOLF/multipod inter-fabric perdue ; pire, name absent ⇒ même les 3 attrs captés ne pilotent rien.

## external-endpoint-group — À TROUS
Tenant, capture dédiée capture_tenants nac.py:951-971 (obj générique l3extInstP + subnets + contrats).
| variable | statut | preuve |
|---|---|---|
| tenant / l3out / name | DÉDIÉ | nac.py:954-957, rangé par L3Out (nac.py:1176) |
| alias (nameAlias), description, preferred_group (prefGrMemb ternaire), qos_class (prio), target_dscp | GÉN via obj() | content simple, attr_map |
| annotation | **MANQUANT** (mineur) | argument resource-level, hors content{} → jamais dérivé |
| subnets (prefix, name, description, flags scope/aggregate) | DÉDIÉ | nac.py:958 obj l3extSubnet ; flags join/concat = kind "flag" (attr_map nac.py:180) |
| subnets[].route_control_profiles | **MANQUANT** | l3extRsSubnetToProfile : 0 hit nac.py |
| subnets[].{bgp,ospf,eigrp}_route_summarization(+_policy) | **MANQUANT** | l3extRsSubnetToRtSumm : 0 hit |
| route_control_profiles (EPG) | **MANQUANT** | l3extRsInstPToProfile : 0 hit |
| contract_consumers / contract_providers | DÉDIÉ | fvRsCons/fvRsProv nac.py:818-819 + 960-965 |
| contract_imported_consumers | **MANQUANT** | fvRsConsIf : 0 hit |
| contract_masters | **MANQUANT** | fvRsSecInherited : 0 hit |
Impact : relations route-control/summarization et contrats importés/masters posés à la main perdus.

## fabric-interface-configuration — À TROUS
DÉDIÉ capture_port_configurations nac.py:1977 (fabricPortConfig).
| variable | statut | preuve |
|---|---|---|
| node_id, module (card), port | DÉDIÉ | nac.py:1990-1994 |
| policy_group | DÉDIÉ | regex leportgrp/spportgrp nac.py:2004 |
| description, shutdown | DÉDIÉ | nac.py:1997-2000 |
| role | DÉDIÉ | roles[nid]=p["role"] nac.py:2009 |
| sub_port | **MANQUANT (warning émis)** | nac.py:1987-1989 : subPort != 0 → skip + warning "sub-port ... non capture" |
Impact : les configs de sous-ports fabric (breakout) sont ignorées (signalées en warning, non reconduites).

## fabric-isis-bfd — 100 %
admin_state : ternaire bool l3IfPol bfdIsis → GÉN singleton (aci_fabric_policies.tf:114).

## fabric-isis-policy — 100 %
redistribute_metric : isisDomPol redistribMetric direct → GÉN singleton (tf:107).

## fabric-l2-mtu — 100 %
l2_port_mtu : l2InstPol fabricMtu direct → GÉN singleton (tf:121).

## fabric-leaf-interface-policy-group — 100 %
name/description : GÉN flat (fabricLePortPGrp, for_each fabric_policies.leaf_interface_policy_groups tf:338).
link_level_policy : enrichissement dédié fabricRsFIfPol nac.py:3599-3603.

## fabric-leaf-interface-profile — 100 %
name (seule variable) : GÉN flat fabricLePortP (variante _manual tf:541 ; _auto dérivée de node_policies, hors moteur mais même objet).

## fabric-leaf-interface-selector — À TROUS
DÉDIÉ capture_fabric_selectors nac.py:2099, appel nac.py:3467 (fabricLFPortS/fabricRsLePortPGrp).
| variable | statut | preuve |
|---|---|---|
| interface_profile, name, description | DÉDIÉ | rattaché au profil par prof_seg leportp |
| policy_group | DÉDIÉ | fabricRsLePortPGrp tDn leportgrp- |
| port_blocks (name/desc/from_module/from_port/to_module/to_port) | DÉDIÉ | fabricPortBlk nac.py:2121-2133 |
| sub_port_blocks | **MANQUANT** | fabricSubPortBlk : 0 hit nac.py |
Impact : sélecteurs à sub-port blocks (breakout fabric) perdus au YAML.

## fabric-leaf-switch-policy-group — 100 %
DÉDIÉ capture_fabric_leaf_switch_pgs nac.py:2547 : name + psu_policy (fabricRsPsuInstPol) + node_control_policy (fabricRsNodeCtrl).

## fabric-leaf-switch-profile — 100 %
DÉDIÉ capture_fabric_leaf_switch_profiles nac.py:2564 : name, selectors (fabricLeafS) + policy (fabricRsLeNodePGrp) + node_blocks (fabricNodeBlk from/to) + interface_profiles (fabricRsLePortP). Exclut system-*/default.

## fabric-link-level-policy — 100 %
name/description/link_debounce_interval : contenu fabricFIfPol simple → GÉN flat (fabric_policies.interface_policies.link_level_policies, tf:1293).

## fabric-pod-policy-group — 100 %
DÉDIÉ capture_fabric_pod_policy_groups nac.py:3189 : name/description + 5 relations (snmp_policy, date_time_policy, management_access_policy, macsec_policy, bgp_route_reflector_policy).

## fabric-pod-profile — À TROUS (MODULE_COVERAGE.md:111 non coché)
Variante _manual (tf:286) captée par le moteur flat (fabricPodP → fabric_policies.pod_profiles) : name seulement.
| variable | statut | preuve |
|---|---|---|
| name | GÉN flat | child_primary=fabricPodP |
| selectors (name, type ALL/range, policy_group, pod_blocks from/to) | **MANQUANT** | fabricPodS / fabricRsPodPGrp / fabricPodBlk : 0 hit nac.py |
Impact : un pod profile manuel perd ses sélecteurs et le lien vers son pod policy group (rattachement des pods aux policies pod).

## fabric-scheduler — 100 %
PHASE2 (exclu du flat), DÉDIÉ capture_schedulers nac.py:3366 : name/description + recurring_windows (trigRecurrWindowP name/day/hour/minute, défauts filtrés). Exclut schedulers système uid=0.

## fabric-span-destination-group — 100 %
PHASE2 (classe spanDestGrp ambiguë), DÉDIÉ capture_span_destination_groups(scope="uni/fabric/") nac.py:2181, appel :3500. 13/13 variables : name, description, ip, source_prefix, dscp, flow_id, mtu, ttl, span_version (→version, wiring tf:1211), enforce_version, tenant/application_profile/endpoint_group (spanRsDestEpg tDn).

## fabric-span-source-group — À TROUS
PHASE2, DÉDIÉ capture_fabric_span_source_groups nac.py:2280.
| variable | statut | preuve |
|---|---|---|
| name, description, admin_state | DÉDIÉ | adminSt défaut enabled géré :2292 |
| destination_name / destination_description | DÉDIÉ | spanSpanLbl :2296-2301 |
| sources (name/description/direction/span_drop, tenant+vrf, tenant+bridge_domain) | DÉDIÉ | spanSrc + spanRsSrcToCtx + spanRsSrcToBD :2303-2324 |
| sources[].fabric_paths | **MANQUANT** | spanRsSrcToPathEp cité seulement en docstring :2283, aucun get_class |
Impact : les sources SPAN fabric pointées sur des ports physiques (fabric_paths) perdent leurs chemins.

## fabric-spine-interface-profile — 100 %
name (seule variable) : GÉN flat fabricSpPortP (variante _manual tf:606).

## fabric-spine-interface-selector — À TROUS
DÉDIÉ capture_fabric_selectors, appel nac.py:3472 (fabricSFPortS/fabricRsSpPortPGrp).
Idem leaf : tout couvert SAUF sub_port_blocks (fabricSubPortBlk, 0 hit) → **MANQUANT**.

## fabric-spine-switch-policy-group — 100 %
DÉDIÉ capture_fabric_spine_switch_pgs nac.py:2613 : name + psu_policy + node_control_policy.

## fabric-spine-switch-profile — 100 %
DÉDIÉ capture_fabric_spine_switch_profiles nac.py:2630 : name, selectors + policy + node_blocks + interface_profiles (fabricRsSpPortP).

## fabric-wide-settings — 100 %
Singleton (tf:50) : 7 variables, toutes ternaires bool infraSetPol → GÉN singleton (domain_validation, enforce_subnet_check, opflex_authentication, disable_remote_endpoint_learn, overlapping_vlan_validation, remote_leaf_direct, reallocate_gipo).

## filter — 100 %
Tenant, DÉDIÉ capture_tenants nac.py:912-931 : vzFilter via obj() (name/alias/description) + entries vzEntry via obj() (name/alias/description/ethertype/stateful/match_only_fragments) + enrichissement dédié protocol et source/destination_from/to_port (ternaires numéro→mot-clé non parsables par attr_map, capturés tels qu'APIC les stocke, [#58]).

## firmware-group — À TROUS
DÉDIÉ capture_update_groups nac.py:3347 (firmwareFwGrp → node_policies.update_groups).
| variable | statut | preuve |
|---|---|---|
| name | DÉDIÉ | :3357-3361 (+ scheduler du maintenance-group jumeau) |
| node_ids | **MANQUANT** | dérivé de node_policies.nodes[].update_group (aci_node_policies.tf:7) ; aucun code ne capte fabricNodeBlk sous fwgrp/maintgrp ni ne pose update_group sur les nœuds (grep update_group : seulement :3634-3637) |
Impact : l'appartenance des switches aux update groups est perdue (groupes recréés vides) — noté « Node block non testé » MODULE_COVERAGE.md:36.

## forwarding-scale-policy — 100 %
name/profile (profType direct) : GÉN flat topoctrlFwdScaleProfilePol (access_policies tf:121) ; référencé aussi par les leaf switch PG (nac.py:2462).

## geolocation — 100 %
DÉDIÉ capture_geolocation nac.py:2867 : site name/description + hiérarchie complète buildings/floors/rooms/rows/racks (+descriptions) + nodes (geoRsNodeLocation → ids ; pod_id reconstruit par le wiring depuis node_policies.nodes[].pod, tf:858). Filtre chaîne default uid=0.

## Récapitulatif
100 % : fabric-isis-bfd, fabric-isis-policy, fabric-l2-mtu, fabric-leaf-interface-policy-group,
fabric-leaf-interface-profile, fabric-leaf-switch-policy-group, fabric-leaf-switch-profile,
fabric-link-level-policy, fabric-pod-policy-group, fabric-scheduler, fabric-span-destination-group,
fabric-spine-interface-profile, fabric-spine-switch-policy-group, fabric-spine-switch-profile,
fabric-wide-settings, filter, forwarding-scale-policy, geolocation.
À trous : error-disabled-recovery, external-connectivity-policy, external-endpoint-group,
fabric-interface-configuration, fabric-leaf-interface-selector, fabric-pod-profile,
fabric-span-source-group, fabric-spine-interface-selector, firmware-group.

---

# LOT 4

# Couverture brownfield nac.py — batch 4 (27 modules)

Légende statut : GEN = moteur générique (attr_map + _flat/_singleton/_tenant_flat_table) ;
DED = code dédié (ligne nac.py) ; SECRET = write-only documenté ; **MANQUANT** = perdu à la capture.

## 1. health-score-evaluation-policy — 100 %
| variable | statut | preuve |
|---|---|---|
| ignore_acked_faults | GEN singleton | healthEvalP `ignoreAckedFaults` ternaire yes/no ; bloc count `try(local.fabric_policies.ignore_acked_faults` (aci_fabric_policies.tf:1191) → _singleton_table (nac.py:283) |

## 2. hsrp-group-policy — 100 % (1 secret)
Instancié aci_tenants.tf:3127, local flatten `tenant.policies.hsrp_group_policies` → _tenant_flat_table (nac.py:507).
| variable | statut | preuve |
|---|---|---|
| tenant/name/description | GEN | dn + name/descr simples |
| preempt | GEN | `ctrl = var.preempt ? "preempt" : ""` → _RE_BOOL forme implicite (nac.py:150) |
| hello_interval, hold_interval, preempt_delay_min/_reload/_max, priority, timeout, auth_type | GEN | attrs simples (helloIntvl, holdIntvl, preemptDelay*, prio, timeout, type) |
| auth_key | SECRET | `key` write-only (lifecycle ignore_changes dans le module) ; APIC ne le renvoie pas |

## 3. hsrp-interface-policy — 100 %
| variable | statut | preuve |
|---|---|---|
| tenant/name/description/delay/reload_delay | GEN | attrs simples |
| bfd_enable, use_bia | DED nac.py:1181-1190 | ctrl join/concat MULTI-LIGNE non parsé par attr_map → reverse dédié flags bfd/bia |

## 4. igmp-interface-policy — À TROUS
| variable | statut | preuve |
|---|---|---|
| tenant/name/description, grp_timeout, last_member_count, last_member_response_time, querier_timeout, query_interval, robustness_variable, query_response_interval, startup_query_count, startup_query_interval | GEN | attrs simples igmpIfPol |
| allow_v3_asm, fast_leave, report_link_local_groups | GEN | ifCtrl join/concat MONO-LIGNE → kind "flag" (nac.py:177-183) |
| version_ | GEN + remap | TENANT_FIELD_REMAP nac.py:535 (`version_`→`version`) |
| max_mcast_entries, reserved_mcast_entries | **MANQUANT** | enfant igmpStateLPol (max/rsvd) : aucun hit `igmpStateLPol` dans nac.py |
| report_policy_multicast_route_map | **MANQUANT** | enfants igmpStRepPol + rtdmcRsFilterToRtMapPol : aucun hit dans nac.py |
| static_report_multicast_route_map | **MANQUANT** | idem (igmpRepPol + rtdmcRsFilterToRtMapPol) |
| state_limit_multicast_route_map | **MANQUANT** | idem (rtdmcRsFilterToRtMapPol sous igmpStateLPol) |

## 5. igmp-snooping-policy — 100 %
Tous attrs simples (adminSt bool, lastMbrIntvl, queryIntvl, rspIntvl, startQueryCnt/Intvl) + ctrl join/concat mono-ligne (fast_leave, querier) → GEN tenant flat (aci_tenants.tf:3499).

## 6. imported-contract — 100 %
| variable | statut | preuve |
|---|---|---|
| tenant/name | DED nac.py:1358-1371 | vzCPIf |
| source_tenant/source_contract | DED nac.py:1366-1370 | relation vzRsIf tDn → `tenant`/`contract` (clés YAML du data model) |

## 7. inband-endpoint-group — À TROUS
Capture dédiée nac.py:1406-1440 (tenant mgmt.inb_endpoint_groups).
| variable | statut | preuve |
|---|---|---|
| name, vlan | DED 1416-1418 | mgmtInB name + encap vlan- |
| bridge_domain | DED 1407,1419 | mgmtRsMgmtBD |
| contract_consumers / contract_providers | DED 1429-1436 | fvRsCons/fvRsProv |
| contract_imported_consumers | **MANQUANT** | fvRsConsIf jamais lu dans nac.py |
| static_routes | **MANQUANT** | mgmtStaticRoute lu seulement pour mgmtOoB (oob_sr, nac.py:1390) ; pas pour mgmtInB |
| subnets (ip, description) | DED 1421-1428 | fvSubnet |
| subnets.public / subnets.shared | **MANQUANT** | attribut `scope` de fvSubnet non capturé (seuls ip/descr) |

## 8. inband-node-address — À TROUS (mineur)
Capture dédiée capture_node_addresses nac.py:2023-2067 (mgmtRsInBStNode).
| variable | statut | preuve |
|---|---|---|
| node_id | DED | regex node-(\d+) |
| pod_id | **MANQUANT** | pod du DN non extrait → node.pod absent du YAML, défaut pod 1 au replan (faux si pod≠1) |
| ip/gateway/v6_ip/v6_gateway | DED 2054-2061 | addr/gw/v6Addr/v6Gw |
| endpoint_group | DED 2062-2064 | inb_endpoint_group (si ≠ default) |
| endpoint_group_vlan | couvert indirect | dérivé par le data model depuis tenants.mgmt inb_endpoint_groups[].vlan (capturé nac.py:1417) |
Note documentée : nœuds ENREGISTRÉS (fabricNode) exclus volontairement avec warning (éviterait node_registration) — perte assumée, pas un trou de code.

## 9. infra-dhcp-relay-policy — 100 %
capture_infra_dhcp_relay_policies nac.py:2802-2833 : name, description, providers_ (dhcpRsProv → ip + type epg {tenant, application_profile, endpoint_group} / l3out {tenant, l3out, external_endpoint_group}). Toutes les variables couvertes.

## 10. infra-dscp-translation-policy — 100 %
Singleton (aci_fabric_policies.tf:639, count + try(local.fabric_policies.infra_dscp_translation_policy.*)) → _singleton_table. 11 vars = attrs simples (adminSt bool, control, level1-6, policy, span, traceroute). 

## 11. interface-configuration — À TROUS
capture_port_configurations nac.py:1977-2021 (infraPortConfig/fabricPortConfig).
| variable | statut | preuve |
|---|---|---|
| node_id, port, module, description, shutdown, breakout, fex_id, role | DED 1990-2009 | node/port/card/description/shutdown/brkoutMap/connectedFex/role |
| policy_group | DED 2004-2007 | regex assocGrp (accportgrp|accbundle|spaccportgrp…) |
| policy_group_type | OK indirect (nuance vs constat initial) | pas un champ YAML : le data model le reconstruit par lookup `pg.type` dans access_policies.leaf_interface_policy_groups (aci_interface_policies.tf:193), et _capture_pgs (nac.py:477-504) capture le type access/pc/vpc des PGs. Perdu SEULEMENT si le PG référencé n'est pas capturé (PG default/system-) |
| port_channel_member_policy | **MANQUANT** | attribut `pcMember` d'infraPortConfig : aucun hit `pcMember` dans nac.py |
| sub_port | **MANQUANT** (warning) | nac.py:1987-1989 : sub-ports sautés avec warning « sub_ports non supporté » |

## 12. interface-shutdown — À TROUS
capture_interface_nodes nac.py:3392-3410 (fabricRsOosPath, ancien paradigme) + dédup new-style nac.py:3725.
| variable | statut | preuve |
|---|---|---|
| pod_id/node_id/module/port | DED 3401-3405 | regex `paths-(\d+)/pathep-\[eth(\d+)/(\d+)\]` → interfaces[].shutdown |
| sub_port | **MANQUANT** | DN `pathep-[eth1/1/1]` ne matche pas la regex (2 nombres exactement) |
| fex_id | **MANQUANT** | DN avec `extpaths-<fex>` ne matche pas (`paths-N/pathep-` exigé contigu) |

## 13. interface-type — 100 %
capture_interface_nodes nac.py:3396-3399 : infraRsPortDirection → type uplink/downlink par (node,module,port). Le module ne gère que les ports simples ; pod_id vient du data model (node_policies). Le ternaire `direc` non parsable par attr_map est reversé en dur ligne 3399.

## 14. ip-aging — 100 %
Singleton (aci_fabric_policies.tf:87 `admin_state = try(local.fabric_policies.ip_aging`) → epIpAgingP adminSt bool.

## 15. ip-sla-policy — 100 %
`content = merge(...)` non parsable par attr_map → capture dédiée nac.py:1283-1307 : name, description, sla_type, multiplier, frequency, port, http_method/http_version/http_uri (si slaType http). 10/10 vars.

## 16. keyring — 100 % (2 secrets)
PHASE2 (nac.py:57) → capture_secretful_policies nac.py:1912-1926.
| variable | statut |
|---|---|
| name, description, ca_certificate (tp), modulus | DED 1917-1923 |
| certificate, private_key | SECRET (ignore_changes cert/key dans le module ; jamais capturés, documenté) |

## 17. l2-mtu-policy — 100 %
Flat GEN (aci_fabric_policies.tf:153 for_each try(local.fabric_policies.l2_mtu_policies)) : l2InstPol name + fabricMtu→port_mtu_size. (Le singleton fabric-l2-mtu est un module distinct hors liste.)

## 18. l2-policy — 100 %
Flat GEN access (aci_access_policies.tf:445) : l2IfPol name, vlanScope, qinq, vepa bool→reflective_relay.

## 19. l3out — À TROUS (majeurs) — confirme les constats
Base : GEN partiel (content merge → nac.py:1152-1165 enrichit descr/alias/targetDscp/enforceRtctrl/mplsEnabled) + l3extRsEctx/RsL3DomAtt (nac.py:949-950) + l3extDefaultRouteLeakP (nac.py:1166-1175).
| variable | statut | preuve |
|---|---|---|
| tenant, name, alias, description, routed_domain, vrf, target_dscp | DED 1147-1158 | ok |
| import/export_route_control_enforcement | DED 1159-1163 | enforceRtctrl |
| sr_mpls (flag) | DED 1164-1165 | mplsEnabled |
| default_route_leak_policy* (4 vars) | DED 1166-1175 | l3extDefaultRouteLeakP |
| ospf, ospf_area, ospf_area_cost, ospf_area_type, ospf_area_control_* (redistribute/summary/suppress_fa) | **MANQUANT** | classe ospfExtP : ZÉRO hit dans nac.py |
| bgp | **MANQUANT** | bgpExtP absent |
| eigrp, eigrp_asn | **MANQUANT** | eigrpExtP absent |
| l3_multicast_ipv4 | **MANQUANT** | pimExtP absent |
| interleak_route_map | **MANQUANT** | l3extRsInterleakPol absent |
| dampening_ipv4/ipv6_route_map | **MANQUANT** | l3extRsDampeningPol absent |
| redistribution_route_maps | **MANQUANT** | l3extRsRedistributePol absent |
| import/export_route_map_* + route_maps | **MANQUANT** (mal scopé) | rtctrlProfile capturé au seul niveau tenant avec dédup DN le plus court (nac.py:541-560) → les route maps scoped L3Out (default-import/default-export/custom) perdues |
| multipod, sr_mpls_infra_l3outs | **MANQUANT** | l3extProvLbl/l3extConsLbl/l3extRsLblToProfile/mplsExtP/mplsRsLabelPol absents |
| vxlan_enabled, border_gateway_set | **MANQUANT** | vxlanExtP / l3extRsProvBgwSet absents |

## 20. l3out-interface-profile — À TROUS (majeurs)
Base GEN l3extLIfP (name, descr, prio→qos_class simple) + DED nac.py:967-1090.
| variable | statut | preuve |
|---|---|---|
| tenant/l3out/node_profile/name/description/qos_class | GEN/DED | l3extLIfP (prio = var.qos_class simple → capturé) |
| bfd_policy | DED 1086-1089 | bfdRsIfPol |
| ospf_interface_profile_name, ospf_interface_policy, ospf_authentication_type/_key_id | DED 1066-1085 | ospfIfP + ospfRsIfPol ; auth publics capturés |
| ospf_authentication_key | SECRET | placeholder OSPF_KEY_PLACEHOLDER (nac.py:1083) |
| interfaces (paths, ip, vlan, svi, mtu, mode, mac, autostate, scope, description + bgp_peers path-level) | DED 981-1064 | l3extRsPathL3OutAtt + bgpPeerP/bgpAsP/bgpLocalAsnP |
| interfaces vPC side A/B (l3extMember), IP secondaires (l3extIp), DHCP relay gw (dhcpRelayGwExtIp), micro-BFD (bfdMicroBfdP) | **MANQUANT** | aucun hit l3extMember/l3extIp/dhcpRelayGwExtIp/bfdMicroBfdP → un SVI vPC perd ses adresses side-A/side-B |
| interfaces floating SVI | **MANQUANT** | l3extVirtualLIfP / l3extRsDynPathAtt / l3extVirtualLIfPLagPolAtt absents |
| bgp_peers.password | SECRET | write-only |
| bgp_peers peer_prefix_policy / route_control_profiles | **MANQUANT** | bgpRsPeerPfxPol / bgpRsPeerToProfile absents |
| eigrp_interface_profile_name, eigrp_keychain_policy, eigrp_interface_policy | **MANQUANT** | eigrpIfP/eigrpRsIfPol/eigrpAuthIfP/eigrpRsKeyChainPol absents |
| pim_policy | **MANQUANT** | pimIfP/pimRsIfPol absents |
| igmp_interface_policy | **MANQUANT** | igmpIfP (sous lifp)/igmpRsIfPol absents |
| nd_interface_policy | **MANQUANT** | l3extRsNdIfPol absent |
| custom_qos_policy | **MANQUANT** | l3extRsLIfPCustQosPol absent |
| multipod, remote_leaf, sr_mpls, transport_data_plane | **MANQUANT** | mplsIfP/mplsRsIfPol + variantes infra absents |
| dhcp_labels | **MANQUANT** | dhcpLbl / dhcpRsDhcpOptionPol absents |
| netflow_monitor_policies | **MANQUANT** | l3extRsLIfPToNetflowMonitorPol absent |
| ingress/egress_data_plane_policing_policy | **MANQUANT** | l3extRsIngressQosDppPol / l3extRsEgressQosDppPol absents |

## 21. l3out-node-profile — À TROUS (majeurs)
Base DED nac.py:1091-1141.
| variable | statut | preuve |
|---|---|---|
| tenant/l3out/name/description | GEN | l3extLNodeP name/descr |
| nodes (node_id, pod_id, router_id, router_id_as_loopback, loopbacks, static_routes+next_hops préf/type/descr/bfd) | DED 1102-1138 | l3extRsNodeL3OutAtt/l3extLoopBackIfP/ipRouteP/ipNexthopP |
| nodes static_routes track_list / next_hops ip_sla_policy-track | **MANQUANT** | ipRsRouteTrack / ipRsNexthopRouteTrack / ipRsNHTrackMember absents |
| bgp_peers (loopback, node-level) | **MANQUANT** | bgpPeerP capturé UNIQUEMENT par parent = path binding (peer_bind.get(pb["dn"]) nac.py:1021) ; les bgpPeerP sous l3extLNodeP jamais lus |
| bgp_infra_peers | **MANQUANT** | bgpInfraPeerP absent |
| multipod, remote_leaf | **MANQUANT** | l3extInfraNodeP (fabricExtCtrlPeering) absent |
| sr_mpls, vxlan_enabled | **MANQUANT** | mplsNodeSidP / relations custom qos absents |
| vxlan_custom_qos_policy, mpls_custom_qos_policy | **MANQUANT** | l3extRsLNodePVxlanCustQosPol / l3extRsLNodePMplsCustQosPol absents |
| bfd_multihop_node_policy, bfd_multihop_auth_key_id/_type | **MANQUANT** | bfdMhNodeP / bfdRsMhNodePol absents |
| bfd_multihop_auth_key | SECRET | (ignore_changes) mais le bloc entier est manquant de toute façon |
| bgp_protocol_profile_name, bgp_timer_policy, bgp_as_path_policy | **MANQUANT** | bgpProtP / bgpRsBgpNodeCtxPol / bgpRsBestPathCtrlPol absents |

## 22. l4l7-device — À TROUS
DED nac.py:1602-1676 (physique single-context).
| variable | statut | preuve |
|---|---|---|
| tenant/name/alias/context_aware/type/function/copy_device/managed/promiscuous_mode/service_type/trunking/active_active | DED 1612-1637 | vnsLDevVip |
| physical_domain | DED 1610,1638 | vnsRsALDevToPhysDomP |
| vmm_provider, vmm_domain | **MANQUANT** | vnsRsALDevToDomP (VMM) jamais lu — device VIRTUAL perd son domaine |
| concrete_devices (name, interfaces port simple pod/node/module/port) | DED 1640-1656 | vnsCDev/vnsCIf/vnsRsCIfPathAtt |
| concrete_devices vcenter_name/vm_name | **MANQUANT** | attrs vcenterName/vmName de vnsCDev non capturés |
| concrete_devices interfaces channel (PC/vPC) et fex | **MANQUANT** | regex nac.py:1647 exige `pod-X/paths-Y/pathep-[ethM/P]` → protpaths/pathep-[<channel>]/extpaths non matchés |
| logical_interfaces (name, vlan, concrete_interfaces) | DED 1658-1671 | vnsLIf + vnsRsCIfAttN |

## 23. ldap — 100 % (secrets + 1 nuance)
capture_aaa_security nac.py:3016-3082.
| variable | statut |
|---|---|
| ldap_providers (hostname_ip, description, port, bind_dn, base_dn, timeout, retries, enable_ssl, filter, attribute, ssl_validation_level, monitoring, monitoring_username) | DED 3018-3049 |
| ldap_providers.password, monitoring_password | SECRET (docstring : omis, ignore_changes) |
| ldap_providers mgmt_epg | DED partiel : `oob` capturé ; inb=défaut recréé par le module (documenté) ; un mgmt_epg_name inb custom serait perdu (mineur) |
| group_map_rules (name, description, group_dn, security_domains/roles) | DED 3050-3068 |
| group_maps (name, rules) | DED 3069-3076 |

## 24. link-level-policy — 100 %
GEN flat (fabricHIfPol : speed, dfeDelayMs, linkDebounce, fecMode simples) + DED nac.py:3506-3518 pour autoNeg (ternaire imbriqué auto/auto_enforce) et portPhyMediaType (physical_media_type).

## 25. lldp-policy — 100 %
GEN flat : lldpIfPol adminRxSt/adminTxSt bools + portDCBXPVer simple.

## 26. login-domain — À TROUS
PHASE2 (nac.py:56) → capture_aaa_security nac.py:3083-3107.
| variable | statut | preuve |
|---|---|---|
| name, description | DED 3088-3092 | aaaLoginDomain |
| realm | DED 3094-3096 | aaaDomainAuth |
| tacacs/radius/ldap_providers (+priority) | DED 3097-3103 | aaaProviderRef par provider group |
| auth_choice | **MANQUANT** | attribut authChoice de aaaLdapProviderGroup jamais lu |
| ldap_group_map | **MANQUANT** | attribut ldapGroupMapRef de aaaLdapProviderGroup jamais lu |

## 27. macsec-interfaces-policy — 100 %
PHASE2-like : capture_secretful_policies nac.py:1949-1974 : macsecIfPol (access) ET macsecFabIfPol (fabric) → name, admin_state, description + macsecRsToKeyChainPol / macsecRsToParamPol (aucun secret). Var `type` implicite par bucket access/fabric.

---

# LOT 5

# Couverture brownfield nac.py — batch 5 (27 modules)

Légende statuts : G = générique (attr_map/_flat/_tenant_flat), D = capture dédiée (ligne nac.py), S = secret documenté, ❌ = MANQUANT.

## macsec-keychain-policies (macsecKeyChainPol + macsecKeyPol) — COUVERT (secrets documentés)
| variable | statut | preuve |
|---|---|---|
| name | D | capture_secretful_policies nac.py:1931 |
| description | D | nac.py:1932-1933 |
| key_policies.name / key_name | D | nac.py:1936 |
| key_policies.description | D | nac.py:1938-1939 |
| key_policies.end_time | D | nac.py:1940-1941 (≠ infinite) |
| key_policies.pre_shared_key | S | placeholder MACSEC_PSK_PLACEHOLDER nac.py:1937 (write-only, ignore_changes module) |
| key_policies.start_time | S/omis documenté | ignore_changes module + commentaire nac.py:1942 |
| type | D | bucket par DN /infra/ vs fabric nac.py:1944 → access_policies.interface_policies / fabric_policies (nac.py:3708-3712) |

## macsec-parameters-policy (macsecParamPol / macsecFabParamPol) — À TROUS
| variable | statut | preuve |
|---|---|---|
| name, description | D | capture_macsec_param_policies nac.py:2752-2754 |
| cipher_suite | D | nac.py:2755 |
| confidentiality_offset | D | nac.py:2757 |
| key_server_priority | D | nac.py:2759 |
| window_size | D | nac.py:2761 |
| key_expiry_time | D | nac.py:2763 |
| security_policy | D | nac.py:2765 |
| type = "fabric" | ❌ | seule la classe access `macsecParamPol` est interrogée (nac.py:2749) et rangée dans access_policies (nac.py:3699-3701). Les policies FABRIC (`macsecFabParamPol`, câblage fabric_policies.macsec_parameters_policies, aci_fabric_policies.tf:1309) ne sont PAS capturées. |

## maintenance-group (maintMaintP/maintMaintGrp) — À TROUS
| variable | statut | preuve |
|---|---|---|
| name | D | capture_update_groups nac.py:3356-3360 (via firmwareFwGrp, même nom) |
| scheduler | D | maintRsPolScheduler nac.py:3350-3354, 3361-3362 |
| target_version | ❌ | maintMaintP.version jamais lu (capture_update_groups ne lit que firmwareFwGrp+scheduler nac.py:3347-3364) |
| node_ids | ❌ | fabricNodeBlk sous maintMaintGrp non capturé (grep : fabricNodeBlk seulement pour switch profiles nac.py:2569/2635) ; aucun `update_group` n'est écrit sur node_policies.nodes[] (câblage : node_ids = nodes où node.update_group == name, aci_node_policies.tf) |

## management-access-policy (commPol + commTelnet/Ssh/Https/Http) — À TROUS (omission déclarée « défauts idempotents »)
| variable | statut | preuve |
|---|---|---|
| name, description | D | capture_management_access_policies nac.py:3229-3231 |
| telnet_admin_state, telnet_port | D | nac.py:3232-3235 |
| ssh_admin_state, ssh_port, ssh_password_auth | D | nac.py:3236-3240 |
| ssh_aes128_ctr…ssh_chacha (6 flags sshCiphers) | ❌ | omis (docstring nac.py:3216) |
| ssh_hmac_sha1/sha2_256/sha2_512 (sshMacs) | ❌ | omis |
| ssh_curve25519…ssh_ecdh_sha2_nistp521 (9 flags kexAlgos) | ❌ | omis |
| https_admin_state, https_client_cert_auth_state, https_port, https_dh | D | nac.py:3241-3248 (⚠️ port/dh non round-trippables sim 6.0(7e), verrouillé 443) |
| https_tlsv1, _1_1, _1_2, _1_3 (sslProtocols) | ❌ | omis |
| https_keyring (commRsKeyRing) | ❌ | grep commRsKeyRing : absent de nac.py |
| https_allow_origins / http_allow_origins (accessControlAllowOrigins) | ❌ | non capturés |
| http_admin_state, http_port | D | nac.py:3249-3252 |

## match-rule (rtctrlSubjP) — À TROUS
| variable | statut | preuve |
|---|---|---|
| tenant | clé placement | tenant-flat |
| name, description | G | _tenant_flat_table (moteur générique), MODULE_COVERAGE l.127 |
| prefixes (ip/aggregate/description/from_length/to_length) | D | rtctrlMatchRtDest nac.py:613-628 (tous les champs du module) |
| community_terms (+ factors community/scope/description) | ❌ | rtctrlMatchCommTerm / rtctrlMatchCommFactor absents de nac.py (grep) |
| regex_community_terms | ❌ | rtctrlMatchCommRegexTerm absent de nac.py |

## mcp-policy (mcpIfPol) — 100 %
| variable | statut | preuve |
|---|---|---|
| name | G | direct |
| admin_state | G | ternaire bool `== true ? "enabled":"disabled"` (_RE_BOOL) ; câblage access_policies.interface_policies.mcp_policies dans _flat_table |

## monitoring-policy (= entrée "common", moncommon) — À TROUS
| variable | statut | preuve |
|---|---|---|
| syslog_policies (name, audit/events/faults/session, minimum_severity, destination_group) | D | capture_common_monitoring nac.py:3256-3279 (incl flags + minSev + syslogRsDestGroup) |
| snmp_trap_policies (name, destination_group) | ❌ | snmpSrc / snmpRsDestGroup absents de nac.py (grep) — déféré avec le module snmp-trap-policy (MODULE_COVERAGE l.147) |

## monitoring-policy-custom (monFabricPol) — À TROUS
| variable | statut | preuve |
|---|---|---|
| name, description | D | capture_monitoring_policies nac.py:2077-2079, appel monFabricPol nac.py:3433 |
| fault_severity_policies (class, faults fault_id/initial/target/description) | D | monFabricTarget + faultSevAsnP nac.py:2080-2095 |
| snmp_trap_policies | ❌ | snmpSrc sous monfab- non capturé |
| syslog_policies | ❌ | syslogSrc capturé UNIQUEMENT sous /moncommon/ (filtre nac.py:3261,3264) ; sous monfab- rien |

## mpls-custom-qos-policy (qosMplsCustomPol, tn-infra) — 100 %
| variable | statut | preuve |
|---|---|---|
| name, alias, description | D | capture_tenants nac.py:1465-1472 |
| ingress_rules (exp_from/exp_to/priority/dscp_target/cos_target) | D | qosMplsIngressRule nac.py:1473-1483 |
| egress_rules (dscp_from/dscp_to/exp_target/cos_target) | D | qosMplsEgressRule nac.py:1484-1492 |

## mst-policy (stpMstRegionPol) — 100 %
| variable | statut | preuve |
|---|---|---|
| name | D | capture_mst_policies nac.py:3139 |
| region | D | regName nac.py:3140-3141 |
| revision | D | rev nac.py:3142-3143 |
| instances (name, id, vlan_ranges from/to) | D | stpMstDomPol + fvnsEncapBlk nac.py:3144-3157 |

## multicast-route-map (pimRouteMapPol) — 100 %
| variable | statut | preuve |
|---|---|---|
| tenant | clé | tenant-flat |
| name, description | G | _tenant_flat_table |
| entries (order/action/source_ip/group_ip/rp_ip) | D | pimRouteMapEntry nac.py:629-647 (tous les champs) |

## nd-interface-policy (ndIfPol) — 100 %
Toutes variables G : controller_state = `join(",", var.x)` → _RE_JOIN (list) ; nud_retransmit_base/interval/count = `!= 0 ? x : null` → _RE_NUMNULL ; hop_limit, ns_tx_interval, mtu, retransmit_retry_count, route_advertise_interval, router_lifetime, reachable_time, retransmit_timer, description = direct. tenant = clé. (MODULE_COVERAGE l.199 : 13 attrs round-trip.)

## nd-ra-prefix-policy (ndPfxPol) — 100 %
G : auto_configuration/on_link/router_address = flags concat (kind "flag") ; valid_lifetime→lifetime, preferred_lifetime→prefLifetime, description = direct. (l.200 : golden.)

## netflow-exporter (accès, netflowExporterPol uni/infra) — 100 %
| variable | statut | preuve |
|---|---|---|
| name, description, dscp, destination_ip, destination_port, source_type, source_ip | G | content plat, capture_flat (filtre /tn-/ nac.py:351 évite le doublon tenant) |
| vrf + tenant | D | netflowRsExporterToCtx /infra/ nac.py:3539,3546-3548 |
| epg_type/application_profile/endpoint_group/l3out/external_endpoint_group + tenant | D | netflowRsExporterToEPg nac.py:3540,3549-3555 |

## netflow-monitor (accès) — 100 %
name/description G ; flow_record D (netflowRsMonitorToRecord nac.py:3557,3563-3565) ; flow_exporters D (netflowRsMonitorToExporter nac.py:3558,3566-3569).

## netflow-record (accès) — 100 %
name/description G ; match_parameters D : `match = join(",", sort(...))` non parsé par _RE_JOIN → enrichissement nac.py:3531-3537 (split + sorted = équivalent exact du sort du module ; un seul attribut, tout est couvert).

## netflow-vmm-exporter (netflowVmmExporterPol) — 100 %
name, description, destination_ip, destination_port, source_ip = G (tous direct) ; `ver="v9"` constante. Câblage access_policies.interface_policies.netflow_vmm_exporters → _flat_table.

## node-control-policy (fabricNodeControl) — 100 %
name G ; dom = ternaire bool `== true ? "Dom" : ""` (_RE_BOOL) ; telemetry (featureSel) direct. Câblage fabric_policies.switch_policies.node_control_policies → _flat_table.

## oob-contract (vzOOBBrCP) — À TROUS
| variable | statut | preuve |
|---|---|---|
| name, alias, description, scope | D | capture_tenants nac.py:1372-1384 (tenant mgmt) |
| subjects (vzSubj name/alias/description + filters vzRsSubjFiltAtt filter/action/log/no_stats/priority) | ❌ | vzSubj/vzRsSubjFiltAtt sous vzOOBBrCP non capturés (RESTE confirmé, MODULE_COVERAGE l.56) |

## oob-endpoint-group (mgmtOoB) — 100 %
name D (nac.py:1395) ; oob_contract_providers D (mgmtRsOoBProv nac.py:1389,1396-1398) ; static_routes (liste de préfixes) D (mgmtStaticRoute nac.py:1390,1399-1401).

## oob-external-management-instance (mgmtInstP) — 100 %
name D (nac.py:1448) ; subnets D (mgmtSubnet nac.py:1442,1449-1451) ; oob_contract_consumers D (mgmtRsOoBCons nac.py:1443,1452-1454).

## oob-node-address (mgmtRsOoBStNode) — À TROUS (mineur) + limites documentées
| variable | statut | preuve |
|---|---|---|
| node_id | D | regex node-(\d+) nac.py:2038-2041 |
| ip/gateway/v6_ip/v6_gateway | D | addr/gw/v6Addr/v6Gw nac.py:2052-2059 |
| endpoint_group | D | nac.py:2048-2050, 2061-2063 (omis si "default" = défaut câblage) |
| pod_id | ❌ | le DN `pod-P` n'est jamais extrait (nac.py:2038) et `pod` n'est pas écrit sur le node → un nœud mgmt en pod≠1 serait re-rendu `pod-1` |
| (limite) nœuds ENREGISTRÉS + node-1 | documenté | exclusion volontaire avec warning nac.py:2042-2047 (sécurité node_registration) |

## ospf-interface-policy (ospfIfPol tenant) — 100 %
G : cost, dead_interval, hello_interval, network_type, priority, lsa_retransmit_interval, lsa_transmit_delay, description direct ; advertise_subnet/bfd/mtu_ignore/passive_interface = 4 flags concat (kind "flag"). tenant = clé.

## ospf-route-summarization-policy (ospfRtSummPol) — 100 %
G : cost direct ; inter_area = ternaire yes/no ; description direct.

## ospf-timer-policy (ospfCtxPol) — 100 %
G : 18 attrs direct (bwRef, dist, maxEcmp, spf*, lsa*, maxLsa*) ; graceful_restart = ternaire `"helper":""` ; router_id_lookup/prefix_suppression = flags concat.

## physical-domain (physDomP, PHASE2 → capture dédiée) — À TROUS
| variable | statut | preuve |
|---|---|---|
| name | D | capture_access nac.py:416-425 |
| vlan_pool | D | infraRsVlanNs nac.py:415, _ref nac.py:378-384 |
| vlan_pool_allocation | OK (dérivé) | le câblage la recalcule depuis vlan_pools[].allocation (aci_access_policies.tf:23), capturée avec les pools |
| security_domains | ❌ | aaaDomainRef sous physDomP non capturé (grep : seul usage aaaDomainRef = néant) alors que le câblage le passe (aci_access_policies.tf:24) |

## pim-policy (pimIfPol tenant) — À TROUS (+ secret documenté)
| variable | statut | preuve |
|---|---|---|
| name, auth_type, designated_router_delay/priority, hello_interval, join_prune_interval | G | direct (tenant-flat, #64) |
| mcast_dom_boundary/passive/strict_rfc | G | flags ctrl concat |
| auth_key | S | secureAuthKey write-only, ignore_changes module, auth_type=none par défaut (MODULE_COVERAGE l.135) |
| neighbor_filter_policy | ❌ | pimNbrFilterPol + rtdmcRsFilterToRtMapPol absents de nac.py (grep rtdmc : 0) |
| join_prune_filter_policy_out | ❌ | pimJPOutbFilterPol absent |
| join_prune_filter_policy_in | ❌ | pimJPInbFilterPol absent |

## Bilan
- 100 % couverts (16) : macsec-keychain-policies*, mcp-policy, mpls-custom-qos-policy, mst-policy, multicast-route-map, nd-interface-policy, nd-ra-prefix-policy, netflow-exporter, netflow-monitor, netflow-record, netflow-vmm-exporter, node-control-policy, oob-endpoint-group, oob-external-management-instance, ospf-interface-policy, ospf-route-summarization-policy, ospf-timer-policy. (*secrets = placeholder documenté)
- À trous (9) : macsec-parameters-policy (fabric), maintenance-group (target_version, node_ids), management-access-policy (ciphers/kex/tls/keyring/allow-origins), match-rule (community terms), monitoring-policy (snmp), monitoring-policy-custom (snmp+syslog), oob-contract (subjects), oob-node-address (pod_id), physical-domain (security_domains), pim-policy (filtres PIM).

---

# LOT 6

# Couverture brownfield nac.py — batch 6 (27 modules)

Statuts : GÉNÉRIQUE (attr_map + moteur plat/singleton/tenant-flat), DÉDIÉ (code capture_* cité), SECRET (omis volontairement, documenté), **MANQUANT**.

## port-channel-member-policy (lacpIfPol, access flat) — 100%
| variable | statut | preuve |
|---|---|---|
| name | GÉNÉRIQUE | `name = var.name` |
| priority | GÉNÉRIQUE | `prio = var.priority` |
| rate | GÉNÉRIQUE | `txRate = var.rate` |

## port-channel-policy (lacpLagPol, access flat) — 100%
| variable | statut | preuve |
|---|---|---|
| name, mode, min_links, max_links | GÉNÉRIQUE | exprs directes |
| suspend_individual, graceful_convergence, fast_select_standby, load_defer, symmetric_hash | DÉDIÉ | ctrl via locals (non parsé par attr_map) → reverse dédié nac.py:3570-3583 (PC_FLAGS) |
| hash_key | DÉDIÉ | l2LoadBalancePol.hashFields nac.py:3573,3584-3585 |

## port-security-policy (l2PortSecurityPol, access flat) — 100%
name, description, maximum_endpoints, timeout : GÉNÉRIQUE (name/descr/maximum/timeout directs).

## port-tracking (infraPortTrackPol, singleton fabric)
| variable | statut | preuve |
|---|---|---|
| admin_state | GÉNÉRIQUE | ternaire bool on/off |
| delay, min_links | GÉNÉRIQUE | directs |
| include_apic | **MANQUANT** | `includeApicPorts = var.include_apic == true ? "yes" : (== false ? "no" : null)` ternaire 3-états non parsé par attr_map ; aucun code dédié (grep includeApicPorts = 0 hit) |

## priority-flow-control-policy (qosPfcIfPol, access flat) — 100%
| variable | statut | preuve |
|---|---|---|
| name, description | GÉNÉRIQUE | directs |
| admin_state, auto_state | DÉDIÉ | adminSt ternaire 3-états → enrichissement nac.py:3519-3530 [#44] |

## psu-policy (psuInstPol, PHASE2) — 100%
name + admin_state (adminRdnM comb/rdn/ps-rdn) : DÉDIÉ capture_psu_policies nac.py:3304-3313.

## ptp (latencyPtpMode, singleton fabric) — 100%
admin_state (bool), global_domain, profile, announce_interval, announce_timeout, sync_interval, delay_interval : GÉNÉRIQUE singleton (tous try(local.fabric_policies.ptp.*) dans le parent, exprs simples).

## ptp-profile (ptpProfile, access flat) — 100%
| variable | statut | preuve |
|---|---|---|
| name, announce_interval, announce_timeout, delay_interval, sync_interval, priority | GÉNÉRIQUE | directs |
| forwardable | GÉNÉRIQUE | ternaire bool implicite |
| template, mismatch_handling | DÉDIÉ | ternaires chaînés → enrichissement nac.py:3611-3625 |

## qos (qosInstPol, singleton access)
| variable | statut | preuve |
|---|---|---|
| preserve_cos | GÉNÉRIQUE | ctrl ternaire bool "dot1p-preserve"/"" (singleton, méthode C validée #95) |
| qos_classes | **MANQUANT** | enfants qosClass/qosSched/qosPfcPol/qosCong/qosBuffer (for_each) — 0 hit nac.py ; MODULE_COVERAGE #95 : « enfants qos classes level1-6 non mappés ». Perd : admin_state, mtu, bandwidth_percent, scheduling, congestion_algorithm, minimum_buffer, pfc_state, no_drop_cos, pfc_scope, ecn, forward_non_ecn, wred_*, weight par level |

## qos-policy (qosCustomPol, tenant flat) — 100%
| variable | statut | preuve |
|---|---|---|
| tenant, name, alias, description | GÉNÉRIQUE | tenant flat (name/nameAlias/descr) |
| dscp_priority_maps, dot1p_classifiers | DÉDIÉ | qosDscpClass/qosDot1PClass nac.py:682-703 (_qos_map : from/to/priority/dscp_target/cos_target) [#83] |

## radius (aaaRadiusProvider, PHASE2) — 100% hors secrets
| variable | statut | preuve |
|---|---|---|
| hostname_ip, description, protocol, port, retries, timeout, monitoring, monitoring_username | DÉDIÉ | capture_aaa_security nac.py:2932-2957 |
| mgmt_epg_type/name | DÉDIÉ | aaaRsSecProvToEpg nac.py:2931,2951-2952 (oob seul ; inb=défaut ; le nom d'EPG vient de node_policies, pas du data model radius) |
| key, monitoring_password | SECRET (documenté) | ignore_changes module + docstring nac.py:2925-2927 |

## redirect-backup-policy (vnsBackupPol) — 100%
name, description : DÉDIÉ nac.py:1563-1569 ; l3_destinations (ip, destination_name, description, mac, ip_2, redirect_health_group) : DÉDIÉ nac.py:1571-1589 (vnsRedirectDest + vnsRsRedirectHealthGroup).

## redirect-health-group (vnsRedirectHealthGroup) — 100%
name, description : DÉDIÉ nac.py:1497-1506.

## redirect-policy (vnsSvcRedirectPol)
| variable | statut | preuve |
|---|---|---|
| name, alias, description, anycast, type, hashing, threshold, max/min_threshold, pod_aware, resilient_hashing, threshold_down_action | DÉDIÉ | nac.py:1511-1539 |
| rewrite_source_mac | DÉDIÉ | srcMacRewriteEnabled nac.py:1536-1537 |
| l3_destinations (ip, name, description, mac, ip_2, redirect_health_group) | DÉDIÉ | nac.py:1540-1558 |
| l3_destinations[].pod (podId) | **MANQUANT** | vnsRedirectDest.podId non lu (nac.py:1541-1556) ; clé data model `pod` existe (aci_tenants.tf redirect_policies locals) |
| ip_sla_policy (+ ip_sla_policy_tenant) | **MANQUANT** | vnsRsIPSLAMonitoringPol : 0 hit nac.py (le hit ip_sla_policy l.1331 = track_members) |
| redirect_backup_policy | **MANQUANT** | vnsRsBackupPol : 0 hit nac.py |
| l1l2_destinations | **MANQUANT** | vnsL1L2RedirectDest / vnsRsL1L2RedirectHealthGroup / vnsRsToCIf : 0 hit nac.py (RESTE confirmé) |

## remote-location (fileRemotePath, PHASE2) — 100% hors secrets
| variable | statut | preuve |
|---|---|---|
| name, hostname_ip, protocol, description, auth_type, path, port, username | DÉDIÉ | capture_secretful_policies nac.py:1895-1909 |
| mgmt_epg_type/name | DÉDIÉ | fileRsARemoteHostToEpg nac.py:1891-1893,1907-1908 (oob seul ; nom EPG = node_policies) |
| password, ssh_private_key, ssh_public_key, ssh_passphrase | SECRET (documenté) | write-only, ignore_changes ; docstring nac.py:1890 |

## remote-vxlan-fabric-policy (vxlanRemoteFabric, tenant infra)
| variable | statut | preuve |
|---|---|---|
| name | au mieux GÉNÉRIQUE plat tenant (si classe résolue) | contenu = name seul |
| remote_evpn_peers | **MANQUANT** | bgpInfraPeerP/bgpAsP/bgpLocalAsnP/bgpRsPeerPfxPol : 0 hit nac.py — perd ip, description, ttl, admin_state, allow_self_as, disable_peer_as_check, remote_as, local_as, as_propagate, peer_prefix_policy (password = secret) |
| border_gateway_set | **MANQUANT** | vxlanRsRemoteFabricToBgwSet : 0 hit nac.py |
NB : MODULE_COVERAGE l.142 = ⛔ LIMITE DÉFINITIVE : famille vxlan* absente du data model APIC 6.0(7e) (classes non résolues) → non capturable sur cette fabric de toute façon.

## rogue-endpoint-control (epControlP, singleton fabric) — 100%
admin_state (bool), hold_interval, detection_interval, detection_multiplier : GÉNÉRIQUE singleton (parent = try(local.fabric_policies.rogue_ep_control.*)).

## route-control-route-map (rtctrlProfile, tenant flat) — 100%
| variable | statut | preuve |
|---|---|---|
| tenant, name, type, description | GÉNÉRIQUE | tenant flat (name/descr/type directs) |
| contexts (name, description, action, order, set_rule, match_rules) | DÉDIÉ | rtctrlCtxP + rtctrlRsScopeToAttrP + rtctrlRsCtxPToSubjP nac.py:561-585 |

## routed-domain (l3extDomP, PHASE2)
| variable | statut | preuve |
|---|---|---|
| name | DÉDIÉ | capture_access nac.py:416-426 |
| vlan_pool | DÉDIÉ | infraRsVlanNs nac.py:415,423-424 |
| vlan_pool_allocation | dérivée (pas un trou) | le parent la calcule depuis vlan_pools[].allocation (capturé avec le pool, allocMode) |
| security_domains | **MANQUANT** | aaaDomainRef sous l3extDomP : non capturé (le hit security_domains nac.py:3063 = règles LDAP) |

## route-tag-policy (l3extRouteTagPol, tenant flat) — 100%
tenant, name, description, tag : GÉNÉRIQUE (locals route_tag_policies → policies.route_tag_policies, exprs directes).

## service-epg-policy (vnsSvcEPgPol) — 100%
name, description, preferred_group : DÉDIÉ nac.py:1590-1601.

## service-graph-template (vnsAbsGraph)
| variable | statut | preuve |
|---|---|---|
| tenant, name, description, alias | DÉDIÉ | nac.py:1674-1682 |
| template_type, redirect, share_encapsulation | DÉDIÉ | vnsAbsNode single nac.py:1684-1691 |
| device_name, device_tenant, device_node_name | DÉDIÉ | vnsRsNodeToLDev nac.py:1692-1701 |
| device_function (funcType) | **MANQUANT** | non lu sur vnsAbsNode |
| device_copy (isCopy), device_managed (managed) | **MANQUANT** | non lus |
| device_adjacency_type (adjType), consumer_direct_connect, provider_direct_connect (directConnect) | **MANQUANT** | vnsAbsConnection non capturé |
| devices, connections (multi-device) | **MANQUANT (documenté)** | nac.py:1602-1604 « multi-device NON captures » ; capture single-device seulement (len(nl)==1, nac.py:1684) |
| annotation | non capturé (dérivé ndo_managed, cohérent avec tout le générateur — pas compté) | |

## set-rule (rtctrlAttrP, tenant flat)
| variable | statut | preuve |
|---|---|---|
| tenant, name, description | GÉNÉRIQUE | tenant flat |
| community, community_mode | DÉDIÉ | rtctrlSetComm nac.py:587,596-600 |
| tag, weight, next_hop, preference, metric | DÉDIÉ | nac.py:588-609 |
| metric_type | DÉDIÉ | rtctrlSetRtMetricType nac.py:610-612 |
| dampening, dampening_half_life, dampening_max_suppress_time, dampening_reuse_limit, dampening_suppress_limit | **MANQUANT** | rtctrlSetDamp : 0 hit nac.py |
| additional_communities | **MANQUANT** | rtctrlSetAddComm : 0 hit |
| set_as_paths (criteria, count, asns) | **MANQUANT** | rtctrlSetASPath/rtctrlSetASPathASN : 0 hit |
| next_hop_propagation | **MANQUANT** | rtctrlSetNhUnchanged : 0 hit |
| multipath | **MANQUANT** | rtctrlSetRedistMultipath : 0 hit |
| external_endpoint_group (+ _l3out, _tenant) | **MANQUANT** | rtctrlSetPolicyTag/rtctrlRsSetPolicyTagToInstP : 0 hit |

## snmp-policy (snmpPol, fabric)
| variable | statut | preuve |
|---|---|---|
| name, admin_state, location, contact | DÉDIÉ | capture_snmp_policies nac.py:2778-2787 |
| communities | DÉDIÉ | snmpCommunityP nac.py:2775,2788-2790 |
| trap_forwarders (ip, port) | DÉDIÉ | snmpTrapFwdServerP nac.py:2776,2791-2798 |
| users | SECRET (documenté) | authKey/privKey write-only, docstring nac.py:2772 |
| clients | **MANQUANT (omission volontaire documentée)** | snmpClientGrpP/snmpClientP/snmpRsEpg non capturés — docstring nac.py:2772-2773 « liés au mgmt_epg node_policies -> omis » ; c'est quand même une perte de config fabric (client groups + entries) |

## snmp-trap-policy (snmpGroup, fabric flat)
| variable | statut | preuve |
|---|---|---|
| name, description | GÉNÉRIQUE | flat fabric (monitoring.snmp_traps) |
| destinations | **MANQUANT (DÉFÉRÉ documenté)** | snmpTrapDest + fileRsARemoteHostToEpg : 0 hit capture ; MODULE_COVERAGE l.147 DÉFÉRÉ #76 (secName = community SECRET obligatoire, snmpTrapDest dans SECRET_CLASSES nac.py:3824) → hostname_ip/port/security/version/mgmt_epg perdus |

## spanning-tree-policy (stpIfPol, access flat) — 100%
name : GÉNÉRIQUE ; bpdu_filter/bpdu_guard : GÉNÉRIQUE via handler flag (ctrl = join+concat INLINE, parsé attr_map nac.py:177-183).

## sr-mpls-global-configuration (mplsSrgbLabelPol, singleton fabric) — 100%
sr_global_block_minimum/maximum : GÉNÉRIQUE singleton (minSrgbLabel/maxSrgbLabel directs, parent try(local.fabric_policies.sr_mpls_global_configuration.*)).

---

# LOT 7

# Couverture brownfield nac.py — batch 7 (25 modules)

Légende statuts : GEN = moteur générique (attr_map + _flat/_singleton/_tenant_flat_table) ; DED = capture dédiée (ligne nac.py) ; SECRET = write-only documenté ; N/A = pas d'état fabric / clé de contexte ; **MANQUANT** = perte au round-trip.

## storm-control-policy — ✅ 100%
Flat table access_policies.interface_policies.storm_control_policies (classe stormctrlIfPol, non-PHASE2, for_each try(local...)).
| variable | statut | preuve |
|---|---|---|
| name / alias / description / action | GEN direct | content fvCtx-like simple |
| rate / burst_rate / *_rate (bc/mc/uuc) | GEN float | `format("%.6f", var.x)` → _RE_FLOAT (nac.py:154) |
| rate_pps / burst_pps / *_pps | GEN direct | |
| configuration_type | DED | nac.py:3604-3610 (isUcMcBcStormPktCfgValid Invalid→"all", défaut separate) |

## switch-configuration — ✅ 100%
| variable | statut | preuve |
|---|---|---|
| node_id | DED | capture_port_configurations nac.py:2012-2019 (attr node) |
| access_policy_group | DED | infraNodeConfig assocGrp regex nac.py:2016 |
| fabric_policy_group | DED | fabricNodeConfig assocGrp nac.py:2012-2019 |
| role | DED | nac.py:2020 (déduit du type de policy group) ; sans danger : aci_node_registration désactivé (DISABLE_MODULES nac.py:83) |

## syslog-policy — ✅ 100% (au niveau du schéma YAML)
capture_syslog_policies nac.py:2679-2743.
| variable | statut | preuve |
|---|---|---|
| name/description/format/show_millisecond/show_timezone | DED | nac.py:2693-2702 (format rfc5424-ts↔enhanced-log) |
| admin_state | DED | syslogProf nac.py:2703-2705 |
| local_admin_state / local_severity | DED | syslogFile nac.py:2706-2711 |
| console_admin_state / console_severity | DED | syslogConsole nac.py:2712-2717 |
| destinations (name, hostname_ip, protocol, port, admin_state, facility, severity, mgmt_epg) | DED | nac.py:2718-2741 (mgmt_epg via fileRsARemoteHostToEpg) |
| destinations.format | N/A schéma | le YAML NaC n'a PAS de format par destination : le parent recopie le format du groupe (aci_fabric_policies.tf:979). Un format par-dest posé à la main hors YAML serait écrasé, mais inexprimable dans le data model → pas un trou nac.py. |
| destinations.mgmt_epg_name | N/A schéma | dérivé de node_policies.oob/inb_endpoint_group par le parent |

## system-global-gipo — ✅ 100%
Singleton (count + try(local.fabric_policies.use_infra_gipo)) → _singleton_table nac.py:283 ; use_infra_gipo bool GEN (useConfiguredSystemGIPo).

## system-performance — ✅ 100%
Singleton ; admin_state (bool), response_threshold, top_slowest_requests, calculation_window : tous GEN (content simple).

## tacacs — ✅ couvert (secrets documentés)
capture_aaa_security nac.py:2932-2960 (providers aaaTacacsPlusProvider).
| variable | statut |
|---|---|
| hostname_ip/description/protocol/port/retries/timeout/monitoring/monitoring_username | DED nac.py:2934-2953 |
| key, monitoring_password | SECRET (ignore_changes dans le module, omis — documenté nac.py:2925-2927) |
| mgmt_epg_type | DED (oob capturé nac.py:2951 ; inb = défaut du data model) |
| mgmt_epg_name | N/A schéma (dérivé node_policies.*_endpoint_group par le parent) |

## tenant — ⚠️ trous
capture_tenants nac.py:788 (obj fvTenant : name, nameAlias→alias, descr→description).
| variable | statut |
|---|---|
| name/alias/description | GEN via obj() |
| security_domains | **MANQUANT** — aaaDomainRef enfant non capturé (aucune occurrence dans nac.py ; documenté « omis » MODULE_COVERAGE.md:151). Un tenant rattaché à un security domain perd ce rattachement. |
| annotation (ndo_managed) | **MANQUANT** (mineur) — attribut resource-level hors content{}, non vu par attr_map ; YAML ndo_managed (orchestrator:msc) non reconstruit. Impact : fabrics pilotées NDO uniquement. |

## tenant-monitoring-policy — ⚠️ trous
Base GEN _tenant_flat_table (monEPGPol, sub policies.monitoring.policies) + enrichissement nac.py:704-723.
| variable | statut |
|---|---|
| name/description | GEN |
| fault_severity_policies | DED nac.py:707-723 (monEPGTarget + faultSevAsnP) |
| snmp_trap_policies | **MANQUANT** — snmpSrc + snmpRsDestGroup non capturés (omission documentée nac.py:706, MODULE_COVERAGE.md:152) |
| syslog_policies | **MANQUANT** — syslogSrc + syslogRsDestGroup non capturés (idem) |

## tenant-netflow-exporter — ✅ 100%
GEN (netflowExporterPol : dscp, dstAddr, dstPort, sourceIpType, srcAddr, name, descr tous directs) + DED nac.py:659-673 : vrf (netflowRsExporterToCtx), epg_type/application_profile/endpoint_group/l3out/external_endpoint_group (netflowRsExporterToEPg).

## tenant-netflow-monitor — ✅ 100%
GEN (name/descr) + DED nac.py:674-681 : flow_record (netflowRsMonitorToRecord), flow_exporters (netflowRsMonitorToExporter).

## tenant-netflow-record — ✅ 100%
GEN (name/descr) + DED nac.py:655-658 : match_parameters (attr match, join+sort).

## tenant-span-destination-group — ✅ 100%
GEN (name/descr) + DED nac.py:724-753 : tenant/application_profile/endpoint_group destination (spanRsDestEpg tDn), ip, source_prefix, dscp, flow_id, mtu, ttl, version (clé YAML `version` = var span_version, cf. aci_tenants.tf:4377), enforce_version.

## tenant-span-source-group — ✅ 100%
GEN (name/descr + admin_state adminSt) + DED nac.py:754-778 : destination (spanSpanLbl), sources (spanSrc name/description/direction + spanRsSrcToEpg application_profile/endpoint_group). NB : la capture émet aussi une clé `tenant` par source, absente du schéma sources (bruit inoffensif, pas une perte).

## track-list — ✅ 100%
DED nac.py:1334-1356 : name, description, type (défaut percentage), percentage_up/down, weight_up/down, track_members (fvRsOtmListMember tDn).

## track-member — ✅ 100%
DED nac.py:1312-1332 : name, description, destination_ip, scope_type+scope (scopeDn reversé /out- ou /BD-), ip_sla_policy (fvRsIpslaMonPol). ip_sla_policy_tenant : recalculé par le parent (common vs tenant, aci_tenants.tf:4568) → pas un champ YAML.

## trust-control-policy — ✅ 100%
_tenant_flat_table (local trust_control_policies ← tenant.policies.trust_control_policies, aci_tenants.tf:3568-3570). fhsTrustCtrlPol : name/descr directs + 6 ternaires bool (`== true ? "yes":"no"`) tous parsés par _RE_BOOL.

## useg-endpoint-group — ⚠️ trous multiples
DED nac.py:834-876 (fvAEPg isAttrBasedEPg=yes + fvCrtrn/fvIpAttr/fvMacAttr [#106]).
| variable | statut |
|---|---|
| name/alias/description/flood_in_encap/intra_epg_isolation/preferred_group/qos_class | GEN via obj(fvAEPg) (ternaires parsés) |
| bridge_domain | DED nac.py:838 (fvRsBd) |
| contract_consumers / contract_providers | DED nac.py:841-846 |
| physical_domains | DED nac.py:848-853 |
| vmware_vmm_domains | PARTIEL — seul le NOM du domaine (nac.py:852) ; deployment_immediacy, port_binding, netflow, elag, uplinks… (fvRsDomAtt_vmm) **MANQUANTS** |
| match_type | DED nac.py:855-858 (fvCrtrn) |
| ip_statements / mac_statements | DED nac.py:859-872 |
| vm_statements | **MANQUANT** (documenté nac.py:873 : VMM absent du simulateur) |
| custom_qos_policy | **MANQUANT** (fvRsCustQosPol non capturé) |
| tags | **MANQUANT** (tagInst) |
| trust_control_policy | **MANQUANT** (fvRsTrustCtrl) |
| contract_imported_consumers | **MANQUANT** (fvRsConsIf) |
| contract_intra_epgs | **MANQUANT** (fvRsIntraEpg) |
| contract_masters | **MANQUANT** (fvRsSecInherited) |
| subnets (+ nd_ra_prefix_policy, ip_pools, next_hop, anycast, nlb) | **MANQUANT** (fvSubnet sous EPG + fvRsNdPfxPol/fvCepNetCfgPol/fvEpReachability/fvEpAnycast/fvEpNlb) |
| static_leafs | **MANQUANT** (fvRsNodeAtt) |
| l4l7_address_pools | **MANQUANT** (vnsAddrInst + fvnsUcastAddrBlk) |
| tenant / application_profile | N/A (clés de contexte, DN) |

## user — ⚠️ trous
capture_aaa_security nac.py:2963-3002.
| variable | statut |
|---|---|
| username/description/status/email/expires/expire_date/first_name/last_name/phone/certificate_name | DED nac.py:2969-2987 |
| domains (+roles, privilege_type) | DED nac.py:2988-2999 (filtre uid==0) |
| password | SECRET documenté — placeholder Placeholder123! (AAA_PWD_PLACEHOLDER, ignore_changes) |
| certificates | **MANQUANT** — aaaUserCert (name+data) non capturé ; data = certificat X.509 PUBLIC, lisible par l'API (même nature que pkiTP.certChain déjà capturé l.3008) → trou réel, pas un secret |
| ssh_keys | **MANQUANT** — aaaSshAuth (name+data) non capturé ; clé publique SSH lisible → trou réel |

## vlan-pool — ✅ 100%
PHASE2 mais capture dédiée capture_access nac.py:399-413 : name/description/allocation via obj(fvnsVlanInstP) ; ranges : description/allocation/role via obj(fvnsEncapBlk) + from/to reversés (strip "vlan-", nac.py:408-409).

## vpc-group — ✅ 100%
mode : moteur singleton (fabricProtPol pairT direct, bloc count aci_node_policies.tf:21) ; groups : capture_vpc_groups nac.py:3110-3126 (name, id, switch_1/2 via fabricNodePEp triés, policy via fabricRsVpcInstPol).

## vpc-policy — ✅ 100%
Flat table (vpcInstPol, access_policies.switch_policies.vpc_policies) : name, peer_dead_interval (deadIntvl), delay_restore_timer (delayRestoreTmr) tous directs.

## vrf — ⛔ trous MASSIFS
Seul le primaire fvCtx est capturé : obj() nac.py:794-796 → name, alias, description, data_plane_learning, enforcement_direction, enforcement_preference (6/6 attrs du content). MODULE_COVERAGE.md:161 : « Enfants … = sous-features séparées ». Aucune des 68 ressources enfants n'a de capture (grep vzAny/dnsLbl/bgpRtTarget/OspfCtxPol/BgpCtxPol/leak*/RtSumm/EpRet/snmpCtxP/pim* : zéro hit).
| variable(s) | statut |
|---|---|
| tenant | N/A (contexte) |
| name/alias/description/data_plane_learning/enforcement_direction/enforcement_preference | GEN via obj(fvCtx) |
| annotation (ndo_managed) | **MANQUANT** (mineur, resource-level) |
| preferred_group | **MANQUANT** — vzAny prefGrMemb |
| contract_consumers / contract_providers / contract_imported_consumers | **MANQUANT** — vzRsAnyToCons/Prov/ConsIf (contrats vzAny = sécurité du VRF entier !) |
| snmp_context_name / snmp_context_community_profiles | **MANQUANT** — snmpCtxP / snmpCommunityP (constat initial confirmé) |
| transit_route_tag_policy | **MANQUANT** — fvRsCtxToExtRouteTagPol |
| ospf_timer_policy | **MANQUANT** — fvRsOspfCtxPol |
| ospf_ipv4/ipv6_address_family_context_policy | **MANQUANT** — fvRsCtxToOspfCtxPol af |
| bgp_timer_policy | **MANQUANT** — fvRsBgpCtxPol |
| bgp_ipv4/ipv6_address_family_context_policy | **MANQUANT** — fvRsCtxToBgpCtxAfPol af |
| bgp_ipv4/ipv6_import/export_route_target (4 vars) | **MANQUANT** — bgpRtTargetP + bgpRtTarget |
| dns_labels | **MANQUANT** — dnsLbl |
| pim_enabled + tout le bloc PIM (mtu, fast_convergence, strict_rfc, max/reserved entries, resource policy RM, static_rps, fabric_rps, bsr_*, auto_rp_*, asm_*, ssm_*, inter_vrf_policies, igmp_ssm_translate_policies ≈ 22 vars) | **MANQUANT** — pimCtxP et toute sa sous-arborescence |
| leaked_internal_subnets / leaked_internal_prefixes / leaked_external_prefixes | **MANQUANT** — leakRoutes/leakInternalSubnet/leakInternalPrefix/leakExternalPrefix/leakTo (route leaking inter-VRF) |
| route_summarization_policies | **MANQUANT** — fvCtxRtSummPol + fvRtSummSubnet + nodes |
| endpoint_retention_policy | **MANQUANT** — fvRsCtxToEpRet |
| vxlan_enabled / border_gateway_set / normalized_vni / vxlan_import/export_route_map (5 vars) | **MANQUANT** — l3extOut vxlan + l3extVxGwFabrics etc. |

## vspan-destination-group — ✅ 100%
capture_vspan_destination_groups nac.py:2328-2368 : name/description + destinations (name, description, ip/dscp/flow_id/mtu/ttl via spanVEpgSummary, tenant/application_profile/endpoint_group/endpoint via spanRsDestToVPort cep). Filtre uni/infra + uid=0.

## vspan-session — ⚠️ trous
capture_vspan_sessions nac.py:2370-2408.
| variable | statut |
|---|---|
| name/description/admin_state | DED nac.py:2381-2385 |
| destination_name / destination_description | DED nac.py:2386-2391 (spanSpanLbl) |
| sources (name/description/direction/tenant/ap/epg) | DED nac.py:2392-2404 (spanVSrc + spanRsSrcToEpg) |
| sources[].endpoint | **MANQUANT** — spanRsSrcToVPort (cep) non capturé |
| sources[].access_paths | **MANQUANT** — spanRsSrcToPathEp (5 formes : port, sub-port, channel, fex port, fex channel) non capturé |

## vxlan-custom-qos-policy — ⛔ non capturé (limite APIC documentée)
Sub policies.vxlan_custom_qos_policies serait dans _tenant_flat_table, MAIS classes qosVxlan* NON RÉSOLUES sur APIC 6.0(7e) (HTTP 400) → get_class échoue → rien (nac.py:1460-1461 [#92] ; MODULE_COVERAGE.md:163 « LIMITE DÉFINITIVE »).
| variable | statut |
|---|---|
| name/description | non capturés sur 6.0(7e) (GEN si APIC ≥ version supportant qosVxlan*) |
| ingress_rules / egress_rules | **MANQUANT même hors 6.0(7e)** — qosVxlanIngressRule/qosVxlanEgressRule (for_each) sans enrichissement dédié |
