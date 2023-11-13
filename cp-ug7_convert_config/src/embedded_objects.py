#!/usr/bin/python3
embedded_objects = {
    "706c720f-c90d-4aa4-8ab4-967e3887f2f0": {
        "type": "service",
        "description": "Quick UDP Internet Connections",
        "port": "443",
        "proto": "udp",
        "name": "quic"
    },
    "b8f7c593-f9ee-4c55-b48a-6ce3be6760ac": {
        "type": "service",
        "description": "SSL Network Extender port",
        "port": "444",
        "proto": "tcp",
        "name": "CP_SSL_Network_Extender"
    },
    "7f5643c7-6b43-4dc4-b935-0bb9ae1f08a7": {
        "type": "service",
        "description": "",
        "port": "32640",
        "proto": "udp",
        "name": "UA_CS"
    },
    "865b8ca1-628f-4603-9976-62e1cdf5836c": {
        "type": "service",
        "description": "",
        "port": "32512",
        "proto": "udp",
        "name": "UA_PHONE"
    },
    "32ce3ea8-b561-4cfc-b215-8e754017bc96": {
        "type": "service",
        "description": "DHCP relay agent",
        "port": "67",
        "proto": "udp",
        "name": "dhcp-relay"
    },
    "6e289c30-76d8-4823-b9f2-c767c2ad69c3": {
        "type": "service",
        "description": "",
        "proto": "ipv6",
        "port": "",
        "name": "SIT_with_Intra_Tunnel_Inspection"
    },
    "97aeb44e-9aea-11d5-bd16-0090272ccb31": {
        "type": "service",
        "description": "Check Point Internal CA Management Tools",
        "port": "18265",
        "proto": "tcp",
        "name": "FW1_ica_mgmt_tools"
    },
    "50ab0021-6af0-43c9-8143-6212ffecff57": {
        "type": "service",
        "description": "Supported from version R55W, MySQL database server",
        "port": "3306",
        "proto": "tcp",
        "name": "MySQL"
    },
    "2a2ca572-fbe7-4e7f-92e4-164f5b4fded1": {
        "type": "service",
        "description": "",
        "port": "8080",
        "proto": "tcp",
        "name": "HTTP_and_HTTPS_proxy"
    },
    "8eddeaa0-259d-448f-95b6-490a39f55962": {
        "type": "service",
        "description": "",
        "port": "8080",
        "proto": "tcp",
        "name": "HTTP_proxy"
    },
    "704fbf04-1714-49a1-a750-38c0e4139a11": {
        "type": "service",
        "description": "",
        "port": "8080",
        "proto": "tcp",
        "name": "HTTPS_proxy"
    },
    "84d6c719-1844-4b00-b21f-40f7a19ca326": {
        "type": "service",
        "description": "Supported from version R55W, PostgreSQL database server",
        "port": "5432",
        "proto": "tcp",
        "name": "PostgreSQL"
    },
    "2bce9f30-30b7-444c-b29a-68343787e504": {
        "type": "service",
        "description": "Supported from version R55W, Skinny Client Control Protocol (SCCP)",
        "port": "2000",
        "proto": "tcp",
        "name": "SCCP"
    },
    "bd824b60-5c5a-42e8-a8e6-348a35cef8c4": {
        "type": "service",
        "description": "used for distributing configuration changes among cluster members and cluster wide monitoring",
        "port": "1111",
        "proto": "tcp",
        "name": "IPSO_Clustering_Mgmt_Protocol"
    },
    "97aeb388-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Security Gateway Service",
        "port": "256",
        "proto": "tcp",
        "name": "FW1"
    },
    "97aeb389-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Security Gateway Logs",
        "port": "257",
        "proto": "tcp",
        "name": "FW1_log"
    },
    "6bdfff7a-b47c-4da8-bf46-a6e987c7fe58": {
        "type": "service",
        "description": "Forwarding Information Base Manager - Dynamic Routing Cluster config",
        "port": "2010",
        "proto": "tcp",
        "name": "FIBMGR"
    },
    "97aeb38a-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Management (Version 4.x)",
        "port": "258",
        "proto": "tcp",
        "name": "FW1_mgmt"
    },
    "97aeb38b-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Security Gateway Client Authentication (Telnet)",
        "port": "259",
        "proto": "tcp",
        "name": "FW1_clntauth_telnet"
    },
    "97aeb38c-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Security Gateway Client Authentication (HTTP)",
        "port": "900",
        "proto": "tcp",
        "name": "FW1_clntauth_http"
    },
    "97aeb38d-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Check Point Security Gateway Client Authentication",
        "content": {
            "FW1_clntauth_telnet": "97aeb38b-9aea-11d5-bd16-0090272ccb30",
            "FW1_clntauth_http": "97aeb38c-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "FW1_clntauth"
    },
    "97aeb38e-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Security Gateway Session Authentication",
        "port": "261",
        "proto": "tcp",
        "name": "FW1_snauth"
    },
    "97aeb38f-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point VPN-1 SecuRemote Topology Requests",
        "port": "264",
        "proto": "tcp",
        "name": "FW1_topo"
    },
    "97aeb390-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point VPN-1 SecuRemote IPSEC Transport Encapsulation Protocol",
        "port": "2746",
        "proto": "udp",
        "name": "VPN1_IPSEC_encapsulation"
    },
    "97aeb390-9aea-11d5-bd16-0090272ccb31": {
        "type": "service",
        "description": "Microsoft CIFS over UDP",
        "port": "445",
        "proto": "udp",
        "name": "microsoft-ds-udp"
    },
    "97aeb391-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point VPN-1 Public Key Transfer Protocol",
        "port": "265",
        "proto": "tcp",
        "name": "FW1_key"
    },
    "97aeb392-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point OPSEC Content Vectoring Protocol",
        "port": "18181",
        "proto": "tcp",
        "name": "FW1_cvp"
    },
    "97aeb393-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point OPSEC URL Filtering Protocol",
        "port": "18182",
        "proto": "tcp",
        "name": "FW1_ufp"
    },
    "97aeb394-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point OPSEC Application Monitoring",
        "port": "18193",
        "proto": "tcp",
        "name": "FW1_amon"
    },
    "97aeb395-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point OPSEC Objects Management Interface",
        "port": "18185",
        "proto": "tcp",
        "name": "FW1_omi"
    },
    "97aeb396-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point OPSEC Objects Management Interface with Secure Internal Communication",
        "port": "18186",
        "proto": "tcp",
        "name": "FW1_omi-sic"
    },
    "97aeb397-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Reporting Client Protocol",
        "port": "18205",
        "proto": "tcp",
        "name": "CP_reporting"
    },
    "97aeb398-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Remote Installation Protocol",
        "port": "18208",
        "proto": "tcp",
        "name": "FW1_CPRID"
    },
    "97aeb399-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point User Authority simple protocol",
        "port": "19190",
        "proto": "tcp",
        "name": "FW1_netso"
    },
    "97aeb39a-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point OPSEC User Authority API",
        "port": "19191",
        "proto": "tcp",
        "name": "FW1_uaa"
    },
    "97aeb39b-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Policy Server Logon protocol",
        "port": "18207",
        "proto": "tcp",
        "name": "FW1_pslogon"
    },
    "97aeb39c-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point NG Policy Server Logon protocol",
        "port": "18231",
        "proto": "tcp",
        "name": "FW1_pslogon_NG"
    },
    "97aeb39d-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point SecuRemote Distribution Server Protocol",
        "port": "18232",
        "proto": "tcp",
        "name": "FW1_sds_logon"
    },
    "97aeb39e-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point SecureClient Verification Keepalive Protocol",
        "port": "18233",
        "proto": "udp",
        "name": "FW1_scv_keep_alive"
    },
    "97aeb39f-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point VPN-1 FWZ Key Negotiations - Reliable Datagram Protocol",
        "port": "259",
        "proto": "udp",
        "name": "RDP"
    },
    "4f0e1416-452e-47b5-92f9-4f7e9d844baf": {
        "type": "service",
        "description": "",
        "port": "3389",
        "proto": "udp",
        "name": "Remote_Desktop_Protocol_UDP"
    },
    "97aeb3a0-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point OPSEC Log Export API",
        "port": "18184",
        "proto": "tcp",
        "name": "FW1_lea"
    },
    "97aeb3a1-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point OPSEC Event Logging API",
        "port": "18187",
        "proto": "tcp",
        "name": "FW1_ela"
    },
    "304e5fe4-6235-48b7-a215-be5bccc59bee": {
        "type": "service",
        "description": "Check Point Smartlog remote communication",
        "port": "8211",
        "proto": "tcp",
        "name": "SML_Remote"
    },
    "97aeb3a2-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Real Time Monitoring",
        "port": "18202",
        "proto": "tcp",
        "name": "CP_rtm"
    },
    "97aeb3a3-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point OPSEC Suspicious Activity Monitor API",
        "port": "18183",
        "proto": "tcp",
        "name": "FW1_sam"
    },
    "97aeb3a4-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Internal CA Pull Certificate Service",
        "port": "18210",
        "proto": "tcp",
        "name": "FW1_ica_pull"
    },
    "97aeb3a5-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Internal CA Push Certificate Service",
        "port": "18211",
        "proto": "tcp",
        "name": "FW1_ica_push"
    },
    "97aeb44e-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Internal CA Fetch CRL and User Registration Services",
        "port": "18264",
        "proto": "tcp",
        "name": "FW1_ica_services"
    },
    "97aeb3a6-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point ConnectControl Load Agent",
        "port": "18212",
        "proto": "udp",
        "name": "FW1_load_agent"
    },
    "97aeb3a7-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point End to End Control Protocol",
        "port": "18241",
        "proto": "udp",
        "name": "E2ECP"
    },
    "97aeb3a8-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point tunnel testing application",
        "port": "18234",
        "proto": "udp",
        "name": "tunnel_test"
    },
    "97aeb3a9-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Redundant Management Protocol",
        "port": "18221",
        "proto": "tcp",
        "name": "CP_redundant"
    },
    "97aeb3aa-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Management Interface",
        "port": "18190",
        "proto": "tcp",
        "name": "CPMI"
    },
    "3a55ff42-0dc0-4a53-9ba3-72c230ca85e6": {
        "type": "service",
        "description": "Check Point Management Server",
        "port": "19009",
        "proto": "tcp",
        "name": "CPM"
    },
    "97aeb3ab-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Daemon Protocol",
        "port": "18191",
        "proto": "tcp",
        "name": "CPD"
    },
    "1d91a5ea-6f2c-4921-b402-4e144c1dcbb9": {
        "type": "service",
        "description": "Check Point UserCheck Protocol",
        "port": "18300",
        "proto": "tcp",
        "name": "UserCheck"
    },
    "97aeb3ac-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Internal Application Monitoring",
        "port": "18192",
        "proto": "tcp",
        "name": "CPD_amon"
    },
    "97aeb3ad-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Extranet public key resolution",
        "port": "18262",
        "proto": "tcp",
        "name": "CP_Exnet_PK"
    },
    "97aeb3ae-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Extranet remote objects resolution",
        "port": "18263",
        "proto": "tcp",
        "name": "CP_Exnet_resolve"
    },
    "97aeb3af-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "IPSEC Internet Key Exchange Protocol over TCP",
        "port": "500",
        "proto": "tcp",
        "name": "IKE_tcp"
    },
    "97aeb3b0-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "IPSEC Internet Key Exchange Protocol (formerly ISAKMP/Oakley)",
        "port": "500",
        "proto": "udp",
        "name": "IKE"
    },
    "97aeb3b1-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Security Gateway SNMP Agent",
        "port": "260",
        "proto": "udp",
        "name": "FW1_snmp"
    },
    "d9501263-61ae-4bd6-b33a-87d4d5ccc249": {
        "type": "service",
        "description": "Simple Network Management Protocol",
        "port": "138",
        "proto": "udp",
        "name": "smb-udp"
    },
    "7af4639a-f103-47fe-96f7-b652f7b34ad9": {
        "type": "service",
        "description": "Simple Network Management Protocol",
        "port": "161",
        "proto": "tcp",
        "name": "snmp-tcp"
    },
    "97aeb3b2-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Simple Network Management Protocol",
        "port": "161",
        "proto": "udp",
        "name": "snmp"
    },
    "97aeb3b3-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Simple Network Management Protocol Traps",
        "port": "162",
        "proto": "udp",
        "name": "snmp-trap"
    },
    "97aeb3b4-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Simple Network Management Protocol - Read Only",
        "port": "161",
        "proto": "udp",
        "name": "snmp-read"
    },
    "97aeb3b5-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "X Window System",
        "port": "6000-6063",
        "proto": "tcp",
        "name": "X11"
    },
    "97aeb3b6-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "",
        "port": "2000",
        "proto": "tcp",
        "name": "OpenWindows"
    },
    "97aeb3b8-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Network File System Daemon over UDP (earlier versions of NFS)",
        "port": "2049",
        "proto": "udp",
        "name": "nfsd"
    },
    "97aeb3b9-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Network File System Daemon over TCP",
        "port": "2049",
        "proto": "tcp",
        "name": "nfsd-tcp"
    },
    "97aeb3bd-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Trivial File Transfer Protocol",
        "port": "69",
        "proto": "udp",
        "name": "tftp"
    },
    "bd8b98d4-d2c0-11d5-a329-00d0b7d41431": {
        "type": "service",
        "description": "Session Initiation Protocol",
        "port": "5060",
        "proto": "udp",
        "name": "sip_any"
    },
    "bd8b98d4-d2c0-11d5-a329-00d0b7d4143f": {
        "type": "service",
        "description": "Session Initiation Protocol",
        "port": "5060",
        "proto": "udp",
        "name": "sip"
    },
    "f41b2e8e-d222-417a-8e37-bcaecfca3165": {
        "type": "service",
        "description": "Supported from version R55W, Media Gateway Control Protocol - Media Gateway port",
        "port": "2427",
        "proto": "udp",
        "name": "mgcp_MG"
    },
    "757b4705-84fe-4912-ac56-48fb15ba8782": {
        "type": "service",
        "description": "Supported from version R55W, Media Gateway Control Protocol - Call-Agent port",
        "port": "2727",
        "proto": "udp",
        "name": "mgcp_CA"
    },
    "97aeb3be-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Remote login (rlogin)",
        "port": "513",
        "proto": "tcp",
        "name": "login"
    },
    "97aeb3bf-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Remote execution (rexec)",
        "port": "512",
        "proto": "tcp",
        "name": "exec"
    },
    "97aeb3c0-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Remote shell (rsh)",
        "port": "514",
        "proto": "tcp",
        "name": "shell"
    },
    "cd082d9a-44a6-4cef-a17d-5541029adfb3": {
        "type": "service",
        "description": "Secure Shell, version 1.x block",
        "port": "22",
        "proto": "tcp",
        "name": "ssh_version_2"
    },
    "18ec9eaa-1657-4240-ab97-5f234623336b": {
        "type": "service",
        "description": "secure shell, encrypted and authenticated rsh",
        "port": "22",
        "proto": "tcp",
        "name": "ssh"
    },
    "97aeb3c7-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Open Shortest Path First Interior GW Protocol",
        "proto": "ospf",
        "port": "",
        "name": "ospf"
    },
    "97aeb3c8-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Gateway-to-Gateway protocol",
        "proto": "ggp",
        "port": "",
        "name": "ggp"
    },
    "97aeb3c9-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Cisco Interior Gateway Routing Protocol",
        "proto": "igp",
        "port": "",
        "name": "igrp"
    },
    "97aeb3ca-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Exterior Gateway Protocol, convey net-reachability information between gateways",
        "proto": "egp",
        "port": "",
        "name": "egp"
    },
    "97aeb3cb-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Internet Group Management Protocol",
        "proto": "igmp",
        "port": "",
        "name": "igmp"
    },
    "97aeb3cc-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Virtual Router Redundancy Protocol",
        "proto": "vrrp",
        "port": "",
        "name": "vrrp"
    },
    "0a3667b6-800b-49a9-a655-087cd970ac27": {
        "type": "service",
        "description": "Citrix ICA printing traffic",
        "port": "1494",
        "proto": "tcp",
        "name": "Citrix_ICA_printing"
    },
    "e8c5ab78-f08d-437c-a9b1-be4a8679d766": {
        "type": "service",
        "description": "UDP Service for general Citrix browsing",
        "port": "1604",
        "proto": "udp",
        "name": "Citrix_ICA_Browsing"
    },
    "3a5ad81b-3bfa-4396-97b2-2581b33790b5": {
        "type": "service",
        "description": "used only for log resolving",
        "port": "3386",
        "proto": "udp",
        "name": "GTPv0"
    },
    "0a95feaa-a655-484d-be5e-e6d38a6937a5": {
        "type": "service",
        "description": "used only for log resolving",
        "port": "2123",
        "proto": "udp",
        "name": "GTPv1-C"
    },
    "a1b5db0a-fa8d-4821-b4de-b7a8e9435ef6": {
        "type": "service",
        "description": "used only for log resolving",
        "port": "2152",
        "proto": "udp",
        "name": "GTPv1-U"
    },
    "97aeb3cd-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Routing Information Protocol",
        "port": "520",
        "proto": "udp",
        "name": "rip"
    },
    "986bad5a-94d2-4a8c-81aa-de98d3ecb5c6": {
        "type": "service",
        "description": "Citrix ICA general Service.",
        "port": "1494",
        "proto": "tcp",
        "name": "Citrix_ICA"
    },
    "97aeb3cf-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Telnet Protocol",
        "port": "23",
        "proto": "tcp",
        "name": "telnet"
    },
    "97aeb3d1-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "File Transfer Protocol - PORT mode only",
        "port": "21",
        "proto": "tcp",
        "name": "ftp-port"
    },
    "97aeb3d2-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "File Transfer Protocol - PASV mode only",
        "port": "21",
        "proto": "tcp",
        "name": "ftp-pasv"
    },
    "16a6aaa2-8449-11d6-a9c5-3e5a6fdb3434": {
        "type": "service",
        "description": "File Transfer Protocol with bi-directional data transfer",
        "port": "21",
        "proto": "tcp",
        "name": "ftp-bidir"
    },
    "97aeb3d0-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "File Transfer Protocol",
        "port": "21",
        "proto": "tcp",
        "name": "ftp"
    },
    "97aeb3d3-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Unix-to-Unix Copy Program",
        "port": "540",
        "proto": "tcp",
        "name": "uucp"
    },
    "97aeb3d4-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Hypertext Transfer Protocol",
        "port": "80",
        "proto": "tcp",
        "name": "http"
    },
    "97aeb3d5-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "The Internet Gopher Protocol",
        "port": "70",
        "proto": "tcp",
        "name": "gopher"
    },
    "97aeb3d6-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Archie Internet Protocol, search for files over FTP servers",
        "port": "1525",
        "proto": "udp",
        "name": "archie"
    },
    "97aeb3d7-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Wide Area Information Servers",
        "port": "210",
        "proto": "tcp",
        "name": "wais"
    },
    "97aeb3d9-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Simple Mail Transfer Protocol",
        "port": "25",
        "proto": "tcp",
        "name": "smtp"
    },
    "83c410f3-82c6-4882-bc41-bf89b7849092": {
        "type": "service",
        "description": "Simple Mail Transfer Protocol",
        "port": "1520-1530",
        "proto": "tcp",
        "name": "tns"
    },
    "97aeb3da-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Post Office Protocol - Version 2",
        "port": "109",
        "proto": "tcp",
        "name": "pop-2"
    },
    "97aeb3db-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Post Office Protocol - Version 3",
        "port": "110",
        "proto": "tcp",
        "name": "pop-3"
    },
    "97aeb3dc-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Network News Transfer Protocol",
        "port": "119",
        "proto": "tcp",
        "name": "nntp"
    },
    "97aeb3df-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "UNIX who Protocol, who is on the system",
        "port": "513",
        "proto": "udp",
        "name": "who"
    },
    "97aeb3e0-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "UNIX syslog Protocol, control system log",
        "port": "514",
        "proto": "udp",
        "name": "syslog"
    },
    "97aeb3e1-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "UNIX netstat Protocol, show network status",
        "port": "15",
        "proto": "tcp",
        "name": "netstat"
    },
    "97aeb3e2-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "UNIX, Finger Protocol",
        "port": "79",
        "proto": "tcp",
        "name": "finger"
    },
    "2a8173a0-5f34-4997-881d-d6cd9fc9cbdb": {
        "type": "service",
        "description": "",
        "port": "5061",
        "proto": "tcp",
        "name": "sip_tls_authentication"
    },
    "36803f2e-3cf3-417b-b5b5-9a2fbba06f73": {
        "type": "service",
        "description": "",
        "port": "5061",
        "proto": "tcp",
        "name": "sip_tls_not_inspected"
    },
    "97aeb3e5-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Host Name Server",
        "port": "42",
        "proto": "udp",
        "name": "name"
    },
    "97aeb3e6-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "UNIX biff Protocol, give notice of incoming mail messages",
        "port": "512",
        "proto": "udp",
        "name": "biff"
    },
    "97aeb3e8-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Identify RCS keyword strings in files",
        "port": "113",
        "proto": "tcp",
        "name": "ident"
    },
    "97aeb3e9-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Defender Authentication service",
        "port": "2626",
        "proto": "tcp",
        "name": "AP-Defender"
    },
    "97aeb3ea-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Defender Authentication service",
        "port": "2626",
        "proto": "tcp",
        "name": "AT-Defender"
    },
    "97aeb3eb-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Bootstrap Protocol Server, users automatically configured ",
        "port": "67",
        "proto": "udp",
        "name": "bootp"
    },
    "7d452f42-ce34-442f-a023-fbc755ddf3d4": {
        "type": "service",
        "description": "Layer 2 Tunneling Protocol",
        "port": "1701",
        "proto": "udp",
        "name": "L2TP"
    },
    "22725520-8e10-4a91-98ac-dcd1f6c4a4dd": {
        "type": "service",
        "description": "DHCP request from enforcement module only",
        "port": "67",
        "proto": "udp",
        "name": "dhcp-req-localmodule"
    },
    "fca646b5-ef34-4df1-895d-7639e181501a": {
        "type": "service",
        "description": "DHCP reply to enforcement module only",
        "port": "68",
        "proto": "udp",
        "name": "dhcp-rep-localmodule"
    },
    "97aeb3ec-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Token based Authentication service (UDP)",
        "port": "5500",
        "proto": "udp",
        "name": "securid-udp"
    },
    "97aeb3ed-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Token based Authentication service (TCP)",
        "port": "5510",
        "proto": "tcp",
        "name": "securidprop"
    },
    "97aeb3ee-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Oracle SQL*Net Version 1",
        "port": "1521",
        "proto": "tcp",
        "name": "sqlnet1"
    },
    "97aeb3ef-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "part of Oracle SQL*Net Version 2 Services",
        "port": "1521",
        "proto": "tcp",
        "name": "sqlnet2-1521"
    },
    "97aeb3f0-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "part of Oracle SQL*Net Version 2 Services",
        "port": "1525",
        "proto": "tcp",
        "name": "sqlnet2-1525"
    },
    "97aeb3f1-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "part of Oracle SQL*Net Version 2 Services",
        "port": "1526",
        "proto": "tcp",
        "name": "sqlnet2-1526"
    },
    "13d7904e-334b-4549-8fbd-6b4d6b8b80b2": {
        "type": "servicegroup",
        "description": "group for citrix communication",
        "content": {
            "Citrix_ICA": "986bad5a-94d2-4a8c-81aa-de98d3ecb5c6",
            "Citrix_ICA_Browsing": "e8c5ab78-f08d-437c-a9b1-be4a8679d766"
        },
        "name": "Citrix_metaFrame"
    },
    "97aeb3f2-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Oracle SQL*Net Version 2 Services",
        "content": {
            "sqlnet2-1521": "97aeb3ef-9aea-11d5-bd16-0090272ccb30",
            "sqlnet2-1525": "97aeb3f0-9aea-11d5-bd16-0090272ccb30",
            "sqlnet2-1526": "97aeb3f1-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "sqlnet2"
    },
    "97aeb3f3-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "real-time full-duplex voice communication via the Internet-server",
        "port": "21300",
        "proto": "udp",
        "name": "FreeTel-outgoing-server"
    },
    "97aeb3f5-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "FreeTel Outgoing Connections",
        "content": {
            "FreeTel-outgoing-server": "97aeb3f3-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "FreeTel-outgoing"
    },
    "97aeb3f7-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Echo Protocol (TCP)",
        "port": "7",
        "proto": "tcp",
        "name": "echo-tcp"
    },
    "97aeb3f8-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Echo Protocol (UDP)",
        "port": "7",
        "proto": "udp",
        "name": "echo-udp"
    },
    "97aeb3f9-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Domain Name System Download",
        "port": "53",
        "proto": "tcp",
        "name": "domain-tcp"
    },
    "97aeb3fa-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Domain Name System Queries",
        "port": "53",
        "proto": "udp",
        "name": "domain-udp"
    },
    "8d807250-57eb-4051-9aec-e6128260261b": {
        "type": "service",
        "description": "Kerberos authentication protocol (version 5)",
        "port": "88",
        "proto": "tcp",
        "name": "Kerberos_v5_TCP"
    },
    "8c137030-a995-4e96-aaae-5f5bc74e7b4e": {
        "type": "service",
        "description": "Kerberos authentication protocol (version 5)",
        "port": "88",
        "proto": "udp",
        "name": "Kerberos_v5_UDP"
    },
    "97aeb3fc-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "secure method for authenticating a request for service",
        "port": "750",
        "proto": "udp",
        "name": "kerberos-udp"
    },
    "97aeb3fd-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Discard Server Protocol (TCP)",
        "port": "9",
        "proto": "tcp",
        "name": "discard-tcp"
    },
    "97aeb3fe-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Discard Server Protocol (UDP)",
        "port": "9",
        "proto": "udp",
        "name": "discard-udp"
    },
    "97aeb3ff-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Time Server Protocol (TCP)",
        "port": "37",
        "proto": "tcp",
        "name": "time-tcp"
    },
    "97aeb400-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Time Server Protocol (UDP)",
        "port": "37",
        "proto": "udp",
        "name": "time-udp"
    },
    "97aeb401-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Daytime Server Protocol (TCP)",
        "port": "13",
        "proto": "tcp",
        "name": "daytime-tcp"
    },
    "97aeb402-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Daytime Server Protocol (UDP)",
        "port": "13",
        "proto": "udp",
        "name": "daytime-udp"
    },
    "97aeb403-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Network Time Protocol (TCP)",
        "port": "123",
        "proto": "tcp",
        "name": "ntp-tcp"
    },
    "97aeb404-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Network Time Protocol (UDP)",
        "port": "123",
        "proto": "udp",
        "name": "ntp-udp"
    },
    "97aeb405-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Internet Control Message Protocol",
        "proto": "icmp",
        "port": "",
        "name": "icmp-proto"
    },
    "97aeb414-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "NetBios Name Service",
        "port": "137",
        "proto": "udp",
        "name": "nbname"
    },
    "97aeb415-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "NetBios Datagram Service",
        "port": "138",
        "proto": "udp",
        "name": "nbdatagram"
    },
    "97aeb417-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Internet Relay Chat Protocol",
        "port": "6660-6670",
        "proto": "tcp",
        "name": "irc1"
    },
    "97aeb418-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Internet Relay Chat Protocol",
        "port": "7000",
        "proto": "tcp",
        "name": "irc2"
    },
    "97aeb419-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Lotus iNotes Web Access Protocol",
        "port": "1352",
        "proto": "tcp",
        "name": "lotus"
    },
    "97aeb41a-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Vocaltec Internet Phone",
        "port": "22555",
        "proto": "udp",
        "name": "interphone"
    },
    "97aeb41b-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "RealNetworks PNA Protocol",
        "port": "7070",
        "proto": "tcp",
        "name": "Real-Audio"
    },
    "97aeb41c-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Real Time Streaming Protocol",
        "port": "554",
        "proto": "tcp",
        "name": "rtsp"
    },
    "69815f35-2a03-4121-8335-23a337dce927": {
        "type": "service",
        "description": "SSL version 3 and higher",
        "port": "443",
        "proto": "tcp",
        "name": "ssl_v3"
    },
    "97aeb41d-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Remote Authentication Dial-In User Service",
        "port": "1645",
        "proto": "udp",
        "name": "RADIUS"
    },
    "3af666e6-d36d-491d-9976-26369baaf84b": {
        "type": "service",
        "description": "Remote Authentication Dial-In User Service accounting",
        "port": "1646",
        "proto": "udp",
        "name": "RADIUS-ACCOUNTING"
    },
    "97aeb41e-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "NEW - Remote Authentication Dial-In User Service",
        "port": "1812",
        "proto": "udp",
        "name": "NEW-RADIUS"
    },
    "d5973930-ef57-43d7-9348-9310224eb9f5": {
        "type": "service",
        "description": "NEW - Remote Authentication Dial-In User Service accounting",
        "port": "1813",
        "proto": "udp",
        "name": "NEW-RADIUS-ACCOUNTING"
    },
    "97aeb41f-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Terminal Access Controller Access Control System over UDP",
        "port": "49",
        "proto": "udp",
        "name": "TACACS"
    },
    "97aeb420-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Terminal Access Controller Access Control System over TCP",
        "port": "49",
        "proto": "tcp",
        "name": "TACACSplus"
    },
    "97aeb421-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "IPSEC Simple Key Management for Internet Protocols",
        "proto": "skip",
        "port": "",
        "name": "SKIP"
    },
    "97aeb422-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "IPSEC Authentication Header Protocol",
        "proto": "ah",
        "port": "",
        "name": "AH"
    },
    "97aeb423-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "IPSEC Encapsulating Security Payload Protocol",
        "proto": "esp",
        "port": "",
        "name": "ESP"
    },
    "840666af-ce3d-47b4-923a-7e32e642033d": {
        "type": "service",
        "description": "IPv6 encapsulated in IPv4",
        "proto": "ipv6",
        "port": "",
        "name": "SIT"
    },
    "97aeb424-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "",
        "proto": "gre",
        "port": "",
        "name": "gre"
    },
    "97aeb425-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Point-to-Point Tunneling Protocol, extension of PPP",
        "port": "1723",
        "proto": "tcp",
        "name": "pptp-tcp"
    },
    "97aeb426-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Point-to-Point Tunneling group, (pptp & gre)",
        "content": {
            "pptp-tcp": "97aeb425-9aea-11d5-bd16-0090272ccb30",
            "gre": "97aeb424-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "PPTP"
    },
    "97aeb427-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "videoconference transmissions over IP networks",
        "port": "1720",
        "proto": "tcp",
        "name": "H323"
    },
    "97aeb427-9aea-11d5-bd16-0090272ccb33": {
        "type": "service",
        "description": "videoconference transmissions over IP networks",
        "port": "1720",
        "proto": "tcp",
        "name": "H323_any"
    },
    "97aeb378-9aea-11d5-bd16-0090272ccb32": {
        "type": "service",
        "description": "RAS and associated connections (H.323 protocols)",
        "port": "1719",
        "proto": "udp",
        "name": "H323_ras"
    },
    "97aeb432-9aea-11d5-bd16-0090272ccb31": {
        "type": "service",
        "description": "Endpoint to Gatekeeper and Gatekeeper to Gatekeeper communication",
        "port": "1719",
        "proto": "udp",
        "name": "H323_ras_only"
    },
    "97aeb428-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "H323, Application sharing protocol",
        "port": "1503",
        "proto": "tcp",
        "name": "T.120"
    },
    "97aeb429-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Novell NetWare Core Protocol",
        "port": "524",
        "proto": "tcp",
        "name": "NCP"
    },
    "97aeb42a-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "IONA Orbix Daemon (IIOP) Port 1570",
        "port": "1570",
        "proto": "tcp",
        "name": "Orbix-1570"
    },
    "97aeb42b-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "IONA Orbix Daemon (IIOP) Port 1571",
        "port": "1571",
        "proto": "tcp",
        "name": "Orbix-1571"
    },
    "97aeb42c-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "IONA Orbix Daemon (IIOP)",
        "content": {
            "Orbix-1570": "97aeb42a-9aea-11d5-bd16-0090272ccb30",
            "Orbix-1571": "97aeb42b-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "Orbix"
    },
    "97aeb42d-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Oracle Application Server (IIOP) NameServer",
        "port": "2649",
        "proto": "tcp",
        "name": "OAS-NameServer"
    },
    "97aeb42e-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Oracle Application Server (IIOP) ORB",
        "port": "2651",
        "proto": "tcp",
        "name": "OAS-ORB"
    },
    "97aeb42f-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Oracle Application Server (IIOP)",
        "content": {
            "OAS-NameServer": "97aeb42d-9aea-11d5-bd16-0090272ccb30",
            "OAS-ORB": "97aeb42e-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "OAS"
    },
    "97aeb430-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Sitara Networks Protocol (SpeedSeeker)",
        "proto": "snp",
        "port": "",
        "name": "Sitara"
    },
    "97aeb433-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Lightweight Directory Access Protocol",
        "port": "389",
        "proto": "tcp",
        "name": "ldap"
    },
    "97aeb434-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Lightweight Directory Access Protocol over TLS/SSL",
        "port": "636",
        "proto": "tcp",
        "name": "ldap-ssl"
    },
    "97aeb435-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Entrust CA Administration Service",
        "port": "710",
        "proto": "tcp",
        "name": "Entrust-Admin"
    },
    "97aeb436-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Entrust CA Key Management Service",
        "port": "709",
        "proto": "tcp",
        "name": "Entrust-KeyMgmt"
    },
    "97aeb437-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point Meta IP UAM Client-Server Communication",
        "port": "5004",
        "proto": "udp",
        "name": "MetaIP-UAT"
    },
    "b9bbeeba-b639-41a3-97d5-1f9d982d7e44": {
        "type": "service",
        "description": "RainWall high availability daemon",
        "port": "6374",
        "proto": "tcp",
        "name": "RainWall_Command"
    },
    "21cc3f85-e6df-443d-9846-bd39bd015b85": {
        "type": "service",
        "description": "RainWall daemons communication",
        "port": "6372",
        "proto": "udp",
        "name": "RainWall_Daemon"
    },
    "4fbd29c5-06db-4912-b23d-1bd50d693185": {
        "type": "service",
        "description": "RainWall remote management status",
        "port": "6374",
        "proto": "udp",
        "name": "RainWall_Status"
    },
    "5ff8e3f0-f9e7-47c0-a8ce-fabcccdb7755": {
        "type": "service",
        "description": "RainWall monitoring",
        "port": "6373",
        "proto": "udp",
        "name": "RainWall_Stop"
    },
    "97aeb438-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Stonesoft StoneBeat Control",
        "port": "3002",
        "proto": "tcp",
        "name": "StoneBeat-Control"
    },
    "97aeb439-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Stonesoft StoneBeat Daemon Heartbeat",
        "port": "3001",
        "proto": "tcp",
        "name": "StoneBeat-Daemon"
    },
    "97aeb43a-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Stonesoft StoneBeat",
        "content": {
            "StoneBeat-Control": "97aeb438-9aea-11d5-bd16-0090272ccb30",
            "StoneBeat-Daemon": "97aeb439-9aea-11d5-bd16-0090272ccb30",
            "snmp": "97aeb3b2-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "StoneBeat"
    },
    "97aeb43b-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Automatic 'Suspicious Activity Monitoring' activator",
        "port": "2998",
        "proto": "tcp",
        "name": "RealSecure"
    },
    "97aeb43c-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "RealNetworks RealPlayer Services",
        "content": {
            "Real-Audio": "97aeb41b-9aea-11d5-bd16-0090272ccb30",
            "rtsp": "97aeb41c-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "RealPlayer"
    },
    "97aeb43d-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Netmeeting group (H323 & Ldap)",
        "content": {
            "H323": "97aeb427-9aea-11d5-bd16-0090272ccb30",
            "ldap": "97aeb433-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "NetMeeting"
    },
    "97aeb43e-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "PCs remote access security software, data",
        "port": "5631",
        "proto": "tcp",
        "name": "pcANYWHERE-data"
    },
    "97aeb43f-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "PCs remote access security software, status",
        "port": "5632",
        "proto": "udp",
        "name": "pcANYWHERE-stat"
    },
    "97aeb440-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Symantec pcANYWHERE",
        "content": {
            "pcANYWHERE-data": "97aeb43e-9aea-11d5-bd16-0090272ccb30",
            "pcANYWHERE-stat": "97aeb43f-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "pcANYWHERE"
    },
    "97aeb441-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Symantec pcTELECOMMUTE File Synchronization",
        "port": "2299",
        "proto": "tcp",
        "name": "pcTELECOMMUTE-FileSync"
    },
    "97aeb442-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Symantec pcTELECOMMUTE",
        "content": {
            "pcANYWHERE-data": "97aeb43e-9aea-11d5-bd16-0090272ccb30",
            "pcANYWHERE-stat": "97aeb43f-9aea-11d5-bd16-0090272ccb30",
            "pcTELECOMMUTE-FileSync": "97aeb441-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "pcTELECOMMUTE"
    },
    "97aeb443-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "HTTP protocol over TLS/SSL",
        "port": "443",
        "proto": "tcp",
        "name": "https"
    },
    "97aeb446-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Interactive Mail Access Protocol",
        "port": "143",
        "proto": "tcp",
        "name": "imap"
    },
    "97aeb447-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Check Point VPN-1 SecuRemote FWZ Encapsulation Protocol",
        "proto": "nos",
        "port": "",
        "name": "FW1_Encapsulation"
    },
    "97aeb448-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Microsoft NetShow (Windows Media Player)",
        "port": "1755",
        "proto": "tcp",
        "name": "netshow"
    },
    "97aeb44a-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "Allows servers to provide applications and data for attached computer workstations (Windows)",
        "port": "1494",
        "proto": "tcp",
        "name": "winframe"
    },
    "97aeb44b-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "person-to-person or group discussions videoconference",
        "port": "7648-7652",
        "proto": "udp",
        "name": "CU-SeeMe"
    },
    "6a40f044-296b-4611-8105-fe83284baf03": {
        "type": "service",
        "description": "VPN-1 embedded / SofaWare Management Server (SMS)",
        "port": "9282",
        "proto": "udp",
        "name": "SWTP_SMS"
    },
    "1649fc50-b2b3-4a95-9839-802da7108629": {
        "type": "service",
        "description": "VPN-1 Embedded/SofaWare commands",
        "port": "9281",
        "proto": "udp",
        "name": "SWTP_Gateway"
    },
    "97aeb44c-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "The Server listening port",
        "port": "453",
        "proto": "tcp",
        "name": "CreativePartnerSrvr"
    },
    "97aeb44d-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "The Client listening port",
        "port": "455",
        "proto": "tcp",
        "name": "CreativePartnerClnt"
    },
    "97aeb44f-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "AOL Instant Messenger. Also used by: ICQ & Apple iChat",
        "port": "5190",
        "proto": "tcp",
        "name": "AOL"
    },
    "4273f04d-1b91-4183-bfc6-ca7c7402ccbb": {
        "type": "service",
        "description": "SSL protocol over POP3S",
        "port": "995",
        "proto": "tcp",
        "name": "POP3S"
    },
    "17e435d4-840f-410c-9857-edfb22c8d9ee": {
        "type": "service",
        "description": "SSL protocol over SMTPS",
        "port": "465",
        "proto": "tcp",
        "name": "SMTPS"
    },
    "188fd31d-b7ce-411e-93d5-fcc2d01705ae": {
        "type": "service",
        "description": "VPN-1 UTM Edge Portal",
        "port": "981",
        "proto": "tcp",
        "name": "EDGE"
    },
    "97aeb451-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "",
        "port": "16384",
        "proto": "tcp",
        "name": "ConnectedOnLine"
    },
    "97aeb467-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Secure ID group",
        "content": {
            "securid-udp": "97aeb3ec-9aea-11d5-bd16-0090272ccb30",
            "securidprop": "97aeb3ed-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "securid"
    },
    "97aeb468-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Authenticated group",
        "content": {
            "telnet": "97aeb3cf-9aea-11d5-bd16-0090272ccb30",
            "ftp": "97aeb3d0-9aea-11d5-bd16-0090272ccb30",
            "http": "97aeb3d4-9aea-11d5-bd16-0090272ccb30",
            "login": "97aeb3be-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "Authenticated"
    },
    "97aeb46a-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Echo Protocol group (TCP/UDP)",
        "content": {
            "echo-tcp": "97aeb3f7-9aea-11d5-bd16-0090272ccb30",
            "echo-udp": "97aeb3f8-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "echo"
    },
    "97aeb46b-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Domain Name System (TCP/UDP)",
        "content": {
            "domain-tcp": "97aeb3f9-9aea-11d5-bd16-0090272ccb30",
            "domain-udp": "97aeb3fa-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "dns"
    },
    "97aeb46c-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Kerberos Protocol group (TCP/UDP)",
        "content": {
            "kerberos-udp": "97aeb3fc-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "kerberos"
    },
    "97aeb46d-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Discard Protocol group (TCP/UDP)",
        "content": {
            "discard-tcp": "97aeb3fd-9aea-11d5-bd16-0090272ccb30",
            "discard-udp": "97aeb3fe-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "discard"
    },
    "97aeb46e-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Time Server Protocol",
        "content": {
            "time-tcp": "97aeb3ff-9aea-11d5-bd16-0090272ccb30",
            "time-udp": "97aeb400-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "time"
    },
    "97aeb46f-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Daytime Protocol group (TCP/UDP)",
        "content": {
            "daytime-tcp": "97aeb401-9aea-11d5-bd16-0090272ccb30",
            "daytime-udp": "97aeb402-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "daytime"
    },
    "97aeb470-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Network Time Protocol group (TCP/UDP)",
        "content": {
            "ntp-tcp": "97aeb403-9aea-11d5-bd16-0090272ccb30",
            "ntp-udp": "97aeb404-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "ntp"
    },
    "97aeb471-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "NetBios Services",
        "content": {
            "nbname": "97aeb414-9aea-11d5-bd16-0090272ccb30",
            "nbdatagram": "97aeb415-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "NBT"
    },
    "97aeb473-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Network File System Services",
        "content": {
            "nfsd": "97aeb3b8-9aea-11d5-bd16-0090272ccb30",
            "nfsd-tcp": "97aeb3b9-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "NFS"
    },
    "97aeb474-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Internet Relay Chat Protocol",
        "content": {
            "irc1": "97aeb417-9aea-11d5-bd16-0090272ccb30",
            "irc2": "97aeb418-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "irc"
    },
    "97aeb475-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "IPSEC Services",
        "content": {
            "AH": "97aeb422-9aea-11d5-bd16-0090272ccb30",
            "ESP": "97aeb423-9aea-11d5-bd16-0090272ccb30",
            "SKIP": "97aeb421-9aea-11d5-bd16-0090272ccb30",
            "IKE": "97aeb3b0-9aea-11d5-bd16-0090272ccb30",
            "VPN1_IPSEC_encapsulation": "97aeb390-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "IPSEC"
    },
    "97aeb476-9aea-11d5-bd16-0090272ccb30": {
        "type": "servicegroup",
        "description": "Entrust CA Services",
        "content": {
            "Entrust-Admin": "97aeb435-9aea-11d5-bd16-0090272ccb30",
            "Entrust-KeyMgmt": "97aeb436-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "Entrust-CA"
    },
    "04eca4d1-e4b7-4ec3-a86f-9bb56765519e": {
        "type": "servicegroup",
        "description": "RainWall high availability",
        "content": {
            "RainWall_Command": "b9bbeeba-b639-41a3-97d5-1f9d982d7e44",
            "RainWall_Daemon": "21cc3f85-e6df-443d-9846-bd39bd015b85",
            "RainWall_Status": "4fbd29c5-06db-4912-b23d-1bd50d693185"
        },
        "name": "RainWall-Control"
    },
    "d8cb6abc-1a8b-4fc0-8be1-3255e51decd1": {
        "type": "service",
        "description": "SecureAgent Authentication service",
        "port": "19194-19195",
        "proto": "udp",
        "name": "CP_SecureAgent-udp"
    },
    "2a469820-b502-434c-9340-a377677a6a60": {
        "type": "servicegroup",
        "description": "Common Internet File System Services",
        "content": {
            "nbname": "97aeb414-9aea-11d5-bd16-0090272ccb30",
            "nbdatagram": "97aeb415-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "CIFS"
    },
    "b61424b4-81e4-11d6-bcec-3e5a6fddcece": {
        "type": "service",
        "description": "SecuRemote Distribution Server Protocol (VC and higher)",
        "port": "65524",
        "proto": "tcp",
        "name": "FW1_sds_logon_NG"
    },
    "dff4f7ba-9a3d-11d6-91c1-3e5a6fdd5151": {
        "type": "service",
        "description": "Microsoft SQL Server",
        "port": "1433",
        "proto": "tcp",
        "name": "MS-SQL-Server"
    },
    "ef245528-9a3d-11d6-9eaa-3e5a6fdd6a6a": {
        "type": "service",
        "description": "Microsoft SQL Monitor",
        "port": "1434",
        "proto": "tcp",
        "name": "MS-SQL-Monitor"
    },
    "d18f244b-0b13-4fb8-aa2f-d966eeffb6b3": {
        "type": "service",
        "description": "MSN Messenger",
        "port": "1863",
        "proto": "tcp",
        "name": "MSNP"
    },
    "bbec6807-808d-49b7-b8dc-54c5a655d392": {
        "type": "service",
        "description": "Mirabilis ICQ versions",
        "port": "4000",
        "proto": "udp",
        "name": "ICQ_locator"
    },
    "0094aac2-a29e-4d04-b86c-f31f63dffae2": {
        "type": "service",
        "description": "Microsoft Network Messenger UDP",
        "port": "1863",
        "proto": "udp",
        "name": "MSN_Messenger_1863_UDP"
    },
    "0ac39b6a-701a-4c33-a88d-9eb0fecf9ef6": {
        "type": "service",
        "description": "Microsoft Network Messenger",
        "port": "5190",
        "proto": "udp",
        "name": "MSN_Messenger_5190"
    },
    "505badad-ae57-4584-9a4c-15987c093a32": {
        "type": "service",
        "description": "Microsoft Network Messenger File Transfer",
        "port": "6891-6900",
        "proto": "tcp",
        "name": "MSN_Messenger_File_Transfer"
    },
    "e3e6d587-3212-4ff4-86a1-d16093689e19": {
        "type": "service",
        "description": "Microsoft Network Messenger Voice communication",
        "port": "6901",
        "proto": "udp",
        "name": "MSN_Messenger_Voice"
    },
    "24cd3a7c-aa2c-43d4-8eb6-ff1f070143ea": {
        "type": "service",
        "description": "Yahoo Messenger messages",
        "port": "5050",
        "proto": "tcp",
        "name": "Yahoo_Messenger_messages"
    },
    "c2639e22-fd63-4520-99f7-a70215b95874": {
        "type": "service",
        "description": "Yahoo Messenger Voice Chat",
        "port": "5000-5001",
        "proto": "tcp",
        "name": "Yahoo_Messenger_Voice_Chat_TCP"
    },
    "c98bb09a-b04f-437c-ad1a-6c8261831b87": {
        "type": "service",
        "description": "Yahoo Messenger Voice Chat",
        "port": "5000-5010",
        "proto": "udp",
        "name": "Yahoo_Messenger_Voice_Chat_UDP"
    },
    "910f509f-8f2a-452d-bc15-e51f8cc1694c": {
        "type": "service",
        "description": "Yahoo Messenger Webcams video",
        "port": "5100",
        "proto": "tcp",
        "name": "Yahoo_Messenger_Webcams"
    },
    "d02080c1-b225-4da0-987b-28b3a551b8c9": {
        "type": "service",
        "description": "Direct Connect P2P application. Used also by other clients",
        "port": "411-412",
        "proto": "tcp",
        "name": "Direct_Connect_TCP"
    },
    "64c3ad3f-69d2-4ec1-b843-5df030c70abf": {
        "type": "service",
        "description": "Direct Connect P2P application. Used also by other clients",
        "port": "411-412",
        "proto": "udp",
        "name": "Direct_Connect_UDP"
    },
    "760d9035-1c76-4c5c-b929-ba1dc6685d6f": {
        "type": "service",
        "description": "eDonkey protocol. Used also by other clients.",
        "port": "4661",
        "proto": "tcp",
        "name": "eDonkey_4661"
    },
    "7115e261-185c-4487-aa18-84f8c275d186": {
        "type": "service",
        "description": "eDonkey protocol. Used also by other clients.",
        "port": "4662",
        "proto": "tcp",
        "name": "eDonkey_4662"
    },
    "b1189907-b9eb-4a21-8b38-1d3e5c6c06d0": {
        "type": "service",
        "description": "Also used by: BearShare, ToadNode, Gnucleus, Xolox, LimeWire",
        "port": "6347",
        "proto": "tcp",
        "name": "GNUtella_rtr_TCP"
    },
    "1b4543a3-579e-4cc7-8f57-4387c37a6815": {
        "type": "service",
        "description": "Also used by: BearShare, ToadNode, Gnucleus, Xolox, LimeWire",
        "port": "6347",
        "proto": "udp",
        "name": "GNUtella_rtr_UDP"
    },
    "cdef1feb-485e-4929-942e-011de8318e56": {
        "type": "service",
        "description": "Also used by: BearShare, ToadNode, Gnucleus, Xolox, LimeWire",
        "port": "6346",
        "proto": "tcp",
        "name": "GNUtella_TCP"
    },
    "8eb18480-2690-4520-ae88-412bf5ce94e3": {
        "type": "service",
        "description": "Also used by: BearShare, ToadNode, Gnucleus, Xolox, LimeWire",
        "port": "6346",
        "proto": "udp",
        "name": "GNUtella_UDP"
    },
    "b45556d9-5e0b-46f4-9c35-ed7d82bec43d": {
        "type": "service",
        "description": "Hotline client connections",
        "port": "5500-5503",
        "proto": "tcp",
        "name": "Hotline_client"
    },
    "d6b64df2-4803-4d79-9794-793d18b277d8": {
        "type": "service",
        "description": "Hotline tracker connections",
        "port": "5499",
        "proto": "udp",
        "name": "Hotline_tracker"
    },
    "3bb26988-e0a5-45d6-8018-d4d4de8b96fa": {
        "type": "service",
        "description": "Napster clients. Also used by: WinMX",
        "port": "6600-6699",
        "proto": "tcp",
        "name": "Napster_Client_6600-6699"
    },
    "741a5b0e-3788-4284-91a1-819e99d9ed96": {
        "type": "service",
        "description": "Napster directory connections",
        "port": "4444",
        "proto": "tcp",
        "name": "Napster_directory_4444"
    },
    "8287d6d8-3b6b-4824-8f2d-18bc570ec9b2": {
        "type": "service",
        "description": "Napster directory connections",
        "port": "5555",
        "proto": "tcp",
        "name": "Napster_directory_5555"
    },
    "1ef8fc95-ff10-414b-af76-c0bcc2cd711e": {
        "type": "service",
        "description": "Napster directory connections",
        "port": "6666",
        "proto": "tcp",
        "name": "Napster_directory_6666"
    },
    "182b1d39-54b6-4e2f-bae8-2d8021d52206": {
        "type": "service",
        "description": "Napster directory connections",
        "port": "7777",
        "proto": "tcp",
        "name": "Napster_directory_7777"
    },
    "be51561e-7876-4c70-9546-0914ae737f6e": {
        "type": "service",
        "description": "Napster directory connections (Primary)",
        "port": "8888",
        "proto": "tcp",
        "name": "Napster_directory_8888_primary"
    },
    "3fd0d58a-9759-4686-b103-d177adfc7193": {
        "type": "service",
        "description": "",
        "port": "8875",
        "proto": "tcp",
        "name": "Napster_redirector"
    },
    "c86f055d-31ad-4430-b12c-1094a86c673c": {
        "type": "service",
        "description": "Uses MANOLITO protocol",
        "port": "41170",
        "proto": "udp",
        "name": "Blubster"
    },
    "2d89310c-5761-4213-bef5-c81bb5677e44": {
        "type": "service",
        "description": "Remote Computer Access & Sharing application, also uses HTTP and HTTPS",
        "port": "8200",
        "proto": "tcp",
        "name": "GoToMyPC"
    },
    "01e9fc32-73df-43d5-9cd4-4f91b6a5c711": {
        "type": "service",
        "description": "This port also used by many trojans and the upnp service",
        "port": "5000",
        "proto": "tcp",
        "name": "iMesh"
    },
    "11da2773-a070-4f68-a3c2-9ce5dc158683": {
        "type": "service",
        "description": "",
        "port": "18301",
        "proto": "tcp",
        "name": "CheckPointExchangeAgent"
    },
    "be146201-61b2-11d6-b5e0-0002b316d24e": {
        "type": "service",
        "description": "FastTrack (KaZaA/Morpheus) P2P Protocol",
        "port": "1214",
        "proto": "tcp",
        "name": "KaZaA"
    },
    "b863ec35-604f-4da1-8e63-82a7903d2c1c": {
        "type": "service",
        "description": "Formerly called Aimster",
        "port": "5025",
        "proto": "tcp",
        "name": "Madster"
    },
    "b236d830-9615-4578-b6e2-b0b44c45fda0": {
        "type": "service",
        "description": "RAT trojan (Remote Administration Tool)",
        "port": "1097-1098",
        "proto": "tcp",
        "name": "RAT"
    },
    "e38e4dea-a610-4416-bf44-6f4e45e95e70": {
        "type": "service",
        "description": "Multidropper trojan",
        "port": "1035",
        "proto": "tcp",
        "name": "Multidropper"
    },
    "10f56849-2e03-40dd-9cf7-56aee2cfa57f": {
        "type": "service",
        "description": "Kaos trojan",
        "port": "1212",
        "proto": "tcp",
        "name": "Kaos"
    },
    "e0c17142-433d-40a7-9eaa-e1d5eba40d2e": {
        "type": "service",
        "description": "Also used by: Backdoor trojan",
        "port": "4000",
        "proto": "tcp",
        "name": "SkyDance-T"
    },
    "8055b0de-dace-4d18-91f4-f39915b7aba8": {
        "type": "service",
        "description": "Also used by: Direct Connection,Connecter,Insane Network trojans",
        "port": "1000",
        "proto": "tcp",
        "name": "DerSphere"
    },
    "08da33ff-bc5f-402a-9865-bee8fee69422": {
        "type": "service",
        "description": "Also used by: Freak88,NetSnooper Gold trojans",
        "port": "7001",
        "proto": "tcp",
        "name": "Freak2k"
    },
    "c2f963b0-db3c-42d5-b0f2-a2a7bc0d378d": {
        "type": "service",
        "description": "Also used by: Latinus,NetSpy,RAT trojans and  K Display Manager",
        "port": "1024",
        "proto": "tcp",
        "name": "Jade"
    },
    "81b90130-2a31-45cd-8092-dc492b116ca9": {
        "type": "service",
        "description": "GateCrasher trojan",
        "port": "6970",
        "proto": "tcp",
        "name": "GateCrasher"
    },
    "ce29b597-76b9-48aa-ac24-ae7e23c438ed": {
        "type": "service",
        "description": "Kuang2 trojan",
        "port": "17300",
        "proto": "tcp",
        "name": "Kuang2"
    },
    "25ac306e-1fc9-4e3e-bf66-4a48473caf3f": {
        "type": "service",
        "description": "WinHole trojan",
        "port": "1081",
        "proto": "tcp",
        "name": "WinHole"
    },
    "637b7f26-c4b2-4510-872e-5a10de046cb4": {
        "type": "service",
        "description": "RexxRave trojan",
        "port": "1104",
        "proto": "udp",
        "name": "RexxRave"
    },
    "06233377-3454-489a-b9fb-2f2ca14b895b": {
        "type": "service",
        "description": "",
        "port": "1027",
        "proto": "tcp",
        "name": "ICKiller"
    },
    "82ba0dd2-42e6-472d-8877-57f519175c14": {
        "type": "service",
        "description": "",
        "port": "31785",
        "proto": "tcp",
        "name": "HackaTack_31785"
    },
    "c693c8c1-78e3-450d-936e-aa3278190633": {
        "type": "service",
        "description": "HackaTack trojan",
        "port": "31787",
        "proto": "tcp",
        "name": "HackaTack_31787"
    },
    "b8d159dc-aa70-4cc5-9c5a-8c2ad3aa977e": {
        "type": "service",
        "description": "HackaTack trojan",
        "port": "31788",
        "proto": "tcp",
        "name": "HackaTack_31788"
    },
    "ff8ea038-34fd-4b7b-8a8a-8d6bf0a599fe": {
        "type": "service",
        "description": "HackaTack trojan",
        "port": "31789",
        "proto": "udp",
        "name": "HackaTack_31789"
    },
    "26339b33-1c42-4e49-96e9-55770f6af0ce": {
        "type": "service",
        "description": "HackaTack trojan",
        "port": "31792",
        "proto": "tcp",
        "name": "HackaTack_31792"
    },
    "6e745536-b8c9-4df5-bfd5-043e62013956": {
        "type": "service",
        "description": "Also used by: SubSeven Java client",
        "port": "1234",
        "proto": "tcp",
        "name": "UltorsTrojan"
    },
    "aa02e546-80d1-453a-91dc-49f606764451": {
        "type": "service",
        "description": "NoBackO trojan",
        "port": "1201",
        "proto": "udp",
        "name": "NoBackO"
    },
    "230b24df-1efa-4a28-b7a4-87dfb79afba7": {
        "type": "service",
        "description": "Also used by: ICQ Nuke 98 trojan",
        "port": "1029",
        "proto": "tcp",
        "name": "InCommand"
    },
    "24de2cde-dfcd-4c9b-9124-492ac4bedba7": {
        "type": "service",
        "description": "Xanadu trojan",
        "port": "1031",
        "proto": "tcp",
        "name": "Xanadu"
    },
    "e926e948-fae7-4140-8fed-11426b1a32b9": {
        "type": "service",
        "description": "Also used by:Bad Blood,EGO,Lion,Ramen,Seeker,The Saint,Tftloader,Webhead trojans",
        "port": "27374",
        "proto": "tcp",
        "name": "SubSeven"
    },
    "2176f91c-5fb4-4111-98bd-7d5d5b358fe0": {
        "type": "service",
        "description": "HackaTack trojan",
        "port": "31790",
        "proto": "tcp",
        "name": "HackaTack_31790"
    },
    "cc1d78cc-5fce-4496-a78b-c37aa0622f7a": {
        "type": "service",
        "description": "Terror trojan",
        "port": "3456",
        "proto": "tcp",
        "name": "Terrortrojan"
    },
    "88aaa643-bf12-4d40-a02d-e98a8159358a": {
        "type": "service",
        "description": "CrackDown trojan",
        "port": "4444",
        "proto": "tcp",
        "name": "CrackDown"
    },
    "73bfbf75-eb13-42c0-ba69-58b8f026b4d6": {
        "type": "service",
        "description": "Also used by: Ramen trojan and printer service.",
        "port": "515",
        "proto": "tcp",
        "name": "lpdw0rm"
    },
    "02f708dd-0337-485f-a04b-3b931971b93a": {
        "type": "service",
        "description": "TheFlu trojan",
        "port": "5534",
        "proto": "tcp",
        "name": "TheFlu"
    },
    "41c4df08-dbf9-4576-9114-b8f1dc4dc8d7": {
        "type": "service",
        "description": "Shadyshell trojan",
        "port": "1337",
        "proto": "tcp",
        "name": "Shadyshell"
    },
    "16aee006-0f79-407e-b6a4-f3cc5a7a31d5": {
        "type": "service",
        "description": "TransScout trojan",
        "port": "2004-2005",
        "proto": "tcp",
        "name": "TransScout"
    },
    "3cf4da8b-576e-47ec-903e-91f155bd0cd9": {
        "type": "service",
        "description": "Trinoo trojan",
        "port": "1524",
        "proto": "tcp",
        "name": "Trinoo"
    },
    "69ca7583-1fd4-4c86-ac1a-680697a9af93": {
        "type": "service",
        "description": "Also used by the: tcpmux service",
        "port": "1",
        "proto": "tcp",
        "name": "SocketsdesTroie"
    },
    "d4b1f3b0-c606-4b6b-8118-ee61303f8e19": {
        "type": "service",
        "description": "Also used by: Fraggle Rock,NetSpy,md5 Backdoor trojans",
        "port": "1025",
        "proto": "tcp",
        "name": "Remote_Storm"
    },
    "a651f18c-1c7c-4bd2-9ffe-790c29e3ccd9": {
        "type": "service",
        "description": "Also used by: Tiles and Backdoor_g trojans",
        "port": "1243",
        "proto": "tcp",
        "name": "SubSeven-G"
    },
    "86077a7d-a8da-4b5b-919c-366fe91ad1da": {
        "type": "service",
        "description": "Also used by: Blazer5 , Bubbel and Back-door trojans",
        "port": "5000",
        "proto": "tcp",
        "name": "Bionet-Setup"
    },
    "c13e3031-02d6-4341-a307-3daf10735078": {
        "type": "service",
        "description": "DaCryptic trojan",
        "port": "1074",
        "proto": "tcp",
        "name": "DaCryptic"
    },
    "05647a8c-f0e7-4354-adbd-c685ee7742f0": {
        "type": "service",
        "description": "HackaTack trojan",
        "port": "31791",
        "proto": "udp",
        "name": "HackaTack_31791"
    },
    "e43b7817-dbb6-4c74-a95a-c424dc47999c": {
        "type": "service",
        "description": "Mneah trojan",
        "port": "4666",
        "proto": "tcp",
        "name": "Mneah"
    },
    "aeaa6c77-e87e-4581-ad73-06417391dfad": {
        "type": "service",
        "description": "Used by: Dark FTP,EGO,Maniac rootkit,Moses,ScheduleAgent,SubSeven,Trinity,The thing,Kaitex,WinSatan trojans.",
        "port": "6667",
        "proto": "tcp",
        "name": "Port_6667_trojans"
    },
    "8d971c42-17de-49a0-a646-a8e0057aebbd": {
        "type": "service",
        "description": "Also used by:Insane Network,Last 2000,Remote Explorer 2000,Senna Spy Trojan Generator trojans",
        "port": "2000",
        "proto": "tcp",
        "name": "DerSphere_II"
    },
    "96759a8d-aab8-43d9-bbfc-b459ce66ac87": {
        "type": "service",
        "description": "Backage trojan",
        "port": "411",
        "proto": "tcp",
        "name": "Backage"
    },
    "f956089c-6dd8-4ff4-9fb1-e13969cdadff": {
        "type": "servicegroup",
        "description": "Common ports used by trojan applications.",
        "content": {
            "Bionet-Setup": "86077a7d-a8da-4b5b-919c-366fe91ad1da",
            "Backage": "96759a8d-aab8-43d9-bbfc-b459ce66ac87",
            "SubSeven-G": "a651f18c-1c7c-4bd2-9ffe-790c29e3ccd9",
            "SkyDance-T": "e0c17142-433d-40a7-9eaa-e1d5eba40d2e",
            "CrackDown": "88aaa643-bf12-4d40-a02d-e98a8159358a",
            "DaCryptic": "c13e3031-02d6-4341-a307-3daf10735078",
            "DerSphere": "8055b0de-dace-4d18-91f4-f39915b7aba8",
            "DerSphere_II": "8d971c42-17de-49a0-a646-a8e0057aebbd",
            "Freak2k": "08da33ff-bc5f-402a-9865-bee8fee69422",
            "GateCrasher": "81b90130-2a31-45cd-8092-dc492b116ca9",
            "HackaTack_31785": "82ba0dd2-42e6-472d-8877-57f519175c14",
            "HackaTack_31787": "c693c8c1-78e3-450d-936e-aa3278190633",
            "HackaTack_31788": "b8d159dc-aa70-4cc5-9c5a-8c2ad3aa977e",
            "HackaTack_31789": "ff8ea038-34fd-4b7b-8a8a-8d6bf0a599fe",
            "HackaTack_31790": "2176f91c-5fb4-4111-98bd-7d5d5b358fe0",
            "HackaTack_31791": "05647a8c-f0e7-4354-adbd-c685ee7742f0",
            "HackaTack_31792": "26339b33-1c42-4e49-96e9-55770f6af0ce",
            "ICKiller": "06233377-3454-489a-b9fb-2f2ca14b895b",
            "InCommand": "230b24df-1efa-4a28-b7a4-87dfb79afba7",
            "Jade": "c2f963b0-db3c-42d5-b0f2-a2a7bc0d378d",
            "Kaos": "10f56849-2e03-40dd-9cf7-56aee2cfa57f",
            "Kuang2": "ce29b597-76b9-48aa-ac24-ae7e23c438ed",
            "lpdw0rm": "73bfbf75-eb13-42c0-ba69-58b8f026b4d6",
            "Mneah": "e43b7817-dbb6-4c74-a95a-c424dc47999c",
            "Multidropper": "e38e4dea-a610-4416-bf44-6f4e45e95e70",
            "NoBackO": "aa02e546-80d1-453a-91dc-49f606764451",
            "Port_6667_trojans": "aeaa6c77-e87e-4581-ad73-06417391dfad",
            "RAT": "b236d830-9615-4578-b6e2-b0b44c45fda0",
            "Remote_Storm": "d4b1f3b0-c606-4b6b-8118-ee61303f8e19",
            "RexxRave": "637b7f26-c4b2-4510-872e-5a10de046cb4",
            "Shadyshell": "41c4df08-dbf9-4576-9114-b8f1dc4dc8d7",
            "SocketsdesTroie": "69ca7583-1fd4-4c86-ac1a-680697a9af93",
            "SubSeven": "e926e948-fae7-4140-8fed-11426b1a32b9",
            "Terrortrojan": "cc1d78cc-5fce-4496-a78b-c37aa0622f7a",
            "TheFlu": "02f708dd-0337-485f-a04b-3b931971b93a",
            "TransScout": "16aee006-0f79-407e-b6a4-f3cc5a7a31d5",
            "Trinoo": "3cf4da8b-576e-47ec-903e-91f155bd0cd9",
            "UltorsTrojan": "6e745536-b8c9-4df5-bfd5-043e62013956",
            "WinHole": "25ac306e-1fc9-4e3e-bf66-4a48473caf3f",
            "Xanadu": "24de2cde-dfcd-4c9b-9124-492ac4bedba7"
        },
        "name": "Trojan_Services"
    },
    "b854ab7b-c8c0-448f-9dd5-491212097c3b": {
        "type": "service",
        "description": "Routing Information Protocol for IPv6",
        "port": "521",
        "proto": "udp",
        "name": "RIPng"
    },
    "bfd72cd2-8e5f-4ede-bdb2-6dfc016afccd": {
        "type": "service",
        "description": "Microsoft SQL Server",
        "port": "1433",
        "proto": "udp",
        "name": "MS-SQL-Server_UDP"
    },
    "5ad1a14c-647c-41de-9f84-d1c34f09d63b": {
        "type": "service",
        "description": "",
        "port": "1434",
        "proto": "udp",
        "name": "MS-SQL-Monitor_UDP"
    },
    "f8a15dfe-8c58-407a-ba18-d92ad5b33966": {
        "type": "service",
        "description": "DameWare Mini Remote Control Protocol",
        "port": "6129",
        "proto": "tcp",
        "name": "DameWare"
    },
    "68a602a2-28da-4425-b566-86a537a3bca3": {
        "type": "servicegroup",
        "description": "MS-SQL Server Protocols",
        "content": {
            "MS-SQL-Monitor": "ef245528-9a3d-11d6-9eaa-3e5a6fdd6a6a",
            "MS-SQL-Monitor_UDP": "5ad1a14c-647c-41de-9f84-d1c34f09d63b",
            "MS-SQL-Server": "dff4f7ba-9a3d-11d6-91c1-3e5a6fdd5151",
            "MS-SQL-Server_UDP": "bfd72cd2-8e5f-4ede-bdb2-6dfc016afccd"
        },
        "name": "MS-SQL"
    },
    "6414f98e-6883-44db-8ee2-debd443c7714": {
        "type": "service",
        "description": "Also uses Napster ports",
        "port": "6257",
        "proto": "udp",
        "name": "WinMX"
    },
    "d3caa92a-1032-41ae-a1a1-2274f3ab9f45": {
        "type": "service",
        "description": "eDonkey protocol. Used also by other clients.",
        "port": "4665",
        "proto": "udp",
        "name": "eDonkey_4665"
    },
    "2c970c2b-84a3-40b5-ab0e-83244dd47bcd": {
        "type": "servicegroup",
        "description": "AOL Instant Messenger. Also used by: ICQ & Apple iChat",
        "content": {
            "AOL": "97aeb44f-9aea-11d5-bd16-0090272ccb30",
            "ICQ_locator": "bbec6807-808d-49b7-b8dc-54c5a655d392"
        },
        "name": "AOL_Messenger"
    },
    "5693aca1-316d-410e-a8f3-ba5d2f97e5b7": {
        "type": "servicegroup",
        "description": "MSN Messenger",
        "content": {
            "MSN_Messenger_1863_UDP": "0094aac2-a29e-4d04-b86c-f31f63dffae2",
            "MSN_Messenger_5190": "0ac39b6a-701a-4c33-a88d-9eb0fecf9ef6",
            "MSN_Messenger_File_Transfer": "505badad-ae57-4584-9a4c-15987c093a32",
            "MSN_Messenger_Voice": "e3e6d587-3212-4ff4-86a1-d16093689e19",
            "MSNP": "d18f244b-0b13-4fb8-aa2f-d966eeffb6b3"
        },
        "name": "MSN_Messenger"
    },
    "8e3ed837-81c6-43ef-bada-7c330c57d891": {
        "type": "servicegroup",
        "description": "Yahoo Messenger",
        "content": {
            "Yahoo_Messenger_messages": "24cd3a7c-aa2c-43d4-8eb6-ff1f070143ea",
            "Yahoo_Messenger_Voice_Chat_TCP": "c2639e22-fd63-4520-99f7-a70215b95874",
            "Yahoo_Messenger_Voice_Chat_UDP": "c98bb09a-b04f-437c-ad1a-6c8261831b87",
            "Yahoo_Messenger_Webcams": "910f509f-8f2a-452d-bc15-e51f8cc1694c"
        },
        "name": "Yahoo_Messenger"
    },
    "cd7c1a5f-6268-40b6-a8c7-2727b8036cb1": {
        "type": "servicegroup",
        "description": "",
        "content": {
            "AOL": "97aeb44f-9aea-11d5-bd16-0090272ccb30",
            "ICQ_locator": "bbec6807-808d-49b7-b8dc-54c5a655d392",
            "MSN_Messenger_1863_UDP": "0094aac2-a29e-4d04-b86c-f31f63dffae2",
            "MSN_Messenger_5190": "0ac39b6a-701a-4c33-a88d-9eb0fecf9ef6",
            "MSN_Messenger_File_Transfer": "505badad-ae57-4584-9a4c-15987c093a32",
            "MSN_Messenger_Voice": "e3e6d587-3212-4ff4-86a1-d16093689e19",
            "MSNP": "d18f244b-0b13-4fb8-aa2f-d966eeffb6b3",
            "Yahoo_Messenger_messages": "24cd3a7c-aa2c-43d4-8eb6-ff1f070143ea",
            "Yahoo_Messenger_Voice_Chat_TCP": "c2639e22-fd63-4520-99f7-a70215b95874",
            "Yahoo_Messenger_Voice_Chat_UDP": "c98bb09a-b04f-437c-ad1a-6c8261831b87",
            "Yahoo_Messenger_Webcams": "910f509f-8f2a-452d-bc15-e51f8cc1694c"
        },
        "name": "Messenger_Applications"
    },
    "5cfc76c2-b743-4b68-9fbf-e901eaa3698d": {
        "type": "servicegroup",
        "description": "Direct Connect P2P application. Used also by other clients",
        "content": {
            "Direct_Connect_TCP": "d02080c1-b225-4da0-987b-28b3a551b8c9",
            "Direct_Connect_UDP": "64c3ad3f-69d2-4ec1-b843-5df030c70abf"
        },
        "name": "Direct_Connect"
    },
    "42929fb0-c8dd-465e-be01-3e484f4299f6": {
        "type": "servicegroup",
        "description": "eDonkey protocol. Used also by other clients.",
        "content": {
            "eDonkey_4661": "760d9035-1c76-4c5c-b929-ba1dc6685d6f",
            "eDonkey_4662": "7115e261-185c-4487-aa18-84f8c275d186",
            "eDonkey_4665": "d3caa92a-1032-41ae-a1a1-2274f3ab9f45"
        },
        "name": "eDonkey"
    },
    "f0059b62-e18e-478f-a3bd-18595d53d3e1": {
        "type": "servicegroup",
        "description": "GNUtella P2P protocol (used by: BearShare, ToadNode, Gnucleus, Xolox, LimeWire)",
        "content": {
            "GNUtella_rtr_TCP": "b1189907-b9eb-4a21-8b38-1d3e5c6c06d0",
            "GNUtella_rtr_UDP": "1b4543a3-579e-4cc7-8f57-4387c37a6815",
            "GNUtella_TCP": "cdef1feb-485e-4929-942e-011de8318e56",
            "GNUtella_UDP": "8eb18480-2690-4520-ae88-412bf5ce94e3"
        },
        "name": "GNUtella"
    },
    "4c3e148f-bcc4-4c97-9955-09da850fb9a6": {
        "type": "servicegroup",
        "description": "Hotline P2P protocol",
        "content": {
            "Hotline_client": "b45556d9-5e0b-46f4-9c35-ed7d82bec43d",
            "Hotline_tracker": "d6b64df2-4803-4d79-9794-793d18b277d8"
        },
        "name": "Hotline"
    },
    "77c21ea4-9db4-40fe-86e0-58252c3759d8": {
        "type": "servicegroup",
        "description": "",
        "content": {
            "CPD": "97aeb3ab-9aea-11d5-bd16-0090272ccb30",
            "FW1": "97aeb388-9aea-11d5-bd16-0090272ccb30",
            "FW1_ica_pull": "97aeb3a4-9aea-11d5-bd16-0090272ccb30",
            "FW1_log": "97aeb389-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "DAIP_Control_services"
    },
    "5ee3ca5b-35a2-4988-859c-7157e8cffead": {
        "type": "servicegroup",
        "description": "Napster P2P protocol",
        "content": {
            "Napster_Client_6600-6699": "3bb26988-e0a5-45d6-8018-d4d4de8b96fa",
            "Napster_directory_4444": "741a5b0e-3788-4284-91a1-819e99d9ed96",
            "Napster_directory_5555": "8287d6d8-3b6b-4824-8f2d-18bc570ec9b2",
            "Napster_directory_6666": "1ef8fc95-ff10-414b-af76-c0bcc2cd711e",
            "Napster_directory_7777": "182b1d39-54b6-4e2f-bae8-2d8021d52206",
            "Napster_directory_8888_primary": "be51561e-7876-4c70-9546-0914ae737f6e",
            "Napster_redirector": "3fd0d58a-9759-4686-b103-d177adfc7193"
        },
        "name": "Napster"
    },
    "d138e7da-3bf1-4d7c-ae35-d551416e8db3": {
        "type": "servicegroup",
        "description": "",
        "content": {
            "Blubster": "c86f055d-31ad-4430-b12c-1094a86c673c",
            "Direct_Connect_TCP": "d02080c1-b225-4da0-987b-28b3a551b8c9",
            "Direct_Connect_UDP": "64c3ad3f-69d2-4ec1-b843-5df030c70abf",
            "eDonkey_4661": "760d9035-1c76-4c5c-b929-ba1dc6685d6f",
            "eDonkey_4662": "7115e261-185c-4487-aa18-84f8c275d186",
            "eDonkey_4665": "d3caa92a-1032-41ae-a1a1-2274f3ab9f45",
            "GNUtella_rtr_TCP": "b1189907-b9eb-4a21-8b38-1d3e5c6c06d0",
            "GNUtella_rtr_UDP": "1b4543a3-579e-4cc7-8f57-4387c37a6815",
            "GNUtella_TCP": "cdef1feb-485e-4929-942e-011de8318e56",
            "GNUtella_UDP": "8eb18480-2690-4520-ae88-412bf5ce94e3",
            "GoToMyPC": "2d89310c-5761-4213-bef5-c81bb5677e44",
            "Hotline_client": "b45556d9-5e0b-46f4-9c35-ed7d82bec43d",
            "Hotline_tracker": "d6b64df2-4803-4d79-9794-793d18b277d8",
            "iMesh": "01e9fc32-73df-43d5-9cd4-4f91b6a5c711",
            "KaZaA": "be146201-61b2-11d6-b5e0-0002b316d24e",
            "Madster": "b863ec35-604f-4da1-8e63-82a7903d2c1c",
            "Napster_Client_6600-6699": "3bb26988-e0a5-45d6-8018-d4d4de8b96fa",
            "Napster_directory_4444": "741a5b0e-3788-4284-91a1-819e99d9ed96",
            "Napster_directory_5555": "8287d6d8-3b6b-4824-8f2d-18bc570ec9b2",
            "Napster_directory_6666": "1ef8fc95-ff10-414b-af76-c0bcc2cd711e",
            "Napster_directory_7777": "182b1d39-54b6-4e2f-bae8-2d8021d52206",
            "Napster_directory_8888_primary": "be51561e-7876-4c70-9546-0914ae737f6e",
            "Napster_redirector": "3fd0d58a-9759-4686-b103-d177adfc7193",
            "WinMX": "6414f98e-6883-44db-8ee2-debd443c7714"
        },
        "name": "P2P_File_Sharing_Applications"
    },
    "e5abecc6-38a0-4889-965b-d4955bada825": {
        "type": "service",
        "description": "SIC TCP service",
        "port": "18190-19191",
        "proto": "tcp",
        "name": "SIC-TCP"
    },
    "7e7ce9b0-8631-4ec3-a7ee-6eb084782a66": {
        "type": "service",
        "description": "MS SQL Sapphire /SQL Slammer Worm",
        "port": "1434",
        "proto": "udp",
        "name": "MSSQL_resolver"
    },
    "3afa6a8a-5c36-4ada-9942-125a04cc6846": {
        "type": "service",
        "description": "Wireless Datagram Protocol with Wireless Transport Layer Security",
        "port": "9202",
        "proto": "udp",
        "name": "wap_wdp_enc"
    },
    "62b30b32-b964-4b37-bede-503ba794dcf9": {
        "type": "service",
        "description": "Wireless Transaction Protocol with Wireless Transport Layer Security",
        "port": "9203",
        "proto": "udp",
        "name": "wap_wtp_enc"
    },
    "7641c3c5-e4c3-4827-b918-d2579f116433": {
        "type": "service",
        "description": "Wireless Datagram Protocol: a simplified protocol suitable for low bandwidth mobile stations enables a connectionless mode.",
        "port": "9200",
        "proto": "udp",
        "name": "wap_wdp"
    },
    "61b7c3e3-b730-4a28-9041-c15e7ff15589": {
        "type": "service",
        "description": "Wireless Transaction Protocol: a simplified protocol suitable for low bandwidth mobile stations enables a connection mode.",
        "port": "9201",
        "proto": "udp",
        "name": "wap_wtp"
    },
    "07ec4cae-7c50-4b2e-81ed-d75643ab5694": {
        "type": "service",
        "description": "Nat Traversal Protocol",
        "port": "4500",
        "proto": "udp",
        "name": "IKE_NAT_TRAVERSAL"
    },
    "aa49fc3b-2b4a-4da9-834f-d8f353d7042d": {
        "type": "service",
        "description": "Nat Traversal Protocol",
        "port": "4500",
        "proto": "tcp",
        "name": "IKE_NAT_TRAVERSAL_TCP"
    },
    "8fbc3970-0c34-419a-8724-30141b0f8443": {
        "type": "service",
        "description": "Jabber Protocol",
        "port": "5222",
        "proto": "tcp",
        "name": "jabber"
    },
    "2f98c148-5884-44b2-a587-787361658d76": {
        "type": "service",
        "description": "",
        "proto": "pim",
        "port": "",
        "name": "pim"
    },
    "7527142e-554e-4b1d-9639-6f800764dbcf": {
        "type": "service",
        "description": "Mobility Extension Header for IPv6",
        "proto": "mobility-header",
        "port": "",
        "name": "Mobility_Header"
    },
    "1c012d66-87d9-4bd8-b3d2-d30ac1bf3efc": {
        "type": "service",
        "description": "",
        "port": "1863",
        "proto": "tcp",
        "name": "MSNMS"
    },
    "b11890a6-2700-495a-8c99-914d31714f3a": {
        "type": "service",
        "description": "Session Initiation Protocol over TCP",
        "port": "5060",
        "proto": "tcp",
        "name": "sip-tcp"
    },
    "5aa6d21c-0cc8-4478-b3a3-2206c2da6d66": {
        "type": "service",
        "description": "",
        "port": "5060",
        "proto": "tcp",
        "name": "sip_any-tcp"
    },
    "bf3b16ad-beea-4aa3-94aa-3b3bd7074690": {
        "type": "service",
        "description": "Check Point Eventia Analyzer Server Protocol",
        "port": "18266",
        "proto": "tcp",
        "name": "CP_seam"
    },
    "f5558c46-011d-4d39-859e-1aa26c70c947": {
        "type": "service",
        "description": "Check Point Smart Portal",
        "port": "4433",
        "proto": "tcp",
        "name": "CP_SmartPortal"
    },
    "e5d744ad-e952-4999-a3b9-3d3130c70479": {
        "type": "service",
        "description": "Microsoft RDP",
        "port": "3389",
        "proto": "tcp",
        "name": "Remote_Desktop_Protocol"
    },
    "8cc5a08a-dfe7-4e21-8382-ff61e8fd0861": {
        "type": "service",
        "description": "Modbus is a serial communications protocol that is very popular in connecting industrial electronic devices",
        "port": "502",
        "proto": "tcp",
        "name": "Modbus"
    },
    "d5358ec6-3aec-4c05-b3a0-4c76bb89842b": {
        "type": "service",
        "description": "DNP3 is a set of communications protocols used between components in process automation systems. Its main use is in utilities such as electric and water companies",
        "port": "20000",
        "proto": "tcp",
        "name": "DNP3"
    },
    "36a4cd8a-2fd2-4cfc-8a80-80514b815670": {
        "type": "service",
        "description": "ICCP is used by utility organizations throughout the world to provide data exchange over wide area networks (WANs) between utility control centers, utilities, power pools, regional control centers and Non-Utility Generators",
        "port": "102",
        "proto": "tcp",
        "name": "ICCP"
    },
    "58825345-5787-4f13-ba3b-6a1549f9a010": {
        "type": "service",
        "description": "OPC specifies the communication of real-time plant data between control devices from different manufacturers",
        "port": "3480",
        "proto": "tcp",
        "name": "OPC"
    },
    "88f622d5-2f77-46d8-a946-c0f0ac91d612": {
        "type": "service",
        "description": "Communicate with indeni (www.indeni.com)",
        "port": "8181",
        "proto": "tcp",
        "name": "indeni"
    },
    "ced7ba46-1e36-48ad-b527-521a63e8cb05": {
        "type": "service",
        "description": "LDAP udp service",
        "port": "389",
        "proto": "udp",
        "name": "ldap_udp"
    },
    "1fceea78-d378-44b4-8939-019b68f48518": {
        "type": "service",
        "description": "Border Gateway Protocol",
        "port": "179",
        "proto": "tcp",
        "name": "BGP"
    },
    "1e20ae67-83d5-4d49-96e8-57b83c68d85b": {
        "type": "service",
        "description": "SSL encrypted IMAP",
        "port": "993",
        "proto": "tcp",
        "name": "IMAP-SSL"
    },
    "528c3168-ac1a-407f-ae71-01263a53d52b": {
        "type": "service",
        "description": "Squid NTLM authentication",
        "port": "3128",
        "proto": "tcp",
        "name": "Squid_NTLM"
    },
    "97aeb416-9aea-11d5-bd16-0090272ccb30": {
        "type": "service",
        "description": "NetBios Session Service",
        "port": "139",
        "proto": "tcp",
        "name": "nbsession"
    },
    "cfbcace4-7c6f-11d6-bf0e-3e5a6fe83232": {
        "type": "service",
        "description": "Microsoft CIFS over TCP",
        "port": "445",
        "proto": "tcp",
        "name": "microsoft-ds"
    },
    "82bccbc2-603c-4d96-a59b-9c2b730efb5c": {
        "type": "servicegroup",
        "description": "",
        "content": {
            "http": "97aeb3d4-9aea-11d5-bd16-0090272ccb30",
            "https": "97aeb443-9aea-11d5-bd16-0090272ccb30"
        },
        "name": "Web"
    },
    "2ec3c63b-d3ed-4971-8e8b-5fe449a4ca06": {
        "type": "servicegroup",
        "description": "Common Web Proxy Services",
        "content": {
            "HTTP_proxy": "8eddeaa0-259d-448f-95b6-490a39f55962",
            "HTTPS_proxy": "704fbf04-1714-49a1-a750-38c0e4139a11"
        },
        "name": "Web_Proxy"
    },
    "7f9275f0-4382-4222-b4cd-06d2c5aa3222": {
        "type": "servicegroup",
        "description": "HTTPS default services",
        "content": {
            "https": "97aeb443-9aea-11d5-bd16-0090272ccb30",
            "HTTP_and_HTTPS_proxy": "2a2ca572-fbe7-4e7f-92e4-164f5b4fded1"
        },
        "name": "HTTPS default services"
    }
}