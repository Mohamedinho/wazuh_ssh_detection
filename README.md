# 🛡️ CyberLab SOC — Enterprise Security Monitoring & Hardening

**A practical Red Team ↔ Blue Team security lab** using Kali Linux, Ubuntu Server, VMware Workstation, Docker and **Wazuh 4.14.9**.

![Status](https://img.shields.io/badge/Lab-Completed-2ea44f) ![Focus](https://img.shields.io/badge/Focus-SOC%20%7C%20Security%20Engineering-2563eb) ![Environment](https://img.shields.io/badge/Environment-Local%20%26%20Isolated-475569)

> **Project period:** November 6–16, 2026  
> **Scope:** Authorized experiments in an isolated local laboratory.  
> **Result:** Detection, investigation, custom correlation, manual containment, SSH hardening and temporary automated response were demonstrated.

## Project overview

CyberLab SOC simulates a small enterprise security workflow: an attacker machine generates controlled test traffic against a monitored Linux endpoint; a SIEM ingests the resulting system and firewall logs; an analyst investigates the alerts and implements defensive controls.

The goal is to learn **why an alert fires, what its evidence proves, and how to respond without disrupting legitimate access**. This README documents the actual lab activity, not a general-purpose exploitation framework.

### Validated outcomes

| Mission | Area | Outcome |
|---|---|---|
| 01 | SSH authentication monitoring | Failed logins attributed to their source in Wazuh |
| 02 | Network visibility and UFW | Firewall logs and custom alert rule `100100` |
| 03 | Detection engineering | Custom `cyberlab-ufw` decoder and correlated rule `100101` |
| 04 | SOC investigation and response | Manual isolation of Kali with Windows access maintained; recovery verified |
| 05 | Linux/SSH hardening | Ed25519 key-based access; password-only authentication refused |
| 06 | Wazuh Active Response | `firewall-drop` triggered from rule `100101`; temporary block and connectivity recovery observed |

## Lab topology

```text
Windows host — VMware Workstation + Docker Desktop / WSL2
│
├── VMnet1 (Host-only): 192.168.163.0/24
│   ├── Windows VMnet1 / Wazuh access   192.168.163.1
│   ├── Ubuntu Server / Wazuh Agent    192.168.163.128
│   │   ├── OpenSSH TCP/22
│   │   ├── UFW / iptables
│   │   └── journald
│   └── Kali Linux (Red Team)          192.168.163.129
│
├── VMnet8 (NAT): 192.168.192.0/24
│   └── Ubuntu ens33                  192.168.192.129 (observed)
│
└── Docker Compose: Wazuh 4.14.9
    ├── Wazuh Manager
    ├── Wazuh Indexer
    └── Wazuh Dashboard               https://localhost
```

> IP addresses were assigned by the lab's virtual networks and may change after DHCP/VMware changes. The Wazuh Manager is a Docker service reachable through the Windows host, not an additional VMware VM.

### Technologies

- **Red Team:** Kali Linux, `nmap`, OpenSSH client, `nc`
- **Endpoint:** Ubuntu Server, `sshd`, UFW, iptables, journald, Wazuh Agent `ubuntu-soc-01`
- **Blue Team:** Wazuh Manager + Indexer + Dashboard, Wazuh Logtest, custom decoder/rules, Active Response
- **Infrastructure:** VMware Host-only/NAT, Windows PowerShell, Docker Desktop / WSL2, external HDD storage

---

## Mission 01 — SSH authentication and source attribution

Kali (`192.168.163.129`) tested SSH access to Ubuntu (`192.168.163.128`). A login using the non-existent account `invalid_soc_test` was rejected; Wazuh recorded the source IP and username.

```bash
ssh -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 \
    invalid_soc_test@192.168.163.128
```

Relevant detections included rule **`5710`** (attempted non-existent SSH user) and **`5503`** (PAM failure). These events establish **failed authentication**, not a successful compromise.

### Evidence

![Kali Host-only interface and source IP](SOC%20LAB%20PICS/step1_adresses_ssh_attaque/kali%20ip%20.png)

*Kali Host-only interface and source IP*
![Controlled failed SSH authentication from Kali](SOC%20LAB%20PICS/step1_adresses_ssh_attaque/ssh%20attaque%20kali%20.png)

*Controlled failed SSH authentication from Kali*

---

## Mission 02 — UFW monitoring and first Wazuh rule

We observed that Nmap activity was not initially represented by a dedicated network-scan alert. UFW was configured to deny unsolicited inbound traffic while allowing SSH from the lab subnet; kernel logs recorded `[UFW BLOCK]` entries.

```bash
sudo ufw allow from 192.168.163.0/24 to any port 22 proto tcp comment 'CyberLab SOC SSH'
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw logging medium
sudo ufw enable

# Verify UFW events
sudo journalctl -k --since "5 minutes ago" --no-pager | grep 'UFW BLOCK'
```

First custom rule: **`100100`**, level 5, identifying individual `[UFW BLOCK]` events. Its Wazuh Logtest result and live Threat Hunting alerts were verified.

```xml
<group name="cyberlab_soc,firewall,">
  <rule id="100100" level="5">
    <program_name>^kernel$</program_name>
    <match type="pcre2">\[UFW BLOCK\]</match>
    <description>CyberLab SOC: UFW blocked a connection</description>
  </rule>
</group>
```

### Evidence

![Initial UFW status before hardening](SOC%20LAB%20PICS/step2_UFW_network_visibility/UFW_status_inactive.png)

*Initial UFW status before hardening*
![UFW rules added while preserving SSH access](SOC%20LAB%20PICS/step2_UFW_network_visibility/UFW_config_safty%20.png)

*UFW rules added while preserving SSH access*
![Linux kernel journal showing firewall block events](SOC%20LAB%20PICS/step2_UFW_network_visibility/UFW_journal_list_block.png)

*Linux kernel journal showing firewall block events*
![Rule 100100 events visible in Wazuh Threat Hunting](SOC%20LAB%20PICS/step2_UFW_network_visibility/wazuh_rule_nmap_scan_verified.png)

*Rule 100100 events visible in Wazuh Threat Hunting*

---

## Mission 03 — Custom decoder and repeated-block correlation

The default kernel decoder did not extract all network attributes. We created a dedicated decoder under `/var/ossec/etc/decoders/` for `srcip`, `dstip`, `protocol` and `dstport`.

```xml
<decoder name="cyberlab-ufw">
  <parent>kernel</parent>
  <prematch type="pcre2">\[UFW BLOCK\]</prematch>
  <regex type="pcre2">SRC=(\S+)\s+DST=(\S+).*?PROTO=(\S+).*?DPT=(\d+)</regex>
  <order>srcip,dstip,protocol,dstport</order>
  <use_own_name>true</use_own_name>
</decoder>
```

Custom correlation rule **`100101`** triggers a level-10 alert when repeated `100100` events share the same source IP in a 30-second window.

```xml
<group name="cyberlab_soc,firewall,">
  <rule id="100101" level="10" frequency="5" timeframe="30">
    <if_matched_sid>100100</if_matched_sid>
    <same_srcip />
    <description>CyberLab SOC: Repeated UFW blocks from the same source IP</description>
  </rule>
</group>
```

The rule was tested using multiple events in **one Wazuh Logtest session** and subsequently confirmed using Kali-generated traffic in Threat Hunting. This detects **repetition**, not proof of malicious scanning: retransmissions and authorized scanner activity require contextual investigation.

### Evidence

![Creation of the custom cyberlab-ufw decoder](SOC%20LAB%20PICS/step3_cree_decodeur_structurer%20donner/cree_decodeur.png)

*Creation of the custom cyberlab-ufw decoder*
![Wazuh Logtest structured field extraction](SOC%20LAB%20PICS/step3_cree_decodeur_structurer%20donner/structure_un_log.png)

*Wazuh Logtest structured field extraction*
![Definition of repeated-block correlation rule 100101](SOC%20LAB%20PICS/step3_cree_decodeur_structurer%20donner/cree_rule_100101_bloque_same_ip.png)

*Definition of repeated-block correlation rule 100101*
![Live correlated level-10 alert in Wazuh](SOC%20LAB%20PICS/step3_cree_decodeur_structurer%20donner/ufw_ip_repeated_test_correct.png)

*Live correlated level-10 alert in Wazuh*

---

## Mission 04 — SOC investigation and manual containment

**Case CYBERLAB-INC-003 (November 13):** Wazuh alerted on repeated firewall blocks from Kali (`192.168.163.129`) targeting multiple TCP ports on Ubuntu (`192.168.163.128`). A separate SSH log showed an authorized successful login from **Windows** (`192.168.163.1`), not Kali.

The lab demonstrated safe, targeted containment. Ubuntu's firewall initially allowed TCP/22 from `192.168.163.0/24`, so the Kali-specific DENY rule was inserted before that allowance.

```bash
# Ubuntu — targeted temporary containment
sudo ufw insert 1 deny from 192.168.163.129 to any
sudo ufw status numbered

# Later — manual recovery
sudo ufw delete deny from 192.168.163.129 to any
```

```powershell
# Windows — administrative connectivity must remain available
Test-NetConnection 192.168.163.128 -Port 22
```

```bash
# Kali — expected to time out during containment
nc -vz -w 3 192.168.163.128 22
```

**Observed outcome:** Kali SSH timed out during containment; Windows SSH connectivity remained successful. Kali SSH returned to `open` after removal of the UFW rule. The activity was classified as an **authorized simulation**, without evidence of compromise.

### Evidence

![Incident investigation of UFW blocks and SSH log events](SOC%20LAB%20PICS/step4_incident_responce_steps/log_investigation_ubuntu.png)

*Incident investigation of UFW blocks and SSH log events*
![Targeted UFW rule inserted ahead of the SSH allow rule](SOC%20LAB%20PICS/step4_incident_responce_steps/bloquer_kali_de_reseau_confinement_2.png)

*Targeted UFW rule inserted ahead of the SSH allow rule*
![Kali SSH connection times out under the manual containment rule](SOC%20LAB%20PICS/step4_incident_responce_steps/kali_blocker.png)

*Kali SSH connection times out under the manual containment rule*
![Windows SSH test remains successful during Kali containment](SOC%20LAB%20PICS/step4_incident_responce_steps/win_marche_bien.png)

*Windows SSH test remains successful during Kali containment*

---

## Mission 05 — Linux and SSH hardening

The Ubuntu SSH server initially accepted passwords. We generated a **dedicated Ed25519 SSH key on Windows**, installed its **public key** on Ubuntu and verified a key-based login before disabling password-based SSH access.

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\cyberlab_soc_ed25519" -C "CyberLab-SOC"

Get-Content "$env:USERPROFILE\.ssh\cyberlab_soc_ed25519.pub" |
  ssh mohamed@192.168.163.128 "umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys"

ssh -i "$env:USERPROFILE\.ssh\cyberlab_soc_ed25519" -o IdentitiesOnly=yes mohamed@192.168.163.128
```

The dedicated hardening file `/etc/ssh/sshd_config.d/00-cyberlab-hardening.conf` contains:

```text
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
MaxAuthTries 3
KbdInteractiveAuthentication no
X11Forwarding no
```

```bash
sudo sshd -t
sudo sshd -T | grep -E '^(passwordauthentication|pubkeyauthentication|permitrootlogin|maxauthtries|kbdinteractiveauthentication|x11forwarding) '
sudo systemctl reload ssh
```

**Observed outcome:** A successful `Accepted publickey` event from Windows and `Permission denied (publickey)` for a password-only attempt from Kali. Wazuh continued to ingest SSH authentication activity (including rule `5715`). **The private SSH key is not included in this repository.**

### Evidence

![SSH configuration before hardening](SOC%20LAB%20PICS/step5_linux_ssh_hardening/afficher_params_ssh_ubuntu%20.png)

*SSH configuration before hardening*
![Effective OpenSSH settings after applying the hardening file](SOC%20LAB%20PICS/step5_linux_ssh_hardening/durcir_serveru_ssh.png)

*Effective OpenSSH settings after applying the hardening file*
![Kali password-only SSH attempt rejected](SOC%20LAB%20PICS/step5_linux_ssh_hardening/acceder_par_kali_refuser_utiliser_kle_public.png)

*Kali password-only SSH attempt rejected*
![Wazuh still monitoring SSH authentication after hardening](SOC%20LAB%20PICS/step5_linux_ssh_hardening/survaillance_wazuh_ssh.png)

*Wazuh still monitoring SSH authentication after hardening*

---

## Mission 06 — Wazuh Active Response (automated containment)

**Case CYBERLAB-INC-004 (November 16):** We configured Wazuh to invoke the agent-side `firewall-drop` script when correlation rule **`100101`** fired. This was configured on the Manager, with an intended exclusion for the Windows administration source IP `192.168.163.1`.

```xml
<!-- Manager ossec.conf: relevant excerpt -->
<global>
  <white_list>192.168.163.1</white_list>
</global>

<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100101</rules_id>
  <timeout>60</timeout>
</active-response>
```

The Manager was recreated **without deleting Docker volumes** so the updated configuration was copied from its Docker source into `/var/ossec/etc/ossec.conf`.

```powershell
cd "E:\CyberLab-SOC\wazuh-docker\single-node"
docker compose config --quiet
docker compose up -d --no-deps --force-recreate wazuh.manager
```

```bash
# Kali — controlled scan
nmap -sT -Pn --max-retries 0 -p 80,443,8080,8081,8082,8083,8084,8085 192.168.163.128

# Kali — test reachability
nc -vz -w 3 192.168.163.128 22

# Ubuntu — investigate response and firewall state
sudo tail -n 30 /var/ossec/logs/active-responses.log
sudo iptables -L INPUT -n --line-numbers | grep 192.168.163.129
```

**Observed outcome:** `active-responses.log` showed `firewall-drop` receiving an **`add`** command with `srcip=192.168.163.129` and `rule.id=100101`. Kali's SSH test timed out and later returned `open`. An inspection of the INPUT chain no longer showed the Kali IP after recovery. The **configured** timeout was 60 seconds; exact elapsed rollback time was not separately measured. A distinct `delete` log line was not captured. **The separate SSH-recovery screenshot shown during the lab was not included in this ZIP**, so it is not presented here as an attached image.

### Evidence

> The supplied Active Response folder contains three screenshots. The final standalone Kali `22 (ssh) open` recovery screenshot can be added later to strengthen the public evidence.

![Wazuh dashboard alert related to blocked traffic and Active Response](SOC%20LAB%20PICS/step6_Wazuh%20Active%20Response/active_scan_blocked.png)

*Wazuh dashboard alert related to blocked traffic and Active Response*
![Ubuntu Active Response log: firewall-drop and rule 100101](SOC%20LAB%20PICS/step6_Wazuh%20Active%20Response/active_response_wazuh.png)

*Ubuntu Active Response log: firewall-drop and rule 100101*
![Kali Nmap results followed by timed-out SSH connectivity during Active Response](SOC%20LAB%20PICS/step6_Wazuh%20Active%20Response/auto_bloc_nmap_scan.png)

*Kali Nmap results followed by timed-out SSH connectivity during Active Response*

---

## Security analysis and limitations

| Observation | Interpretation |
|---|---|
| `100100` fired | A UFW block was observed |
| `100101` fired | Repeated blocks shared a source IP; not necessarily a malicious scan |
| SSH authentication refused | A password-only attempt was denied after hardening |
| Active Response `add` event | Wazuh invoked a response targeting the observed source IP |
| Kali connectivity later returned | Consistent with temporary response rollback; exact rollback time not measured |
| No demonstrated compromise | This was authorized and simulated, not evidence of an intruder succeeding |

**Operational note:** Automatically banning sources can create false positives and block legitimate traffic. Apply this type of response only with a tested exclusion policy and recovery path. The rule used here is a demonstration, not a production-ready IDS signature.

## Organisation des images dans GitHub

Ajoute **toi-même** le dossier `SOC LAB PICS` décompressé à la racine du dépôt, à côté de `README.md`. **Conserve exactement les noms des six sous-dossiers et des 38 fichiers originaux**, y compris les espaces et les majuscules. Les images de ce README renvoient directement à ces noms ; aucun renommage n’est nécessaire.

```text
CyberLab-SOC/
├── README.md
└── SOC LAB PICS/
    ├── step1_adresses_ssh_attaque/
    ├── step2_UFW_network_visibility/
    ├── step3_cree_decodeur_structurer donner/
    ├── step4_incident_responce_steps/
    ├── step5_linux_ssh_hardening/
    └── step6_Wazuh Active Response/
```

**Sécurité :** ne publie pas les clés privées SSH, les secrets de configuration Wazuh, les volumes Docker ou les disques de VM. Vérifie les captures avant publication pour masquer toute information que tu ne souhaites pas rendre publique.

## References

- [Wazuh documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK — T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Ubuntu OpenSSH documentation](https://ubuntu.com/server/docs/service-openssh)

---

**Project outcome:** CyberLab SOC's technical demonstrations were completed by **November 16, 2026**. This repository documents observed results, not ongoing SOC monitoring or a production deployment.
