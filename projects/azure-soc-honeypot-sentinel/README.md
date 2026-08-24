# Azure Sentinel SOC Lab: Honeypot Traffic Analysis & Threat Detection

## Overview
This project simulates a Security Operations Center (SOC) workflow using Microsoft Azure and Microsoft Sentinel. I deployed an intentionally exposed Windows VM ("honeypot") to the public internet, disabled its firewall protections, and captured real-world attack traffic. Logs from the VM were forwarded into a Log Analytics Workspace and analyzed in Sentinel using KQL (Kusto Query Language) to identify failed login attempts, extract attacker IP data, and visualize attack origins on a geographic map.

## Objectives
- Deploy and configure a vulnerable VM in Azure to attract real-world attack traffic
- Forward Windows Security Event logs to a centralized SIEM (Microsoft Sentinel)
- Query and filter security logs using KQL
- Enrich attacker IP data with geolocation information
- Visualize attack sources on an interactive map for analysis

## Architecture

| Component | Details |
| :--- | :--- |
| Resource Group | SOC_LAB_1 |
| Region | East US 2 |
| Virtual Network | Vnet_SOC_LAB_1 (10.0.0.0/16) |
| Honeypot VM | USER-1-CORP |
| VM Image | Windows 10 Enterprise, 22H2 – x64 Gen2 |
| VM Size | D2s_v3 (2 vCPUs, 8 GiB RAM) |
| Log Analytics Workspace | LAW-SOC-LAB-1 |
| SIEM | Microsoft Sentinel |
| Log Forwarding Method | Windows Security Events via AMA (Azure Monitor Agent) |

**Traffic Flow:**
Public Internet → NSG (Allow All Inbound) → Exposed VM (Firewall Disabled) → Windows Security Event Logs → Data Collection Rule → Log Analytics Workspace → Microsoft Sentinel → KQL Analysis & Visualization


## Setup / Steps Performed

### 1. Create the Resource Group
Created a resource group to contain all lab resources.
- Name: `SOC_LAB_1`
- Region: East US 2

A resource group acts as a logical container/folder for everything deployed in this lab.


### 2. Create the Virtual Network
Deployed a virtual network to host the honeypot VM.
- Name: `Vnet_SOC_LAB_1`
- Address space: `10.0.0.0/16` → usable range `10.0.0.0 – 10.0.0.255` (/24, 256 addresses)
- Resource Group: `SOC_LAB_1`


### 3. Deploy the Honeypot VM
Created the VM that would serve as the exposed target.
- Name: `USER-1-CORP`
- Image: Windows 10 Enterprise, version 22H2 – x64 Gen2
- Size: `D2s_v3` (2 vCPUs, 8 GiB memory) — approx. $70.08/month if left running continuously; **stopped the VM when not actively collecting data to control cost**
- Availability Options: No infrastructure redundancy required (zonal redundancy unavailable for this size in the selected region)

Once deployed, Azure automatically generated supporting resources within the resource group: a Public IP address, a Network Security Group (NSG, acting as a virtual firewall), a Network Interface (virtual Ethernet port), and a managed disk.


### 4. Configure NSG Inbound Rule
Added an inbound rule to intentionally expose the VM to all traffic.
- Name: `DANGER_AllowAnyCustomInbound`
- Source: Any
- Source Port Ranges: * (Any)
- Destination: Any
- Destination Port Range: * (Any)
- Service: Custom
- Action: Allow
- Priority: 100

This rule name was deliberately marked with `DANGER_` as a reminder that this configuration is unsafe outside of an isolated lab environment.


### 5. Disable the Windows Firewall
Connected to the VM via RDP using its public IP address (Windows App on macOS), then opened `wf.msc` (Windows Firewall with Advanced Security) and disabled the firewall across all profile tabs (Domain, Private, Public).

Verified exposure by pinging the VM's public IP from a local device — successful replies confirmed the VM was now reachable from the internet.


### 6. Generate Initial Test Traffic
Attempted a login with intentionally incorrect credentials to confirm that failed login attempts were being logged locally on the VM, in preparation for forwarding those logs to the SIEM.

### 7. Create the Log Analytics Workspace
- Name: `LAW-SOC-LAB-1`
- Resource Group: `SOC_LAB_1`

This workspace serves as the centralized storage location for log data ingested from the VM.


### 8. Deploy Microsoft Sentinel
Enabled Sentinel on top of the Log Analytics Workspace to serve as the SIEM layer.

### 9. Connect the VM as a Data Source
Installed the **Windows Security Events via AMA (Azure Monitor Agent)** connector in Sentinel and configured a Data Collection Rule (DCR) to forward the VM's security event logs.
- Rule Name: `DCR-Windows-SOC-LAB-1`
- Resource Group: `SOC_LAB_1`
- Resource: `USER-1-CORP` (honeypot VM)
- Data Source: All Security Events

Verified the Azure Monitor Windows Agent extension showed **"Provisioning Succeeded"** under the VM's Extensions + Applications tab, confirming successful log forwarding setup.


### 10. Validate Log Ingestion with KQL
In the Log Analytics Workspace's Logs tab, queried the `SecurityEvent` table to confirm logs were flowing in from the VM (allowing a short delay for initial ingestion).

```kql
SecurityEvent
| where Account == "<account name>"
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress
```

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress
```

Event ID `4625` represents a failed logon attempt — the primary signal used to identify brute-force and credential-based attack attempts against the honeypot.


### 11. Enrich Data with Geolocation (Watchlist)
To map attacker origins, uploaded a GeoIP CSV dataset (~55,000 entries) as a Sentinel Watchlist.
- Name: `geoip`
- Alias: `geoip`
- Search Key: `network`

*(Note: this feature has since moved to Microsoft Defender but functions the same way.)*

Queried a specific attacker IP against the watchlist to enrich failed logon events with location data:

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "<attacker IP address>"
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```


### 12. Build an Attack Map Visualization
Created a Sentinel Workbook to visualize failed login attempts geographically, aggregating failure counts by attacker IP and location, then rendering them as a heatmap.

```json
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
    "size": 3,
    "timeContext": {
      "durationMs": 2592000000
    },
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "map",
    "mapSettings": {
      "locInfo": "LatLong",
      "locInfoColumn": "countryname",
      "latitude": "latitude",
      "longitude": "longitude",
      "sizeSettings": "FailureCount",
      "sizeAggregation": "Sum",
      "opacity": 0.8,
      "labelSettings": "friendly_location",
      "legendMetric": "FailureCount",
      "legendAggregation": "Sum",
      "itemColorSettings": {
        "nodeColorField": "FailureCount",
        "colorAggregation": "Sum",
        "type": "heatmap",
        "heatmapPalette": "greenRed"
      }
    }
  },
  "name": "query - 0"
}
```

Saved the workbook to complete the lab.


## Findings / Results
- Total failed login attempts observed: `#`
- Top attacking countries/regions: `...`
- Notable attacker IP(s) and behavior patterns: `...`
- Any brute-force or credential-stuffing patterns identified: `...`

## Skills Demonstrated
- Azure infrastructure deployment (Resource Groups, VNets, VMs, NSGs)
- Network security concepts (firewall rules, exposure/attack surface, NSG configuration)
- Microsoft Sentinel (data connectors, watchlists, workbooks, analytics)
- Basic KQL (Kusto Query Language) for log querying and data enrichment
- SIEM log ingestion pipeline (VM → AMA → DCR → Log Analytics → Sentinel)
- Threat data visualization and geolocation analysis

## Lessons Learned / Next Steps
- Map observed attacker behavior to MITRE ATT&CK techniques
- Build Sentinel Analytics Rules to auto-generate alerts/incidents from repeated failed logons
- Add a SOAR playbook (e.g., auto-block attacker IP after N failed attempts)
- Compare attack patterns across a longer collection window
- Explore cost-optimization strategies for running honeypot labs (auto-shutdown schedules)

---
*Note: This lab was conducted in an isolated Azure environment for educational purposes. The VM was intentionally exposed and firewall-disabled only within this controlled sandbox, then deallocated after data collection to avoid ongoing exposure and cost.*
