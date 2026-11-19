import { addDaysIso } from './dates.ts'
import { severityFromCvss } from './severity.ts'
import type { Vulnerability, VulnerabilityInput } from './types.ts'

type SeedSpec = VulnerabilityInput & { id: string }

function seedAt(today: string): SeedSpec[] {
  return [
    {
      id: 'demo-router-default-admin',
      title: 'Default administrator password still enabled',
      asset: 'router',
      cveId: null,
      cvss: 9.8,
      status: 'In progress',
      owner: 'Network',
      dueDate: addDaysIso(today, -2),
      notes: 'Replace the factory password and disable WAN management. Demo finding only.',
    },
    {
      id: 'demo-camera-auth-bypass',
      title: 'IP camera firmware with a known authentication bypass',
      asset: 'camera-01',
      cveId: 'CVE-2021-36260',
      cvss: 9.8,
      status: 'Open',
      owner: 'Lab',
      dueDate: addDaysIso(today, -7),
      notes: 'Isolate the camera VLAN until a vendor update is applied. Demo finding only.',
    },
    {
      id: 'demo-wifi-wps',
      title: 'Wi-Fi protected setup (WPS) is still enabled',
      asset: 'wifi-ap',
      cveId: null,
      cvss: 7.5,
      status: 'Open',
      owner: 'Network',
      dueDate: addDaysIso(today, -1),
      notes: 'Turn WPS off on the access point and use a long WPA2/WPA3 passphrase.',
    },
    {
      id: 'demo-nas-openssh',
      title: 'OpenSSH version affected by a race-condition signal handler issue',
      asset: 'nas-01',
      cveId: 'CVE-2024-6387',
      cvss: 8.1,
      status: 'Open',
      owner: 'Storage',
      dueDate: addDaysIso(today, 7),
      notes: 'Upgrade OpenSSH on nas-01 and confirm the service still starts after reboot.',
    },
    {
      id: 'demo-pihole-admin',
      title: 'Pi-hole admin interface reachable on the LAN without 2FA',
      asset: 'pi-hole',
      cveId: null,
      cvss: 6.5,
      status: 'Mitigated',
      owner: 'DNS',
      dueDate: addDaysIso(today, -14),
      notes: 'Restricted the UI to a management VLAN and enabled a unique admin password.',
    },
    {
      id: 'demo-nas-rsync',
      title: 'Unencrypted rsync daemon exposed on the LAN',
      asset: 'nas-01',
      cveId: null,
      cvss: 5.3,
      status: 'Accepted risk',
      owner: 'Storage',
      dueDate: addDaysIso(today, 30),
      notes: 'Accepted for trusted lab hosts only. Track until SSH-based sync replaces it.',
    },
    {
      id: 'demo-pihole-logs',
      title: 'DNS query logs kept without a retention limit',
      asset: 'pi-hole',
      cveId: null,
      cvss: 4.3,
      status: 'Open',
      owner: 'DNS',
      dueDate: addDaysIso(today, 14),
      notes: 'Configure log rotation and shorten the query history window.',
    },
    {
      id: 'demo-hypervisor-spec',
      title: 'Hypervisor missing microcode mitigations for speculative execution',
      asset: 'hypervisor',
      cveId: 'CVE-2017-5754',
      cvss: 5.6,
      status: 'Accepted risk',
      owner: 'Compute',
      dueDate: null,
      notes: 'Accepted until the next maintenance window. Guest workloads are not shared.',
    },
    {
      id: 'demo-printer-snmp',
      title: 'Printer answers to SNMP v2c with a public community string',
      asset: 'printer',
      cveId: null,
      cvss: 3.7,
      status: 'In progress',
      owner: 'Lab',
      dueDate: addDaysIso(today, 10),
      notes: 'Disable SNMPv2c or move to SNMPv3 with a unique community.',
    },
  ]
}

export function buildDemoVulnerabilities(
  today: string,
  nowIso = new Date().toISOString(),
): Vulnerability[] {
  return seedAt(today).map((spec) => ({
    id: spec.id,
    title: spec.title,
    asset: spec.asset,
    cveId: spec.cveId,
    cvss: spec.cvss,
    severity: severityFromCvss(spec.cvss),
    status: spec.status,
    owner: spec.owner,
    dueDate: spec.dueDate,
    notes: spec.notes,
    createdAt: nowIso,
    updatedAt: nowIso,
  }))
}
