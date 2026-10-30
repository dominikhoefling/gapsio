# Features and permissions

Wardline follows least privilege: every feature adds only the read-only application permissions it needs – nothing
more. The single source of truth is [`setup/permissions.json`](https://github.com/dominikhoefling/wardline/blob/main/setup/permissions.json);
the install, grant and app registration scripts all read it.

| Feature | Default | What you get | Permissions (read-only, application) |
|---|---|---|---|
| `Core` | always | Intune policies: exclusions, ASR configuration, MDAV baseline (Windows, macOS, Linux) | Graph: `DeviceManagementConfiguration.Read.All`, `GroupMember.Read.All` |
| `Hunting` | on | Device state, local exclusions, effective ASR mode, Linux/macOS drift, local AI agents (Advanced Hunting) | Graph: `ThreatHunting.Read.All` |
| `Indicators` | on | Allow indicators from Defender for Endpoint | Defender for Endpoint: `Ti.Read.All` |
| `Coverage` | on | Intune-managed devices that are not onboarded to Defender for Endpoint (sensor problems and device discovery need only `Hunting`) | Graph: `DeviceManagementManagedDevices.Read.All` |
| `Agents` | on | Entra Agent ID, Agent 365 package catalog, Conditional Access coverage | Graph: `AgentIdentityBlueprint.Read.All`, `AgentIdentityBlueprintPrincipal.Read.All`, `AgentIdentity.Read.All`, `User.ReadBasic.All`, `CopilotPackages.Read.All`, `AgentInstance.Read.All` (legacy fallback), `Policy.Read.All` |
| `Access` | off | Defender XDR unified RBAC: roles, assignments, data-source scope, PIM eligibility and activations, access packages, portal usage, Entra bypass roles | Graph: `RoleManagement.Read.Defender`, `RoleManagement.Read.Directory`, `PrivilegedEligibilitySchedule.Read.AzureADGroup`, `PrivilegedAssignmentSchedule.Read.AzureADGroup`, `EntitlementManagement.Read.All`, `AuditLog.Read.All`, `Directory.Read.All` |
| `Inventory` | off | Device inventory via Intune Remediations (use `-DeviceInventory`) | Graph: `DeviceManagementScripts.Read.All`, `DeviceManagementManagedDevices.Read.All` |

```powershell
# Show exactly what would be granted – changes nothing
./setup/Install-Wardline.ps1 -ShowPermissions -Features Hunting,Agents

# Endpoint only, without agents and indicators
./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -Features Hunting

# Add the optional access module later
./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -Features Hunting,Indicators,Coverage,Agents,Access
```

- **Switching a feature off** and running the script again removes the permissions that are no longer needed.
- A feature that is not selected is **skipped quietly** at runtime – no errors for missing permissions.
- New releases may add permissions only in a new **minor** version; `Update-Wardline.ps1` reports them before updating
  ([updates](updates.md)).

## Who holds the permissions?

By default the **user-assigned managed identity** of the Function App (`id-<prefix>-runner`). Alternatively a
**data-access app registration** created by the identity team; the managed identity signs in to it via workload
identity federation, so there is still no secret ([separation of duties](separation-of-duties.md)).

## Other identities

- **Portal app registration**: no application permissions, no secret. Delegated `openid profile email User.Read` only
  (admin consent), app role `Wardline.Admin` for administrators.
- **Azure roles** of the managed identity: Storage Blob/Queue/Table Data roles only on Wardline's own storage account,
  Monitoring Metrics Publisher on its Application Insights.
