# Testing in a test tenant

!!! warning
    Use a **test tenant** only. All objects are named "Wardline-Test …" and can be removed completely.

## 1. Install Wardline

See the [quick start](getting-started.md) – first without test data to verify setup, sign-in and permissions.
The device inventory can be tested with `-DeviceInventory`; the test VM must then also be enrolled in Intune.

## 2. Test VM (Windows 11 Enterprise)

```powershell
# Onboarding package: Defender portal › Settings › Endpoints › Onboarding › Windows 10 and 11 › "Group Policy"
./tests/vm/New-WardlineTestVm.ps1 -ResourceGroup rg-wardline-testvm -Location germanywestcentral -OnboardingPackage ~/Downloads/WindowsDefenderATPOnboardingPackage.zip
```

No inbound ports, auto-shutdown at 18:00 UTC, managed without RDP via `az vm run-command`.

## 3. Test data in the tenant

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
./tests/tenant/New-WardlineTestData.ps1 -TenantId <tenant>.onmicrosoft.com -SkipAccess
```

- Checks every Settings Catalog ID of the baseline against the tenant → `wardline-setting-check.txt`
- Windows, macOS, Linux and ASR test policies with exclusions at every risk level and deliberate deviations,
  **assigned to an empty group** (applies to no device)
- AI agents: a test blueprint, three agent identities, two agent users and two **report-only** Conditional Access
  policies (needs the Agent ID licence/preview; `-SkipAgents` to skip)
- Two allow indicators with made-up values (`-SkipIndicators` to skip)
- Without `-SkipAccess`: disabled test users, a role-assignable group, PIM eligibility, PIM for groups and an access package

## 4. Local exclusions on the VM

```powershell
./tests/vm/Invoke-WardlineVmTest.ps1 -Phase Setup     # 4 local exclusions
./tests/vm/Invoke-WardlineVmTest.ps1 -Phase Status    # check on the VM
```

## 5. Collect and review

After 15–30 minutes click **Collect now** in the portal.

## 6. Drift

`-Phase Drift` removes one exclusion; collect again and open **Changes**.

## 7. Clean up

```powershell
./tests/vm/Invoke-WardlineVmTest.ps1 -Phase Cleanup
./tests/tenant/Remove-WardlineTestData.ps1 -TenantId <tenant>.onmicrosoft.com
az group delete -n rg-wardline-testvm --yes
```
