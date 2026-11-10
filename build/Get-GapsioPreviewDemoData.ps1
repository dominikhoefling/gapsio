#Requires -Version 7.2
<#
.SYNOPSIS
    Fictitious snapshot for the Purview DLP preview module used by New-GapsioDemo.ps1.

.DESCRIPTION
    The Purview module reads Advanced Hunting tables the test tenant in tests/Test-Gapsio.ps1 does not simulate. The
    snapshot follows the shape Invoke-GapsioPurviewPreviewCollection writes, with dates relative to now and a fixed
    random seed, so the demo and the website screenshots are reproducible. All names are made up; mail addresses use
    contoso.example. (The Office module is simulated by the tests and comes from their output.)
#>

function Get-GapsioPreviewDemoData {
    param([DateTime]$Now = [DateTime]::UtcNow, [int]$Seed = 7)
    $rand = [Random]::new($Seed)
    $iso = { param([DateTime]$d) $d.ToString('o') }
    $days = @(29..0 | ForEach-Object { $Now.Date.AddDays(-$_) })
    $T = { param($en, $de) [ordered]@{ en = $en; de = $de } }

    # ---------------------------------------------------------------- Purview DLP preview
    $devNames = @('ws-1042', 'ws-1077', 'ws-1103', 'ws-1150', 'ws-1188', 'ws-1201', 'ws-1243', 'ws-1290', 'mbp-2011', 'mbp-2034', 'mbp-2052', 'ws-1311', 'ws-1325', 'ws-1340')
    $devices = @(for ($i = 0; $i -lt $devNames.Count; $i++) {
            $mac = $devNames[$i].StartsWith('mbp')
            $active = $i % 3 -ne 2 -and $devNames[$i] -ne 'mbp-2052'
            $ev = if ($active) { $rand.Next(4, 220) } else { 0 }
            [ordered]@{ device = $devNames[$i]; platform = $(if ($mac) { 'macOS' } else { 'Windows11' }); osVersion = $(if ($mac) { '15.6' } else { '10.0.26100' }); lastSeen = (& $iso $Now.AddHours(-$rand.Next(1, 40)))
                dlpActive = $active; dlpEvents = $ev; dlpLast = $(if ($active) { & $iso $Now.AddHours(-$rand.Next(2, 90)) } else { $null })
                operations = $(if ($active) { @(@('FileCopiedToRemovableMedia', 'FileUploadedToCloud', 'FilePrinted', 'FileCopiedToClipboard') | Select-Object -First ($rand.Next(1, 4))) } else { @() }) }
        })
    $silent = @($devices | Where-Object { -not $_.dlpActive }).Count
    $alertDaily = foreach ($d in $days) {
        foreach ($b in @(@{ k = 'High'; n = 1 }, @{ k = 'Medium'; n = 4 }, @{ k = 'Low'; n = 7 })) {
            $v = [Math]::Max(0, $b.n + $rand.Next(-2, 3)); if ($v) { [ordered]@{ day = (& $iso $d); bucket = $b.k; events = $v } }
        }
    }
    $cap = { param($id, $label, $lic, $en, $co, $sku, $plan) [ordered]@{ id = $id; label = $label; licensed = $lic; enabled = $en; consumed = $co; sources = @($(if ($lic) { [ordered]@{ skuPartNumber = $sku; enabled = $en; consumed = $co; status = 'Enabled'; plans = @("$plan (Success)") } })) } }
    $purview = [ordered]@{
        version = 1; generatedAt = (& $iso $Now.AddMinutes(-22)); windowDays = 30; ok = 12; errors = 0
        summary = [ordered]@{ capableDevices = $devices.Count; dlpActiveDevices = $devices.Count - $silent; silentDevices = $silent; auditFeed = $true; roleHolders = 9; labels = 7 }
        licensing = [ordered]@{
            capabilities = @(
                (& $cap 'endpointdlp' 'Endpoint DLP' $true 250 212 'SPE_E5' 'MICROSOFTENDPOINTDLP')
                (& $cap 'dlpcore' 'DLP for Exchange / SharePoint / OneDrive' $true 400 361 'SPE_E3' 'EXCHANGE_S_ENTERPRISE')
                (& $cap 'dlpteams' 'DLP for Teams chat / advanced DLP (E5)' $true 250 212 'SPE_E5' 'MIP_S_CLP2')
                (& $cap 'labels' 'Sensitivity labels (manual)' $true 400 361 'SPE_E3' 'MIP_S_CLP1')
                (& $cap 'autolabel' 'Auto-labelling / Information Protection premium' $true 250 212 'SPE_E5' 'MIP_S_CLP2')
                (& $cap 'insiderrisk' 'Insider Risk Management' $true 250 212 'SPE_E5' 'INSIDER_RISK')
                (& $cap 'auditpremium' 'Audit (Premium) / long-term retention' $true 250 212 'SPE_E5' 'M365_ADVANCED_AUDITING')
                (& $cap 'agents' 'Purview for AI agents' $false 0 0 $null $null)
            )
            users = [ordered]@{ endpointdlp = 212; mipPremium = 212; mipStandard = 361; insiderRisk = 212 }
        }
        devices = $devices
        roles = @(
            [ordered]@{ role = 'Global Administrator'; scope = 'Full Purview access, incl. DLP policies and content'; assignment = 'active'; principal = 'Nina Vogt'; upn = 'nina.vogt@contoso.example'; type = 'user'; directoryScope = '/' }
            [ordered]@{ role = 'Global Administrator'; scope = 'Full Purview access, incl. DLP policies and content'; assignment = 'eligible'; principal = 'Kai Becker'; upn = 'kai.becker@contoso.example'; type = 'user'; directoryScope = '/' }
            [ordered]@{ role = 'Compliance Administrator'; scope = 'Create/change DLP, label and retention policies'; assignment = 'active'; principal = 'Compliance Team (Demo)'; upn = ''; type = 'group'; directoryScope = '/' }
            [ordered]@{ role = 'Compliance Data Administrator'; scope = 'DLP policies + compliance data'; assignment = 'eligible'; principal = 'Dana Seidel'; upn = 'dana.seidel@contoso.example'; type = 'user'; directoryScope = '/' }
            [ordered]@{ role = 'Security Operator'; scope = 'Manage DLP alerts'; assignment = 'active'; principal = 'SOC Analysts (Demo)'; upn = ''; type = 'group'; directoryScope = '/' }
            [ordered]@{ role = 'Security Reader'; scope = 'Read DLP alerts and reports'; assignment = 'active'; principal = 'Bob (Demo)'; upn = 'bob.demo@contoso.example'; type = 'user'; directoryScope = '/' }
        )
        labels = @(
            [ordered]@{ id = 'l1'; name = 'Public'; parent = ''; sensitivity = 0; isActive = $true; contentFormats = @('file', 'email') }
            [ordered]@{ id = 'l2'; name = 'General'; parent = ''; sensitivity = 1; isActive = $true; contentFormats = @('file', 'email') }
            [ordered]@{ id = 'l3'; name = 'Confidential'; parent = ''; sensitivity = 2; isActive = $true; contentFormats = @('file', 'email', 'site', 'unifiedGroup') }
            [ordered]@{ id = 'l4'; name = 'All employees'; parent = 'Confidential'; sensitivity = 3; isActive = $true; contentFormats = @('file', 'email') }
            [ordered]@{ id = 'l5'; name = 'Finance'; parent = 'Confidential'; sensitivity = 4; isActive = $true; contentFormats = @('file', 'email') }
            [ordered]@{ id = 'l6'; name = 'Highly confidential'; parent = ''; sensitivity = 5; isActive = $true; contentFormats = @('file', 'email', 'site', 'unifiedGroup') }
            [ordered]@{ id = 'l7'; name = 'Board only'; parent = 'Highly confidential'; sensitivity = 6; isActive = $true; contentFormats = @('file', 'email') }
        )
        results = @(
            [ordered]@{ key = 'devices_platform'; title = 'MDE-onboarded devices by platform'; workload = 'Devices'; status = 'ok'; result = @([ordered]@{ OSPlatform = 'Windows11'; devices = 11; capable = 11 }, [ordered]@{ OSPlatform = 'macOS'; devices = 3; capable = 3 }, [ordered]@{ OSPlatform = 'WindowsServer2022'; devices = 4; capable = 0 }) }
            [ordered]@{ key = 'dlp_rule_matches'; title = 'DLP rule matches by workload and policy'; workload = 'DLP'; status = 'ok'; result = @(
                    [ordered]@{ Workload = 'Endpoint'; Policy = 'Protect customer data'; Rule = 'Credit card numbers – block USB'; events = 184; users = 22; LastEvent = (& $iso $Now.AddHours(-3)) },
                    [ordered]@{ Workload = 'Exchange'; Policy = 'Protect customer data'; Rule = 'External recipients'; events = 96; users = 31; LastEvent = (& $iso $Now.AddHours(-6)) },
                    [ordered]@{ Workload = 'SharePoint'; Policy = 'Finance documents'; Rule = 'Anonymous sharing'; events = 41; users = 9; LastEvent = (& $iso $Now.AddDays(-1)) }) }
            [ordered]@{ key = 'dlp_overrides'; title = 'DLP overrides and justifications'; workload = 'DLP'; status = 'ok'; result = @(
                    [ordered]@{ User = 'sales.rep1@contoso.example'; overrides = 14; LastEvent = (& $iso $Now.AddHours(-20)) }, [ordered]@{ User = 'sales.rep2@contoso.example'; overrides = 6; LastEvent = (& $iso $Now.AddDays(-2)) }) }
            [ordered]@{ key = 'dlp_alerts_daily'; title = 'DLP alerts (daily)'; workload = 'Alerts'; status = 'ok'; result = @($alertDaily) }
            [ordered]@{ key = 'dlp_alerts'; title = 'DLP alerts'; workload = 'Alerts'; status = 'ok'; result = @(
                    [ordered]@{ Severity = 'High'; Title = 'DLP policy match: credit card numbers copied to USB'; alerts = 9; LastEvent = (& $iso $Now.AddHours(-3)) },
                    [ordered]@{ Severity = 'Medium'; Title = 'DLP policy match: finance document shared anonymously'; alerts = 17; LastEvent = (& $iso $Now.AddDays(-1)) },
                    [ordered]@{ Severity = 'Low'; Title = 'DLP policy match: external e-mail with customer data'; alerts = 64; LastEvent = (& $iso $Now.AddHours(-6)) }) }
            [ordered]@{ key = 'label_changes'; title = 'Sensitivity labels removed or downgraded'; workload = 'Labels'; status = 'ok'; result = @([ordered]@{ User = 'project.lead@contoso.example'; removed = 3; downgraded = 8 }) }
        )
        findings = @(
            [ordered]@{ id = 'purview.devices_silent'; severity = 'Medium'; category = 'purview'
                title = (& $T 'Capable devices without Endpoint DLP activity' 'DLP-fähige Geräte ohne Endpoint-DLP-Aktivität')
                detail = (& $T "$silent of $($devices.Count) onboarded Windows/macOS devices reported no DLPEndpoint audit event in 30 days." "$silent von $($devices.Count) onboarded Windows-/macOS-Geräten haben in 30 Tagen kein DLPEndpoint-Audit-Ereignis gemeldet.")
                recommendation = (& $T 'Check Purview > Settings > Device onboarding, policy scope (devices/users) and that Endpoint DLP policies include the Devices location.' 'Purview > Einstellungen > Geräte-Onboarding, Policy-Scope (Geräte/Benutzer) und Speicherort „Geräte“ in den Endpoint-DLP-Richtlinien prüfen.') }
            [ordered]@{ id = 'purview.overrides'; severity = 'Medium'; category = 'purview'
                title = (& $T 'Users override DLP policies' 'Benutzer übersteuern DLP-Richtlinien')
                detail = (& $T '20 override(s)/justification(s) by 2 user(s) in 30 days.' '20 Override(s)/Begründung(en) von 2 Benutzer(n) in 30 Tagen.')
                recommendation = (& $T 'Review justifications; switch frequently overridden rules from "warn" to "block" or refine them.' 'Begründungen prüfen; häufig übersteuerte Regeln von „Warnen“ auf „Blockieren“ umstellen oder schärfen.') }
            [ordered]@{ id = 'purview.label_downgrades'; severity = 'Medium'; category = 'purview'
                title = (& $T 'Sensitivity labels removed or downgraded' 'Vertraulichkeitsbezeichnungen entfernt oder herabgestuft')
                detail = (& $T '3 removal(s), 8 downgrade(s) by 1 user(s).' '3 Entfernung(en), 8 Herabstufung(en) durch 1 Benutzer.')
                recommendation = (& $T 'Require justification for downgrades (label policy) and correlate with exfil activity.' 'Begründungspflicht für Herabstufungen (Label-Policy) aktivieren und mit Exfil-Aktivität korrelieren.') }
            [ordered]@{ id = 'purview.compliance_permanent'; severity = 'Low'; category = 'purview'
                title = (& $T 'Compliance roles assigned permanently' 'Compliance-Rollen dauerhaft zugewiesen')
                detail = (& $T '1 permanent Compliance (Data) Administrator assignment(s).' '1 dauerhafte Compliance-(Data-)Administrator-Zuweisung(en).')
                recommendation = (& $T 'Prefer PIM eligible assignments with approval.' 'PIM-berechtigte Zuweisungen mit Genehmigung bevorzugen.') }
        )
        warnings = @()
        notes = @(
            'Purview role groups (Compliance portal) have no Microsoft Graph API – only Entra roles are listed.'
            'Endpoint DLP device onboarding switch and DLP policies themselves are only readable via Security & Compliance PowerShell (Get-DlpCompliancePolicy).')
    }
    [ordered]@{ purviewpreview = $purview }
}
