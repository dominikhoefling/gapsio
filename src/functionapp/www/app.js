/* Wardline portal. Deliberately without a framework and without external dependencies.
   Security rule: data is only ever written to the DOM as text (never innerHTML), because exclusion paths,
   command lines and names can come from attackers.
   Languages: English and German. The back end delivers codes (status, severity, type …) and bilingual
   texts ({ en, de }); this file translates the codes and picks the text in the selected language. */
(() => {
  'use strict';

  // ---------- Language ----------
  const LANGS = { en: 'English', de: 'Deutsch' };
  function storedLang() { try { return localStorage.getItem('wardline-lang'); } catch { return null; } }
  let lang = storedLang() || ((navigator.language || '').toLowerCase().startsWith('de') ? 'de' : 'en');
  if (!LANGS[lang]) lang = 'en';
  const locale = () => (lang === 'de' ? 'de-DE' : 'en-GB');

  /* Dictionary: key -> [English, German]. {0}, {1} … are placeholders. */
  const L = {
    // general
    'loading': ['Loading …', 'Lade …'], 'data.as.of': ['Data as of {0}', 'Datenstand {0}'], 'reload': ['Reload', 'Neu laden'],
    'version': ['Version {0}', 'Version {0}'], 'update.available': ['Update available: {0}', 'Update verfügbar: {0}'],
    'run.now': ['Collect now', 'Jetzt erfassen'], 'reloaded': ['Data reloaded.', 'Daten neu geladen.'], 'signout': ['Sign out', 'Abmelden'],
    'role.admin': ['Wardline administrator', 'Wardline-Administrator'], 'role.user': ['User', 'Benutzer'], 'signed.in': ['Signed in', 'Angemeldet'],
    'language': ['Language', 'Sprache'], 'search': ['Search …', 'Suchen …'], 'search.aria': ['Search table', 'Tabelle durchsuchen'],
    'export.csv': ['Export as CSV', 'Als CSV exportieren'], 'all': ['all', 'alle'], 'entries': ['{0} entries', '{0} Einträge'], 'entry': ['1 entry', '1 Eintrag'],
    'entries.capped': ['{0} entries, showing the first {1} (the export contains all).', '{0} Einträge, die ersten {1} werden angezeigt (Export enthält alle).'],
    'no.match': ['No matches for these filters.', 'Keine Treffer für diese Filter.'], 'no.entries': ['No entries.', 'Keine Einträge.'],
    'none': ['none', 'keine'], 'never': ['never', 'nie'], 'unlimited': ['permanent', 'unbefristet'], 'error': ['Error: {0}', 'Fehler: {0}'],
    'run.started': ['Run started.', 'Lauf gestartet.'], 'run.failed': ['Start failed: {0}', 'Start fehlgeschlagen: {0}'],
    'run.403': ['Start failed (403 from Azure): sign-in rejected the request. Reload the page (Ctrl+F5) and try again.', 'Start fehlgeschlagen (403 von Azure): Die Anmeldung hat die Anfrage abgelehnt. Seite neu laden (Strg+F5) und erneut versuchen.'],
    'demo.run': ['Demo: runs are not possible here.', 'Demo: Läufe sind hier nicht möglich.'],
    'nodata.admin': ['There is no data for this area yet.', 'Für diesen Bereich liegen noch keine Daten vor.'],
    'nodata.user': ['There is no data for this area yet. Data is updated daily.', 'Für diesen Bereich liegen noch keine Daten vor. Die Daten werden täglich aktualisiert.'],
    'load.failed': ['Data could not be loaded: {0}', 'Daten konnten nicht geladen werden: {0}'], 'unknown.error': ['unknown error', 'unbekannter Fehler'],
    'signin.failed': ['Sign-in failed: {0}', 'Anmeldung fehlgeschlagen: {0}'], 'not.signed.in': ['Not signed in', 'Nicht angemeldet'],
    'warnings': ['{0} notice(s) from the last run (e.g. missing permissions or licences)', '{0} Hinweis(e) aus dem letzten Lauf (z. B. fehlende Rechte oder Lizenzen)'],
    'noaccess': ['Wardline is only available to administrators (app role “Wardline Administrator”). Please contact your security team.', 'Wardline steht nur Administratoren zur Verfügung (App-Rolle „Wardline Administrator“). Bitte wenden Sie sich an Ihr Security-Team.'],
    'ok': ['OK', 'OK'], 'problem': ['Problem', 'Problem'], 'na': ['n/a', 'n. a.'], 'yes': ['yes', 'ja'], 'no': ['no', 'nein'],
    // navigation
    'nav.endpoint': ['Endpoint', 'Endpoint'], 'nav.agents': ['AI agents (beta)', 'KI-Agents (Beta)'], 'nav.access': ['Permissions (unified RBAC)', 'Berechtigungen (Unified RBAC)'], 'nav.everyone': ['For everyone', 'Für alle'], 'nav.history': ['History', 'Verlauf'], 'nav.settings': ['Settings', 'Einstellungen'],
    'nav.menu': ['Menu', 'Menü'], 'nav.close': ['Close menu', 'Menü schließen'],
    'v.overview': ['Overview', 'Übersicht'], 'v.findings': ['Findings', 'Befunde'], 'v.exclusions': ['Exclusions', 'Exclusions'], 'v.asr': ['ASR rules', 'ASR-Regeln'],
    'v.devices': ['Devices', 'Geräte'], 'v.baseline': ['Baseline', 'Baseline'], 'v.agents': ['Agents', 'Agents'], 'v.agentca': ['Conditional Access', 'Conditional Access'],
    'v.access': ['Roles and paths', 'Rollen und Wege'], 'v.whocan': ['Who can do what?', 'Wer kann was?'], 'v.mine': ['My permissions', 'Meine Rechte'], 'v.changes': ['Changes', 'Änderungen'],
    'nav.licensing': ['Licences', 'Lizenzen'], 'v.licensing': ['Licence indication', 'Lizenz-Indikation'],
    'li.product': ['Product', 'Produkt'], 'lp.MDE': ['Defender for Endpoint', 'Defender for Endpoint'], 'lp.MDO': ['Defender for Office 365', 'Defender for Office 365'],
    'li.sec.mde': ['Defender for Endpoint', 'Defender for Endpoint'], 'li.sec.mdo': ['Defender for Office 365', 'Defender for Office 365'],
    'li.mdo.lede': ['Licensed per user (mailbox). Purchased vs. assigned units and the users holding a plan. Plan 2 adds Threat Explorer, automated investigation, attack simulation and campaign views – these work tenant-wide, which is why Microsoft expects Plan 2 for every user who benefits.', 'Lizenziert pro Benutzer (Postfach). Gekaufte vs. zugewiesene Einheiten und die Benutzer mit Plan. Plan 2 ergänzt Threat Explorer, automatische Untersuchung, Angriffssimulation und Kampagnenansicht – diese wirken mandantenweit, weshalb Microsoft Plan 2 für jeden Benutzer erwartet, der davon profitiert.'],
    'li.mdo.none': ['No Defender for Office 365 plan found in this tenant.', 'Kein Defender-for-Office-365-Plan in diesem Mandanten gefunden.'],
    'li.mdoUsers': ['users with an MDO plan', 'Benutzer mit MDO-Plan'], 'li.mdoUsersP2': ['on Plan 2', 'mit Plan 2'], 'li.mdoUsersP1': ['on Plan 1', 'mit Plan 1'], 'li.mdoDisabled': ['disabled accounts with a plan', 'deaktivierte Konten mit Plan'],
    'li.mdoWithoutMde': ['MDO users without an MDE plan', 'MDO-Benutzer ohne MDE-Plan'], 'li.mdeWithoutMdo': ['MDE users without an MDO plan', 'MDE-Benutzer ohne MDO-Plan'],
    'li.mdoUserTable': ['Users with a Defender for Office 365 plan', 'Benutzer mit Defender-for-Office-365-Plan'], 'li.mdeTier': ['MDE plan', 'MDE-Plan'],
    'li.tab.overview': ['Overview', 'Übersicht'], 'li.skus.lede': ['Every subscription that contains a Defender plan, with purchased and assigned units. Suites such as Microsoft 365 E5 appear once per product.', 'Jedes Abonnement mit einem Defender-Plan, mit gekauften und zugewiesenen Einheiten. Suiten wie Microsoft 365 E5 erscheinen einmal pro Produkt.'],
    'li.ov.mde.note': ['Per user, up to five devices each. Devices are mapped to users – open for details.', 'Pro Benutzer, bis zu fünf Geräte. Geräte werden Benutzern zugeordnet – für Details öffnen.'],
    'li.ov.mdo.note': ['Per user (mailbox). Plan holders and plan mix – open for details.', 'Pro Benutzer (Postfach). Planinhaber und Plan-Mix – für Details öffnen.'],
    'mod.endpoint': ['Endpoint', 'Endpoint'], 'mod.agents': ['Agents (beta)', 'Agents (Beta)'], 'mod.access': ['Access', 'Zugriffe'], 'mod.licensing': ['Licensing', 'Lizenzen'],
    'cat.Licensing': ['Licensing', 'Lizenzen'], 'coll.skus': ['SKU', 'SKU'], 'coll.users': ['Licensed user', 'Lizenzierter Benutzer'],
    // severities and categories
    'sev.Critical': ['Critical', 'Kritisch'], 'sev.High': ['High', 'Hoch'], 'sev.Medium': ['Medium', 'Mittel'], 'sev.Low': ['Low', 'Niedrig'], 'sev.Info': ['Info', 'Info'],
    'cat.Combined': ['Combined', 'Kombiniert'], 'cat.Device': ['Device', 'Gerät'], 'cat.Exclusion': ['Exclusion', 'Exclusion'], 'cat.Indicator': ['Indicator', 'Indikator'],
    'cat.Baseline': ['Baseline', 'Baseline'], 'cat.ASR': ['ASR', 'ASR'], 'cat.ConditionalAccess': ['Conditional Access', 'Conditional Access'], 'cat.Accountability': ['Accountability', 'Verantwortung'],
    'cat.Agent': ['Agent', 'Agent'], 'cat.LocalAgent': ['Local agent', 'Lokaler Agent'],
    // overview
    'ov.title': ['Overview', 'Übersicht'], 'ov.aria': ['Findings by severity: {0}', 'Befunde nach Schweregrad: {0}'],
    'ov.clean': ['No open findings. The ward line is closed.', 'Keine offenen Befunde. Die Verteidigungslinie ist geschlossen.'],
    'ov.open': ['{0} open finding(s)', '{0} offene(r) Befund(e)'], 'ov.crit': [', {0} of them critical', ', davon {0} kritisch'],
    'ov.combined': [' {0} finding(s) only arise from a combination of several weaknesses.', ' {0} Befund(e) entstehen erst aus der Kombination mehrerer Schwächen.'],
    'ov.devices': ['devices in Defender', 'Geräte in Defender'], 'ov.policyExcl': ['exclusions in policies', 'Exclusions in Richtlinien'], 'ov.localExcl': ['local exclusions on devices', 'lokale Exclusions auf Geräten'],
    'ov.edr': ['exclusions that also affect EDR', 'Ausnahmen, die auch EDR betreffen'], 'ov.asr': ['ASR rules on target', 'ASR-Regeln im Soll'], 'ov.of': ['{0} of {1}', '{0} von {1}'],
    'ov.baseline': ['baseline checks met', 'Baseline-Prüfungen erfüllt'],
    'ov.cloud': ['cloud agents, {0} with Entra Agent ID', 'Cloud-Agents, davon {0} mit Entra Agent ID'], 'ov.local': ['local agents on {0} device(s)', 'lokale Agents auf {0} Gerät(en)'],
    'ov.caId': ['agent identities protected by Conditional Access', 'Agent-Identitäten mit Conditional Access'], 'ov.caUser': ['agent users protected by Conditional Access', 'Agent-User mit Conditional Access'],
    'ov.autoApprove': ['local agents with auto-approve', 'lokale Agents mit Auto-Approve'],
    'ov.priv': ['people with permanent response/config permissions', 'Personen mit dauerhaften Response-/Konfigurationsrechten'], 'ov.elig': ['eligible permissions (PIM for groups)', 'eligible Berechtigungen (PIM für Gruppen)'],
    'ov.unusedAcc': ['people whose permissions were never used', 'Personen, deren Berechtigungen nie genutzt wurden'], 'ov.bypass': ['people bypassing unified RBAC via Entra roles', 'Personen umgehen Unified RBAC über Entra-Rollen'],
    'ov.openPkg': ['packages requestable by all users', 'Pakete für alle Benutzer beantragbar'], 'ov.runs': ['Recent runs', 'Letzte Läufe'],
    'col.time': ['Time', 'Zeitpunkt'], 'col.module': ['Module', 'Modul'], 'col.changes': ['Changes', 'Änderungen'], 'col.notices': ['Notices', 'Hinweise'], 'col.duration': ['Duration', 'Dauer'],
    // findings
    'f.lede': ['Everything that weakens protection – individually and in combination. Check combined findings first: they show where several small gaps add up to a big one.', 'Alles, was den Schutz schwächt – einzeln und in Kombination. Kombinierte Befunde zuerst prüfen: Sie zeigen, wo mehrere kleine Lücken zusammen eine große ergeben.'],
    'f.severity': ['Severity', 'Schweregrad'], 'f.category': ['Category', 'Kategorie'], 'f.finding': ['Finding', 'Befund'], 'f.device': ['Device', 'Gerät'],
    'f.description': ['Description', 'Beschreibung'], 'f.recommendation': ['Recommendation', 'Empfehlung'], 'f.none': ['No open findings.', 'Keine offenen Befunde.'],
    // exclusions
    'x.title': ['Exclusions and allow indicators', 'Exclusions und Allow-Indikatoren'],
    'x.lede': ['Every exclusion is a deliberate blind spot. The rating follows simple rules: the broader, the more writable and the less centrally managed, the riskier. Contextual exclusions and SHA256 indicators count as good practice.', 'Jede Ausnahme ist ein bewusster blinder Fleck. Die Bewertung folgt einfachen Regeln: Je breiter, je beschreibbarer und je weniger zentral verwaltet, desto riskanter. Kontextuelle Exclusions und SHA256-Indikatoren gelten als gute Praxis.'],
    'x.tab.policy': ['In policies', 'In Richtlinien'], 'x.tab.local': ['Local on devices', 'Lokal auf Geräten'], 'x.tab.indicators': ['Allow indicators', 'Allow-Indikatoren'], 'x.tab.edr': ['Affects EDR', 'Wirkt auf EDR'],
    'x.risk': ['Risk', 'Risiko'], 'x.type': ['Type', 'Typ'], 'x.value': ['Value', 'Wert'], 'x.effect': ['Effect', 'Wirkung'], 'x.policy': ['Policy', 'Richtlinie'], 'x.assignment': ['Assignment', 'Zuweisung'],
    'x.platform': ['Platform', 'Plattform'], 'x.onlyGlobal': ['Global (AV+EDR) only', 'Nur Global (AV+EDR)'], 'x.notEffective': ['not effective', 'wirkt nicht'], 'x.unassigned': ['not assigned', 'nicht zugewiesen'],
    'x.rating': ['Rating', 'Bewertung'], 'x.source': ['Source', 'Quelle'], 'x.setting': ['Setting', 'Einstellung'], 'x.modified': ['Last modified', 'Zuletzt geändert'],
    'x.none.policy': ['No exclusions are configured in policies.', 'In den Richtlinien sind keine Exclusions konfiguriert.'],
    'x.local.inv': ['Detected via Advanced Hunting (Windows: registry changes, macOS/Linux: mdatp commands) and the daily device inventory via Intune Remediations. The inventory also captures exclusions older than 30 days.', 'Erkannt über Advanced Hunting (Windows: Registry-Änderungen, macOS/Linux: mdatp-Befehle) und die tägliche Geräte-Inventur über Intune Remediations. Die Inventur erfasst auch Exclusions, die älter als 30 Tage sind.'],
    'x.local.ah': ['Detected via Advanced Hunting: on Windows from registry changes, on macOS and Linux from mdatp commands. Visible are changes from the last 30 days before installation and everything after – older exclusions are only captured by the optional device inventory. Exclusions deployed through a third-party MDM profile (e.g. Jamf) are not visible.', 'Erkannt über Advanced Hunting: unter Windows aus Registry-Änderungen, unter macOS und Linux aus mdatp-Befehlen. Sichtbar sind Änderungen der letzten 30 Tage vor der Installation und alles danach – ältere Exclusions erfasst nur die optionale Geräte-Inventur. Per fremdem MDM-Profil (z. B. Jamf) verteilte Exclusions sind nicht sichtbar.'],
    'x.origin': ['Origin', 'Herkunft'], 'x.setBy': ['Set by', 'Gesetzt von'], 'x.status': ['Status', 'Status'], 'x.onlyPresent': ['Present only', 'Nur vorhandene'],
    'x.present': ['present', 'vorhanden'], 'x.removed': ['removed {0}', 'entfernt {0}'], 'x.detectedBy': ['Detected by', 'Erkannt durch'], 'x.confirmed': ['Last confirmed', 'Zuletzt bestätigt'],
    'x.firstSeen': ['First seen', 'Erstmals gesehen'], 'x.lastChange': ['Last change', 'Letzte Änderung'], 'x.cmd': ['Command line', 'Befehlszeile'], 'x.account': ['Account', 'Konto'],
    'x.none.local': ['No local exclusions detected.', 'Keine lokalen Exclusions erkannt.'], 'x.title.col': ['Title', 'Titel'], 'x.createdBy': ['Created by', 'Erstellt von'], 'x.expires': ['Expires', 'Läuft ab'],
    'x.created': ['Created', 'Erstellt'], 'x.deviceGroups': ['Device groups', 'Gerätegruppen'], 'x.allDevices': ['all devices', 'alle Geräte'], 'x.none.ind': ['No allow indicators.', 'Keine Allow-Indikatoren vorhanden.'],
    'x.edr.lede': ['These exclusions blind not only antivirus but also detection (EDR): global exclusions on Linux (policy or local via “mdatp … --scope global”) and allow indicators. Windows and macOS exclusions only apply to antivirus – EDR still sees the files. Automation folder exclusions and alert tuning rules are not available through a Microsoft API and are not included.', 'Diese Ausnahmen machen nicht nur den Virenschutz blind, sondern auch die Erkennung (EDR): globale Exclusions unter Linux (Richtlinie oder lokal per „mdatp … --scope global“) und Allow-Indikatoren. Windows- und macOS-Exclusions gelten nur für den Virenschutz – EDR sieht die Dateien weiterhin. Automation-Folder-Exclusions und Alert-Tuning-Regeln stellt Microsoft nicht per API bereit; sie sind hier nicht enthalten.'],
    'x.kind': ['Kind', 'Art'], 'x.where': ['Where', 'Wo'], 'x.kind.global': ['Global exclusion', 'Global-Exclusion'], 'x.kind.globalLocal': ['Global exclusion (local)', 'Global-Exclusion (lokal)'],
    'x.kind.ind': ['Allow indicator ({0})', 'Allow-Indikator ({0})'], 'x.where.policy': ['Policy: {0}', 'Richtlinie: {0}'], 'x.where.local': ['Local: {0}', 'Lokal: {0}'], 'x.where.groups': ['Device groups: {0}', 'Gerätegruppen: {0}'],
    'x.none.edr': ['No exclusions that affect EDR.', 'Keine Ausnahmen, die EDR betreffen.'],
    'type.Path': ['Path', 'Pfad'], 'type.TempPath': ['Path (temporary)', 'Pfad (temporär)'], 'type.Process': ['Process', 'Prozess'], 'type.Extension': ['Extension', 'Erweiterung'], 'type.IP': ['IP', 'IP'],
    'type.ASR': ['ASR', 'ASR'], 'type.CFA': ['CFA', 'CFA'], 'type.TamperException': ['Tamper exception', 'Tamper-Ausnahme'], 'type.AllowedThreat': ['Allowed threat', 'Erlaubte Bedrohung'],
    'scope.AV': ['AV', 'AV'], 'scope.Global': ['Global (AV+EDR)', 'Global (AV+EDR)'], 'scope.ASR': ['ASR (all rules)', 'ASR (alle Regeln)'], 'scope.ASRRule': ['ASR: {0}', 'ASR: {0}'], 'scope.CFA': ['Controlled folder access', 'Überwachter Ordnerzugriff'],
    'origin.Local': ['Local', 'Lokal'], 'origin.GPO': ['GPO', 'GPO'], 'origin.Policy': ['Policy', 'Richtlinie'],
    'src.IntuneSettingsCatalog': ['Intune / Security Settings Management', 'Intune / Security Settings Management'], 'src.IntuneTemplate': ['Intune endpoint security template', 'Intune Endpoint-Security-Vorlage'],
    'src.IntuneLegacy': ['Intune device configuration (legacy)', 'Intune Gerätekonfiguration (klassisch)'], 'src.AdvancedHunting': ['Advanced Hunting', 'Advanced Hunting'], 'src.DeviceInventory': ['Device inventory', 'Geräte-Inventur'],
    // devices
    'd.lede': ['The actual state on the devices – regardless of what the policies say.', 'Der tatsächliche Zustand auf den Geräten – unabhängig davon, was in den Richtlinien steht.'],
    'd.device': ['Device', 'Gerät'], 'd.platform': ['Platform', 'Plattform'], 'd.group': ['Device group', 'Gerätegruppe'], 'd.onlyIssues': ['Devices with issues only', 'Nur Geräte mit Auffälligkeiten'],
    'd.mode': ['Mode', 'Modus'], 'd.tamper': ['Tamper', 'Tamper'], 'd.rtp': ['Real-time', 'Echtzeit'], 'd.cloud': ['Cloud', 'Cloud'], 'd.bm': ['Behavior', 'Verhalten'], 'd.pua': ['PUA', 'PUA'],
    'd.asrBelow': ['ASR below target', 'ASR unter Soll'], 'd.local': ['Local exclusions', 'Lokale Exclusions'], 'd.policyExcl': ['Intune exclusions', 'Intune-Exclusions'], 'd.os': ['Operating system', 'Betriebssystem'], 'd.lastSeen': ['Last seen', 'Zuletzt gesehen'],
    'd.sig': ['Signatures up to date', 'Signaturen aktuell'], 'd.plat': ['Platform up to date', 'Plattform aktuell'], 'd.alerts': ['Exclusion alerts (30 days)', 'Exclusion-Alerts (30 Tage)'],
    'd.checks': ['All checks', 'Alle Prüfungen'], 'd.asr': ['ASR rules', 'ASR-Regeln'], 'd.none': ['No devices found. Is Defender for Endpoint with Advanced Hunting active?', 'Keine Geräte gefunden. Ist Defender for Endpoint mit Advanced Hunting aktiv?'],
    'mode.Active': ['Active', 'Aktiv'], 'mode.Passive': ['Passive', 'Passiv'], 'mode.SxSPassive': ['SxS passive', 'SxS passiv'], 'mode.EdrBlock': ['EDR in block mode', 'EDR im Blockmodus'], 'mode.Unknown': ['Unknown', 'Unbekannt'],
    // baseline
    'b.title': ['MDAV baseline', 'MDAV-Baseline'],
    'b.lede': ['Three levels per check: what is recommended (target), what is configured in Intune and what actually applies on the devices. Basis: {0} ({1}).', 'Drei Ebenen je Prüfung: was empfohlen ist (Soll), was in Intune konfiguriert ist und was auf den Geräten tatsächlich gilt. Grundlage: {0} ({1}).'],
    'b.src.default': ['Wardline default', 'Wardline-Standard'], 'b.src.custom': ['custom baseline (storage)', 'kundeneigene Baseline (Storage)'],
    'b.weight': ['Weight', 'Gewicht'], 'b.check': ['Check', 'Prüfung'], 'b.target': ['Target', 'Soll'], 'b.status': ['Status', 'Status'], 'b.devices': ['Devices', 'Geräte'],
    'b.devCount': ['{0} ok, {1} deviating', '{0} ok, {1} abweichend'], 'b.why': ['Why', 'Warum'], 'b.fix': ['How to fix', 'So beheben'], 'b.configuredIn': ['Configured in', 'Konfiguriert in'],
    'b.noPolicy': ['no policy', 'keiner Richtlinie'], 'b.meets': ['meets target', 'entspricht Soll'], 'b.deviates': ['deviates', 'weicht ab'], 'b.notAssigned': [' (not assigned, not effective)', ' (nicht zugewiesen, wirkt nicht)'],
    'b.setting': ['Setting', 'Einstellung'], 'b.deviceOnly': ['device state only', 'nur Gerätezustand'], 'b.seen': ['{0} Defender settings found in policies (to verify the baseline)', '{0} Defender-Einstellungen in Richtlinien gefunden (zum Abgleich der Baseline)'],
    'st.OK': ['OK', 'OK'], 'st.Deviation': ['Deviation', 'Abweichung'], 'st.NotConfigured': ['Not configured', 'Nicht konfiguriert'], 'st.NotAssigned': ['Not assigned', 'Nicht zugewiesen'],
    'st.Inconsistent': ['Inconsistent', 'Uneinheitlich'], 'st.DeviceDeviation': ['Deviation on devices', 'Abweichung am Gerät'], 'st.NoData': ['No data', 'Keine Daten'], 'st.NotRelevant': ['Not relevant', 'Nicht relevant'], 'st.Default': ['Default (not weakened)', 'Standard (nicht abgeschwächt)'],
    'st.Conflict': ['Conflict', 'Konflikt'], 'st.BelowTarget': ['Configured below target', 'Unter Soll konfiguriert'], 'st.NoDeviceData': ['No device data', 'Keine Gerätedaten'], 'st.BlockRecommended': ['Target met, block recommended', 'Soll erfüllt, Block empfohlen'],
    // ASR
    'a.lede': ['Three levels per rule: target (baseline), what is configured in Intune and which mode actually applies on the devices – overall, per Defender device group and per device.', 'Pro Regel drei Ebenen: Soll (Baseline), was in Intune konfiguriert ist, und welcher Modus auf den Geräten tatsächlich wirkt – gesamt, pro Defender-Gerätegruppe und pro Gerät.'],
    'a.none': ['No ASR data yet. Available after the next run.', 'Noch keine ASR-Daten. Nach dem nächsten Lauf verfügbar.'],
    'a.tab.rules': ['Rules', 'Regeln'], 'a.tab.groups': ['Device groups', 'Gerätegruppen'], 'a.tab.devices': ['Devices', 'Geräte'], 'a.tab.exclusions': ['ASR exclusions', 'ASR-Ausnahmen'],
    'a.rule': ['Rule', 'Regel'], 'a.configured': ['Configured', 'Konfiguriert'], 'a.effective': ['Effective on devices', 'Effektiv auf Geräten'], 'a.target2': ['min. {0}, goal {1}', 'mind. {0}, Ziel {1}'],
    'a.noDeviceData': ['no device data', 'keine Gerätedaten'], 'a.guid': ['Rule GUID', 'Regel-GUID'], 'a.note': ['Note', 'Hinweis'], 'a.policies': ['Policies', 'Richtlinien'],
    'a.belowByGroup': ['Below target by device group', 'Unter Soll nach Gerätegruppe'], 'a.devicesN': ['{0}: {1} device(s)', '{0}: {1} Gerät(e)'], 'a.naUnknown': ['Not applicable / unknown', 'Nicht anwendbar / unbekannt'],
    'a.groups.lede': ['Device groups from Defender for Endpoint (MachineGroup). The assignment of the Intune policies is shown in the rule view.', 'Gerätegruppen aus Defender for Endpoint (MachineGroup). Die Zuweisung der Intune-Richtlinien steht in der Regel-Ansicht.'],
    'a.groupOpt': ['{0} ({1} devices, {2} below target)', '{0} ({1} Geräte, {2} unter Soll)'], 'a.modeInGroup': ['Mode in the group', 'Modus in der Gruppe'], 'a.below': ['Below target', 'Unter Soll'],
    'a.noGroups': ['No Windows devices with ASR data.', 'Keine Windows-Geräte mit ASR-Daten.'], 'a.onlyBelow': ['Devices below target only', 'Nur Geräte unter Soll'], 'a.block': ['Block', 'Block'],
    'a.noWin': ['No Windows devices found.', 'Keine Windows-Geräte gefunden.'], 'a.appliesTo': ['Applies to', 'Gilt für'], 'a.noExcl': ['No ASR exclusions.', 'Keine ASR-Ausnahmen.'], 'a.targetN': ['Target {0}', 'Soll {0}'],
    'a.ownGroup': ['(no group)', '(ohne Gruppe)'],
    'asr.Block': ['Block', 'Block'], 'asr.Warn': ['Warn', 'Warnen'], 'asr.Audit': ['Audit', 'Audit'], 'asr.Off': ['Off', 'Aus'],
    // agents
    'g.title': ['AI agents (beta)', 'KI-Agents (Beta)'],
    'g.beta': ['Beta: Entra Agent ID and Agent 365 are new and their APIs still change. This module is tested against the public API contracts, not yet against a fully licensed tenant – treat the data as indicative and report gaps.', 'Beta: Entra Agent ID und Agent 365 sind neu, ihre APIs ändern sich noch. Dieses Modul ist gegen die öffentlichen API-Verträge getestet, noch nicht gegen einen voll lizenzierten Mandanten – die Daten als Hinweis verstehen und Lücken melden.'],
    'g.lede': ['Cloud agents (Copilot Studio, Foundry, custom) with blueprint, agent identity and agent user – and local agents running on endpoints (coding assistants, IDE extensions). Conditional Access is rated separately for the agent identity and the agent user: a policy for one does not apply to the other, and “All users” does not include agent users.', 'Cloud-Agents (Copilot Studio, Foundry, eigene) mit Blueprint, Agent-Identität und Agent-User – und lokale Agents auf Endgeräten (Coding-Assistenten, IDE-Erweiterungen). Conditional Access wird für Agent-Identität und Agent-User getrennt bewertet: Eine Richtlinie für das eine gilt nicht für das andere, und „Alle Benutzer“ schließt Agent-User nicht ein.'],
    'g.secdef': ['Security defaults are enabled – Conditional Access is not evaluated.', 'Sicherheitsstandards (Security Defaults) sind aktiv – Conditional Access wird nicht ausgewertet.'],
    'g.tab.cloud': ['Cloud agents ({0})', 'Cloud-Agents ({0})'], 'g.tab.local': ['Local agents ({0})', 'Lokale Agents ({0})'],
    'g.agent': ['Agent', 'Agent'], 'g.bpId': ['Blueprint ID', 'Blueprint-ID'], 'g.agentId': ['Agent ID', 'Agent-ID'], 'g.userId': ['Agent user ID', 'Agent-User-ID'],
    'g.caAgent': ['CA agent', 'CA Agent'], 'g.caUser': ['CA agent user', 'CA Agent-User'], 'g.noUser': ['no agent user', 'kein Agent-User'], 'g.disabled': ['disabled', 'deaktiviert'],
    'g.onlyOpen': ['Unprotected only', 'Nur ohne Schutz'], 'g.blueprint': ['Blueprint', 'Blueprint'], 'g.bpInvisible': ['not visible in this tenant', 'im Mandanten nicht sichtbar'],
    'g.bpObj': ['Blueprint object ID / principal', 'Blueprint-Objekt-ID / Principal'], 'g.agentApp': ['Agent app ID', 'Agent-App-ID'], 'g.agentUser': ['Agent user', 'Agent-User'],
    'g.sponsors': ['Sponsors', 'Sponsoren'], 'g.sources': ['Sources', 'Quellen'], 'g.defStatus': ['Status (Defender)', 'Status (Defender)'], 'g.created': ['Created', 'Erstellt'],
    'g.caPolAgent': ['CA policies (agent)', 'CA-Richtlinien Agent'], 'g.caPolUser': ['CA policies (agent user)', 'CA-Richtlinien Agent-User'], 'g.excluded': ['excluded', 'ausgenommen'],
    'g.none.cloud': ['No cloud agents found. Entra Agent ID and Agent 365 require the corresponding licences.', 'Keine Cloud-Agents gefunden. Für Entra Agent ID und Agent 365 sind die entsprechenden Lizenzen nötig.'],
    'g.local.lede': ['Local agents run with the rights of the signed-in user – Conditional Access does not apply to them. What matters is the device and the agent’s configuration: auto-approve, MCP servers and whether the process is trusted.', 'Lokale Agents laufen mit den Rechten des angemeldeten Benutzers – Conditional Access greift für sie nicht. Entscheidend sind das Gerät und die Konfiguration des Agents: Auto-Approve, MCP-Server und ob der Prozess vertrauenswürdig ist.'],
    'g.vendor': ['Vendor', 'Hersteller'], 'g.device': ['Device', 'Gerät'], 'g.user': ['User', 'Benutzer'], 'g.autoApprove': ['Auto-approve', 'Auto-Approve'], 'g.mcp': ['MCP servers', 'MCP-Server'],
    'g.mcpUnpinned': ['{0} ({1} unpinned)', '{0} ({1} ohne feste Version)'], 'g.deviceState': ['Device state', 'Gerätezustand'], 'g.tamperOff': ['Tamper off', 'Tamper aus'], 'g.localExcl': ['{0} local excl.', '{0} lokale Excl.'],
    'g.deviceOk': ['ok', 'ok'], 'g.onlyAuto': ['Auto-approve only', 'Nur mit Auto-Approve'], 'g.process': ['Process', 'Prozess'], 'g.trusted': ['Trusted process', 'Vertrauenswürdiger Prozess'],
    'g.version': ['Version', 'Version'], 'g.mcpList': ['MCP servers', 'MCP-Server'], 'g.devGroup': ['Device group', 'Gerätegruppe'], 'g.avMode': ['Defender mode', 'Defender-Modus'], 'g.asrBelow': ['ASR rules below target', 'ASR-Regeln unter Soll'],
    'g.model': ['Model', 'Modell'], 'g.owners': ['Owners', 'Besitzer'], 'g.guardrails': ['Guardrails', 'Guardrails'], 'g.tools': ['Tools / data sources', 'Tools / Datenquellen'], 'g.endpoints': ['Endpoints', 'Endpoints'], 'g.external': ['external', 'extern'],
    'g.connected': ['Connected agents', 'Verbundene Agents'], 'g.channels': ['Channels', 'Kanäle'], 'g.sharedWith': ['Shared with (entries)', 'Geteilt mit (Einträge)'], 'g.permissions': ['Permissions (entries)', 'Berechtigungen (Einträge)'], 'g.instances': ['Instances', 'Instanzen'],
    'g.none.local': ['No local agents found. Defender reports them in AgentsInfo (Advanced Hunting).', 'Keine lokalen Agents gefunden. Defender meldet sie in AgentsInfo (Advanced Hunting).'],
    'g.blueprints': ['Blueprints', 'Blueprints'], 'g.bpAppId': ['Blueprint ID (app ID)', 'Blueprint-ID (App-ID)'], 'g.publisher': ['Publisher', 'Herausgeber'], 'g.agents': ['Agents', 'Agents'],
    'g.unpinned': ['unpinned', 'ohne feste Version'],
    'ca.Protected': ['Protected', 'Geschützt'], 'ca.ReportOnly': ['Report-only', 'Nur Report-only'], 'ca.Excluded': ['Excluded', 'Ausgenommen'], 'ca.Unclear': ['Unclear (attribute filter)', 'Unklar (Attributfilter)'],
    'ca.NotCovered': ['Not covered', 'Nicht abgedeckt'], 'ca.SecurityDefaults': ['Security defaults on', 'Sicherheitsstandards aktiv'], 'ca.NoAgentId': ['No Entra Agent ID', 'Keine Entra Agent ID'],
    'ca.IdentityMissing': ['Agent identity missing', 'Agent-Identität fehlt'], 'ca.UserContext': ['User context', 'Benutzerkontext'],
    'via.AllAgentIdentities': ['All agent identities', 'Alle Agent-Identitäten'], 'via.Direct': ['Assigned directly', 'Direkt zugewiesen'], 'via.Blueprint': ['Via blueprint', 'Über Blueprint'],
    'via.AttributeFilter': ['Attribute filter', 'Attributfilter'], 'via.AllAgentUsers': ['All agent users', 'Alle Agent-User'],
    'pst.Enabled': ['On', 'Aktiv'], 'pst.ReportOnly': ['Report-only', 'Report-only'], 'pst.Disabled': ['Off', 'Deaktiviert'],
    'ctl.block': ['Block', 'Blockieren'], 'ctl.mfa': ['MFA', 'MFA'], 'ctl.compliantDevice': ['Compliant device', 'Konformes Gerät'], 'ctl.domainJoinedDevice': ['Hybrid joined device', 'Hybrid-Gerät'],
    'ctl.compliantNetwork': ['Compliant network', 'Konformes Netzwerk'], 'ctl.none': ['No grant control', 'Keine Gewährungssteuerung'], 'ctl.and': [' and ', ' und '], 'ctl.or': [' or ', ' oder '],
    'ctl.risk': [' (only at agent risk: {0})', ' (nur bei Agent-Risiko: {0})'],
    'tg.AllAgentIdentities': ['All agent identities', 'Alle Agent-Identitäten'], 'tg.SomeAgentIdentities': ['{0} agent identit(ies)/blueprint(s)', '{0} Agent-Identität(en)/Blueprint(s)'],
    'tg.AttributeFilter': ['Attribute filter: {0}', 'Attributfilter: {0}'], 'tg.AllAgentUsers': ['All agent users', 'Alle Agent-User'], 'tg.SomeAgentUsers': ['{0} agent user(s)', '{0} Agent-User'],
    'res.All': ['All resources', 'Alle Ressourcen'], 'res.AllAgentResources': ['All agent resources', 'Alle Agent-Ressourcen'], 'res.n': ['{0} resource(s)', '{0} Ressource(n)'],
    'src.EntraAgentId': ['Entra Agent ID', 'Entra Agent ID'], 'src.Agent365Registry': ['Agent 365 registry', 'Agent 365 Registry'], 'src.Agent365Packages': ['Agent 365 (package catalog)', 'Agent 365 (Paketkatalog)'], 'src.DefenderAgentsInfo': ['Defender (AgentsInfo)', 'Defender (AgentsInfo)'],
    'c.title': ['Conditional Access for agents', 'Conditional Access für Agents'], 'c.lede': ['Policies that target agent identities or agent users – and how many agents they actually cover.', 'Richtlinien, die Agent-Identitäten oder Agent-User adressieren – und wie viele Agents sie tatsächlich erfassen.'],
    'c.policy': ['Policy', 'Richtlinie'], 'c.state': ['State', 'Zustand'], 'c.target': ['Target', 'Ziel'], 'c.excludes': [' (− {0} exclusion(s))', ' (− {0} Ausnahme(n))'], 'c.resources': ['Resources', 'Ressourcen'],
    'c.effect': ['Effect', 'Wirkung'], 'c.covers': ['Covers', 'Erfasst'], 'c.coversN': ['{0} agent(s), {1} agent user(s)', '{0} Agent(s), {1} Agent-User'], 'c.none': ['No Conditional Access policy targets agents.', 'Keine Conditional-Access-Richtlinie adressiert Agents.'],
    'c.weak': ['Not effectively protected', 'Nicht wirksam geschützt'], 'c.weak.lede': ['Agent identities and agent users that are not covered by an enabled policy – report-only counts as unprotected here.', 'Agent-Identitäten und Agent-User, die von keiner aktiven Richtlinie erfasst werden – auch Report-only zählt hier als ungeschützt.'],
    'c.allOk': ['All cloud agents with Entra Agent ID are covered by Conditional Access.', 'Alle Cloud-Agents mit Entra Agent ID sind durch Conditional Access erfasst.'],
    // access (optional module)
    'r.lede': ['Defender XDR unified RBAC: who holds which Defender role – directly, via group, eligible through PIM for groups or requestable via an access package – for which data sources, and when the person last actually used the Defender portal. Device-group scoping for Defender for Endpoint is configured on the device groups page and is not exposed by the API.', 'Defender XDR Unified RBAC: Wer welche Defender-Rolle hat – direkt, über Gruppe, eligible per PIM für Gruppen oder über ein Access Package beantragbar –, für welche Datenquellen, und wann die Person das Defender-Portal zuletzt tatsächlich genutzt hat. Das Gerätegruppen-Scoping für Defender for Endpoint wird auf der Gerätegruppen-Seite konfiguriert und ist per API nicht sichtbar.'],
    'r.person': ['Person', 'Person'], 'r.role': ['Role', 'Rolle'], 'r.platform': ['Platform', 'Plattform'], 'r.state': ['State', 'Zustand'], 'r.path': ['Path', 'Weg'], 'r.scope': ['Data sources', 'Datenquellen'], 'r.ends': ['Ends', 'Endet'],
    'r.onlyPriv': ['Response/config permissions only', 'Nur Response-/Konfigurationsrechte'], 'r.privileged': ['response/config', 'Response/Konfig'], 'r.onlyUnused': ['Never used only', 'Nur nie genutzte'],
    'r.perms': ['Permission groups', 'Berechtigungsgruppen'], 'r.assignment': ['Assignment', 'Zuweisung'], 'r.lastUsed': ['Last used', 'Zuletzt genutzt'], 'r.activated': ['activated {0}', 'aktiviert {0}'],
    'r.usageNote': ['Usage = last interactive sign-in to the Defender portal (security.microsoft.com), observed since {0}; “never used” after {1} days without a sign-in.', 'Nutzung = letzte interaktive Anmeldung am Defender-Portal (security.microsoft.com), beobachtet seit {0}; „nie genutzt“ nach {1} Tagen ohne Anmeldung.'],
    'r.bypass': ['Full access outside unified RBAC', 'Vollzugriff außerhalb von Unified RBAC'],
    'r.bypass.lede': ['These Entra roles keep access to the whole Defender portal regardless of unified RBAC – they do not appear in the role table above.', 'Diese Entra-Rollen behalten Zugriff auf das gesamte Defender-Portal unabhängig von Unified RBAC – in der Rollentabelle oben erscheinen sie nicht.'],
    'r.level': ['Impact', 'Auswirkung'], 'lvl.High': ['Full access', 'Vollzugriff'], 'lvl.Low': ['Read all', 'Alles lesen'],
    'r.none': ['No unified RBAC assignments found. Is unified RBAC activated in the Defender portal (Permissions → Roles)?', 'Keine Unified-RBAC-Zuweisungen gefunden. Ist Unified RBAC im Defender-Portal aktiviert (Berechtigungen → Rollen)?'],
    'au.Used': ['used', 'genutzt'], 'au.Unused': ['never used', 'nie genutzt'], 'au.Unknown': ['no data yet', 'noch keine Daten'],
    'r.open': ['Requestable by large groups', 'Für große Gruppen beantragbar'], 'r.open.lede': ['A whole group of users can request these access packages themselves. Check that approvals and roles match.', 'Diese Access Packages kann ein ganzer Benutzerkreis selbst beantragen. Prüfen Sie, ob Genehmigungen und Rollen dazu passen.'],
    'r.package': ['Access package', 'Access Package'], 'r.policy': ['Policy', 'Richtlinie'], 'r.who': ['Who can request', 'Wer darf beantragen'], 'r.grants': ['Grants', 'Vermittelt'],
    'aud.allMemberUsers': ['all members', 'alle Mitglieder'], 'aud.allDirectoryUsers': ['all users incl. guests', 'alle Benutzer inkl. Gäste'], 'aud.allExternalUsers': ['all external users', 'alle externen Benutzer'], 'aud.allConfiguredConnectedOrganizationUsers': ['connected organisations', 'verbundene Organisationen'],
    'rs.Active': ['Active', 'Aktiv'], 'rs.Activated': ['Active (activated via PIM)', 'Aktiv (per PIM aktiviert)'], 'rs.Eligible': ['Eligible', 'Eligible'], 'rs.Requestable': ['Requestable', 'Beantragbar'],
    'w.lede': ['Pick Defender XDR unified RBAC roles (multiple selection) or search for a person. Shows everyone who has them – directly, via a group, eligible through PIM or requestable via an access package – plus Entra roles that bypass unified RBAC. Free text also matches permissions, e.g. “liveresponse”.', 'Wählen Sie Defender-XDR-Unified-RBAC-Rollen (Mehrfachauswahl) oder suchen Sie eine Person. Gezeigt werden alle, die sie haben – direkt, über Gruppe, eligible per PIM oder über ein Access Package beantragbar –, dazu Entra-Rollen, die Unified RBAC umgehen. Freitext findet auch Berechtigungen, z. B. „liveresponse“.'],
    'w.input': ['Person, group or permission …', 'Person, Gruppe oder Berechtigung …'], 'w.min': ['Enter at least three characters.', 'Mindestens drei Zeichen eingeben.'], 'w.noRole': ['No role or person matches this search.', 'Keine Rolle und keine Person passt zu dieser Suche.'],
    'w.start': ['Pick one or more roles or search for a person.', 'Wählen Sie eine oder mehrere Rollen oder suchen Sie eine Person.'],
    'w.pickRoles': ['Roles (multiple selection)', 'Rollen (Mehrfachauswahl)'], 'w.clear': ['Clear selection', 'Auswahl aufheben'],
    'w.kind': ['Type', 'Art'], 'w.group': ['Group', 'Gruppe'], 'w.user': ['User', 'Benutzer'], 'w.direct': ['Direct', 'Direkt'], 'w.permanent': ['permanent', 'dauerhaft'],
    'w.bypass': ['Includes Entra roles (e.g. Global/Security Administrator) that have every Defender permission regardless of unified RBAC.', 'Enthält Entra-Rollen (z. B. Global/Security Administrator), die unabhängig von Unified RBAC jede Defender-Berechtigung haben.'],
    'w.roles': ['Matching roles: {0}', 'Passende Rollen: {0}'], 'w.nobody': ['Nobody has any of these roles.', 'Niemand hat eine dieser Rollen.'],
    'm.lede': ['Which Defender roles you have now, which you can activate yourself and which you can request.', 'Welche Defender-Rollen Sie jetzt haben, welche Sie selbst aktivieren und welche Sie beantragen können.'],
    'm.active': ['Active', 'Aktiv'], 'm.active.i': ['You have these permissions right now.', 'Diese Rechte haben Sie in diesem Moment.'], 'm.pim': ['Activatable via PIM', 'Per PIM aktivierbar'],
    'm.pim.i': ['You are eligible; the role only takes effect after activation.', 'Sie sind berechtigt; die Rolle wird erst nach Aktivierung wirksam.'], 'm.req': ['Requestable', 'Beantragbar'],
    'm.req.i': ['You can request the role through these access packages.', 'Über diese Access Packages können Sie die Rolle beantragen.'], 'm.none': ['None.', 'Keine.'],
    'm.activate': ['Activate in PIM', 'In PIM aktivieren'], 'm.request': ['Request in My Access', 'In My Access beantragen'], 'm.all': ['Requestable by everyone', 'Für alle beantragbar'],
    'm.all.i': ['These packages are open to all users of your type.', 'Diese Pakete stehen allen Benutzern Ihres Typs offen.'], 'm.until': [' · until {0}', ' · bis {0}'],
    'm.asof': ['Data as of {0}. Changes appear after the next run.', 'Stand der Daten: {0}. Änderungen erscheinen nach dem nächsten Lauf.'],
    // changes
    'ch.lede': ['What changed between two runs. Every run is also kept as a dated snapshot in your company’s storage account.', 'Was sich zwischen zwei Läufen verändert hat. Jeder Lauf wird zusätzlich als datierter Snapshot im Storage Account Ihres Unternehmens aufbewahrt.'],
    'ch.kind': ['Kind', 'Art'], 'ch.area': ['Area', 'Bereich'], 'ch.what': ['What', 'Was'], 'ch.before': ['Before', 'Vorher'], 'ch.after': ['After', 'Nachher'],
    'ch.Added': ['Added', 'Neu'], 'ch.Changed': ['Changed', 'Geändert'], 'ch.Removed': ['Removed', 'Entfernt'], 'ch.Other': ['Not broken down', 'Ohne Aufschlüsselung'],
    'ch.state.present': ['present on device', 'auf dem Gerät vorhanden'], 'ch.state.removed': ['removed', 'entfernt'],
    'ch.chart': ['Changes per day', 'Änderungen pro Tag'], 'ch.day': ['Day', 'Tag'], 'ch.chart.hint': ['Hover a day for details, click it to filter the table.', 'Mouse-over zeigt Details zum Tag, ein Klick filtert die Tabelle.'],
    'ch.areas': ['By area', 'Nach Bereich'],
    'v.license': ['Licence', 'Lizenz'],
    'lic.lede': ['Wardline checks the licence offline – it never calls home. Without a valid licence Wardline runs as Community edition: all checks run, summaries and charts are complete, but every list shows only its first {0} entries in clear – the rest is masked on the server.', 'Wardline prüft die Lizenz offline – es wird nichts nach Hause gemeldet. Ohne gültige Lizenz läuft Wardline als Community-Edition: alle Prüfungen laufen, Zusammenfassungen und Diagramme sind vollständig, aber jede Liste zeigt nur die ersten {0} Einträge im Klartext – der Rest wird serverseitig maskiert.'],
    'lic.community.rows': ['Community edition: {0} of {1} entries shown in clear, the rest is masked.', 'Community-Edition: {0} von {1} Einträgen im Klartext, der Rest ist maskiert.'],
    'lic.community.link': ['Get a licence for the full list.', 'Mit Lizenz die ganze Liste sehen.'], 'lic.community.masked': ['Masked – licence required', 'Maskiert – Lizenz erforderlich'],
    'lic.community.export': ['The export contains only the unmasked entries.', 'Der Export enthält nur die unmaskierten Einträge.'],
    'lic.status': ['Status', 'Status'], 'lic.customer': ['Licensed to', 'Lizenziert für'], 'lic.plan': ['Plan', 'Tarif'], 'lic.expires': ['Valid until', 'Gültig bis'], 'lic.id': ['Licence ID', 'Lizenz-ID'],
    'lic.tenant': ['Tenant', 'Tenant'], 'lic.source': ['Entered', 'Hinterlegt'], 'lic.src.Portal': ['in the portal by {0} on {1}', 'im Portal von {0} am {1}'], 'lic.src.AppSetting': ['at installation (-LicenseKey)', 'bei der Installation (-LicenseKey)'],
    'lic.enter': ['Enter licence key', 'Lizenzschlüssel eingeben'], 'lic.key': ['Licence key (starts with WL1.)', 'Lizenzschlüssel (beginnt mit WL1.)'], 'lic.save': ['Save licence', 'Lizenz speichern'],
    'lic.saved': ['Licence saved.', 'Lizenz gespeichert.'], 'lic.buy': ['Get a licence', 'Lizenz erwerben'], 'lic.days': ['{0} days left', 'noch {0} Tage'],
    'lic.st.None': ['No licence (Community edition)', 'Keine Lizenz (Community-Edition)'], 'lic.st.Valid': ['Valid', 'Gültig'], 'lic.st.ExpiringSoon': ['Expires soon', 'Läuft bald ab'],
    'lic.st.Expired': ['Expired', 'Abgelaufen'], 'lic.st.Invalid': ['Invalid key', 'Ungültiger Schlüssel'], 'lic.st.WrongTenant': ['Key belongs to another tenant', 'Schlüssel gehört zu einem anderen Tenant'],
    'lic.plan.Monthly': ['Monthly', 'Monatlich'], 'lic.plan.Annual': ['Annual', 'Jährlich'], 'lic.plan.Assessment': ['Assessment', 'Assessment'], 'lic.plan.Pilot': ['Pilot', 'Pilot'], 'lic.plan.Partner': ['Partner', 'Partner'],
    'lic.side': ['Licence: {0}', 'Lizenz: {0}'],
    'lic.n.None': ['Wardline runs as Community edition without a licence key: lists show the first {0} entries, the rest is masked.', 'Wardline läuft ohne Lizenzschlüssel als Community-Edition: Listen zeigen die ersten {0} Einträge, der Rest ist maskiert.'],
    'lic.n.ExpiringSoon': ['The Wardline licence expires in {0} days.', 'Die Wardline-Lizenz läuft in {0} Tagen ab.'],
    'lic.n.Expired': ['The Wardline licence expired on {0}. After 30 days Wardline falls back to the Community edition – please renew.', 'Die Wardline-Lizenz ist am {0} abgelaufen. Nach 30 Tagen fällt Wardline auf die Community-Edition zurück – bitte verlängern.'],
    'lic.n.Invalid': ['The Wardline licence key is not valid – Community edition.', 'Der Wardline-Lizenzschlüssel ist ungültig – Community-Edition.'], 'lic.n.WrongTenant': ['The Wardline licence key belongs to another tenant – Community edition.', 'Der Wardline-Lizenzschlüssel gehört zu einem anderen Tenant – Community-Edition.'],
    'lic.n.action': ['Licence …', 'Lizenz …'],
    'chart.more': ['+ {0} more', '+ {0} weitere'], 'chart.total': ['Total: {0}', 'Gesamt: {0}'], 'chart.on': ['On', 'An'], 'chart.off': ['Off', 'Aus'],
    'chart.na': ['Not applicable', 'Nicht anwendbar'], 'chart.unknown': ['Unknown', 'Unbekannt'], 'chart.share': ['{0} of {1} devices', '{0} von {1} Geräten'],
    'chart.onShort': ['on', 'an'], 'chart.noRun': ['no run', 'kein Lauf'],
    'd.glance': ['Protection at a glance', 'Schutz auf einen Blick'],
    'd.glance.lede': ['Per Defender feature: on, off or unknown. Hover a segment for the devices, click it to filter the table.', 'Pro Defender-Funktion: an, aus oder unbekannt. Mouse-over zeigt die Geräte, ein Klick filtert die Tabelle.'],
    'd.chartFilter': ['Chart selection', 'Diagramm-Auswahl'], 'd.platforms': ['Platforms', 'Plattformen'], 'd.runmode': ['Antivirus mode', 'Virenschutz-Modus'],
    'd.sensorHealth': ['EDR sensor', 'EDR-Sensor'], 'd.sigs': ['Signatures current', 'Signaturen aktuell'],
    'ov.trend': ['Trend (30 days)', 'Verlauf (30 Tage)'], 'ov.trend.findings': ['Open findings', 'Offene Befunde'], 'ov.trend.drift': ['Changes per day', 'Änderungen pro Tag'],
    'ov.trend.none': ['The trend fills up with every run.', 'Der Verlauf füllt sich mit jedem Lauf.'], 'ov.trend.np': ['Network protection on', 'Netzwerkschutz an'],
    'dv.np.EventsBlock': ['Network protection: derived from block events (no TVM assessment)', 'Netzwerkschutz: aus Block-Ereignissen abgeleitet (keine TVM-Bewertung)'],
    'dv.np.EventsAudit': ['Network protection: only audit events – it runs in audit mode', 'Netzwerkschutz: nur Audit-Ereignisse – läuft im Überwachungsmodus'],
    'ch.none': ['No changes yet. Deviations are recorded here from the second run on.', 'Noch keine Änderungen. Ab dem zweiten Lauf werden Abweichungen hier festgehalten.'],
    'coll.policyExclusions': ['Exclusion (policy)', 'Exclusion (Richtlinie)'], 'coll.localExclusions': ['Exclusion (local)', 'Exclusion (lokal)'], 'coll.indicators': ['Indicator', 'Indikator'],
    'coll.devices': ['Device', 'Gerät'], 'coll.baseline': ['Baseline', 'Baseline'], 'coll.asrRules': ['ASR rule', 'ASR-Regel'], 'coll.asrGroups': ['ASR device group', 'ASR-Gerätegruppe'],
    'coll.findings': ['Finding', 'Befund'], 'coll.entitlements': ['Permission', 'Recht'], 'coll.audiences': ['Open package', 'Offenes Paket'], 'coll.bypass': ['Entra bypass role', 'Entra-Bypass-Rolle'], 'coll.agents': ['Agent', 'Agent'],
    'coll.blueprints': ['Blueprint', 'Blueprint'], 'coll.policies': ['CA policy', 'CA-Richtlinie'], 'coll.coverage': ['Coverage', 'Abdeckung'],
    // categories, coverage, usage
    'cat.Coverage': ['Coverage', 'Abdeckung'], 'cat.Hygiene': ['Hygiene', 'Hygiene'], 'cat.Dependency': ['Dependency', 'Abhängigkeit'], 'cat.Updates': ['Updates', 'Updates'], 'cat.Inventory': ['Inventory', 'Inventar'], 'cat.Fleet': ['Fleet', 'Flotte'], 'cat.LeastPrivilege': ['Least privilege', 'Least Privilege'], 'cat.Response': ['Response', 'Response'], 'cat.Platform': ['macOS / Linux', 'macOS / Linux'],
    'cov.NotOnboarded': ['Not onboarded (Intune device)', 'Nicht onboarded (Intune-Gerät)'], 'cov.CanBeOnboarded': ['Discovered, can be onboarded', 'Erkannt, kann onboarded werden'],
    'cov.SensorInactive': ['Sensor inactive', 'Sensor inaktiv'], 'cov.Misconfigured': ['Sensor misconfigured', 'Sensor falsch konfiguriert'],
    'cov.ImpairedCommunications': ['Impaired communications', 'Eingeschränkte Kommunikation'], 'cov.NoSensorData': ['No sensor data', 'Keine Sensordaten'], 'cov.SensorIssue': ['Sensor problem', 'Sensorproblem'],
    'covsrc.Intune': ['Intune', 'Intune'], 'covsrc.Defender': ['Defender', 'Defender'], 'covsrc.DeviceDiscovery': ['Device discovery', 'Geräteerkennung'],
    'use.Used': ['Activity seen', 'Aktivität gesehen'], 'use.Unused': ['No activity (30 days)', 'Keine Aktivität (30 Tage)'], 'use.NotChecked': ['Not checked', 'Nicht geprüft'],
    'x.usage': ['Activity', 'Aktivität'], 'x.onlyUnused': ['No activity only', 'Nur ohne Aktivität'], 'x.usageHits': ['{0} events, last {1}', '{0} Ereignisse, zuletzt {1}'],
    'x.usage.help': ['Process and file events on any device in the last 30 days (Advanced Hunting). Wildcards and variables are not checked.', 'Prozess- und Dateiereignisse auf allen Geräten in den letzten 30 Tagen (Advanced Hunting). Platzhalter und Variablen werden nicht geprüft.'],
    'ov.coverage': ['devices without full Defender coverage', 'Geräte ohne vollständige Defender-Abdeckung'], 'ov.unused': ['exclusions without activity (30 days)', 'Exclusions ohne Aktivität (30 Tage)'],
    'ov.tampering': ['devices with tampering attempts (30 days)', 'Geräte mit Manipulationsversuchen (30 Tage)'], 'ov.inetHigh': ['internet-facing devices with high exposure', 'internet-exponierte Geräte mit hoher Exposure'], 'ov.inactive': ['devices inactive 90+ days still in inventory', 'Geräte seit 90+ Tagen inaktiv, noch im Inventar'],
    // devices
    'd.tab.devices': ['Devices ({0})', 'Geräte ({0})'], 'd.tab.coverage': ['Coverage gaps ({0})', 'Abdeckungslücken ({0})'],
    'd.np': ['Network prot.', 'Netzwerkschutz'], 'd.open': ['Open device page', 'Geräteseite öffnen'],
    'd.cov.lede': ['Devices Defender for Endpoint does not (fully) protect: Intune-managed devices that never showed up in Defender, onboarded devices with sensor problems and devices found by device discovery.', 'Geräte, die Defender for Endpoint nicht (vollständig) schützt: Intune-verwaltete Geräte, die nie in Defender aufgetaucht sind, onboardete Geräte mit Sensorproblemen und Geräte aus der Geräteerkennung.'],
    'd.cov.status': ['Status', 'Status'], 'd.cov.source': ['Source', 'Quelle'], 'd.cov.user': ['User', 'Benutzer'], 'd.cov.none': ['No coverage gaps found.', 'Keine Abdeckungslücken gefunden.'],
    'd.cov.feature': ['The Intune comparison needs the feature Coverage (Install-Wardline.ps1 -Features …,Coverage).', 'Der Intune-Abgleich braucht die Funktion Coverage (Install-Wardline.ps1 -Features …,Coverage).'],
    // device page
    'dv.back': ['← All devices', '← Alle Geräte'], 'dv.notfound': ['Device not found in the latest run.', 'Gerät im letzten Lauf nicht gefunden.'],
    'd.large': ['Large fleet: {0} devices. The list is searched and filtered on the server; charts show the totals of the last run.', 'Große Flotte: {0} Geräte. Die Liste wird serverseitig gesucht und gefiltert; die Diagramme zeigen die Summen des letzten Laufs.'],
    'd.remote.count': ['{0} devices match – page {1} of {2}', '{0} Geräte passen – Seite {1} von {2}'], 'd.remote.loading': ['Searching…', 'Suche…'], 'd.remote.error': ['Search failed: {0}', 'Suche fehlgeschlagen: {0}'],
    'd.prev': ['← Previous', '← Zurück'], 'd.next': ['Next →', 'Weiter →'], 'f.devicesN': ['{0} devices', '{0} Geräte'],
    'd.cov.truncated': ['Only the first {0} entries are shown here; the export contains this subset.', 'Hier werden nur die ersten {0} Einträge angezeigt; der Export enthält diese Teilmenge.'],
    'dv.protection': ['Protection state', 'Schutzzustand'], 'dv.asr': ['ASR rules on this device', 'ASR-Regeln auf diesem Gerät'], 'dv.local': ['Local exclusions', 'Lokale Exclusions'],
    'dv.policies': ['Policies with exclusions and their assignments', 'Richtlinien mit Exclusions und ihre Zuweisungen'], 'dv.policies.note': ['This list shows only policies that target this device (server-side target resolution). For old snapshots without target IDs, Wardline falls back to a platform filter.', 'Diese Liste zeigt nur Richtlinien, die dieses Gerät tatsächlich targeten (serverseitige Target-Auflösung). Bei alten Snapshots ohne Target-IDs nutzt Wardline als Fallback den Plattform-Filter.'],
    'dv.policies.count': ['Resolved for this device: {0}', 'Für dieses Gerät aufgelöst: {0}'],
    'dv.findings': ['Findings for this device', 'Befunde zu diesem Gerät'], 'dv.agents': ['Local AI agents', 'Lokale KI-Agents'], 'dv.changes': ['Changes', 'Änderungen'],
    'dv.links': ['Open in', 'Öffnen in'], 'dv.defender': ['Defender portal', 'Defender-Portal'], 'dv.intune': ['Intune', 'Intune'],
    'dv.user': ['Last user', 'Letzter Benutzer'], 'dv.join': ['Join type', 'Join-Typ'], 'dv.sensor': ['Sensor health', 'Sensorzustand'], 'dv.exposure': ['Exposure level', 'Gefährdungsstufe'],
    'dv.tags': ['Device tags', 'Geräte-Tags'], 'dv.inet': ['Internet-facing', 'Internet-exponiert'], 'dv.assetValue': ['Asset value', 'Asset-Wert'], 'dv.tvmExcluded': ['Excluded from Vulnerability Management', 'Von Vulnerability Management ausgeschlossen'],
    'dv.tampering': ['Tampering attempts (30 d)', 'Manipulationsversuche (30 T)'], 'dv.troubleshooting': ['Troubleshooting mode (30 d)', 'Troubleshooting-Modus (30 T)'], 'dv.tsActive': ['active now', 'gerade aktiv'], 'dv.clientVersion': ['Sensor version', 'Sensorversion'],
    'dv.thirdParty': ['Third-party AV/EDR', 'Fremd-AV/EDR'], 'ov.thirdParty': ['devices with a third-party AV/EDR product', 'Geräte mit Fremd-AV/EDR-Produkt'], 'd.thirdParty': ['Third-party AV/EDR', 'Fremd-AV/EDR'], 'chart.3pav.1': ['third-party product present', 'Fremdprodukt vorhanden'], 'chart.3pav.0': ['Defender only', 'nur Defender'],
    // licensing (optional module, Defender for Endpoint only)
    'li.lede': ['Indication, not an audit: which Defender plans are purchased and assigned and who holds them. For Defender for Endpoint, Wardline also maps onboarded client devices to users (Intune primary user, Defender logon events) and shows which devices were used in the last {0} days only by people without a plan. Server licences are not visible in Microsoft 365.', 'Indikation, kein Audit: welche Defender-Pläne gekauft und zugewiesen sind und wer sie hält. Für Defender for Endpoint ordnet Wardline zusätzlich onboardete Client-Geräte Benutzern zu (primärer Intune-Benutzer, Defender-Anmeldeereignisse) und zeigt, welche Geräte in den letzten {0} Tagen nur von Personen ohne Plan genutzt wurden. Serverlizenzen sind in Microsoft 365 nicht sichtbar.'],
    'li.skus': ['Purchased plans', 'Gekaufte Pläne'], 'li.sku': ['Product', 'Produkt'], 'li.tier': ['Plan', 'Plan'], 'li.enabled': ['Purchased', 'Gekauft'], 'li.consumed': ['Assigned', 'Zugewiesen'], 'li.free': ['Free', 'Frei'], 'li.over': ['over-assigned', 'überzugewiesen'],
    'li.tier.P2': ['Plan 2', 'Plan 2'], 'li.tier.P1': ['Plan 1', 'Plan 1'], 'li.tier.MDB': ['Defender for Business', 'Defender for Business'], 'li.tier.Server': ['Servers', 'Server'],
    'li.licensedUsers': ['users with an MDE plan', 'Benutzer mit MDE-Plan'], 'li.clients': ['onboarded clients', 'onboardete Clients'], 'li.clientsUnlicensed': ['clients used only by unlicensed users', 'Clients nur von Unlizenzierten genutzt'], 'li.clientsNoUser': ['clients without any user seen', 'Clients ohne erkannten Benutzer'],
    'li.usersNoDevice': ['licensed users without a device', 'lizenzierte Benutzer ohne Gerät'], 'li.usersOver': ['users above {0} devices', 'Benutzer über {0} Geräten'], 'li.servers': ['onboarded servers (separate licence)', 'onboardete Server (separate Lizenz)'], 'li.p1only': ['clients covered by Plan 1 only', 'Clients nur durch Plan 1 abgedeckt'],
    'li.devices': ['Client devices', 'Client-Geräte'], 'li.devices.lede': ['Every onboarded client with the users seen in the window and the best plan among them. “No user” means neither Intune nor the logon events named anyone.', 'Jeder onboardete Client mit den im Zeitraum gesehenen Benutzern und dem besten Plan darunter. „Kein Benutzer“ heißt: weder Intune noch die Anmeldeereignisse nennen jemanden.'],
    'li.state': ['Licence state', 'Lizenzstatus'], 'ls.Licensed': ['Licensed', 'Lizenziert'], 'ls.Unlicensed': ['Unlicensed', 'Unlizenziert'], 'ls.NoUser': ['No user', 'Kein Benutzer'], 'ls.Server': ['Server', 'Server'],
    'li.users': ['Users seen', 'Gesehene Benutzer'], 'li.licensedBy': ['Covered by', 'Abgedeckt durch'], 'li.confidence': ['Mapping', 'Zuordnung'], 'lc.Intune': ['Intune primary user', 'Primärer Intune-Benutzer'], 'lc.Logon': ['Logon events', 'Anmeldeereignisse'], 'lc.LoggedOn': ['Defender logged-on user', 'Angemeldeter Benutzer (Defender)'], 'lc.None': ['–', '–'],
    'li.userTable': ['Licensed users', 'Lizenzierte Benutzer'], 'li.userTable.lede': ['Users with a Defender for Endpoint plan and the onboarded client devices they were seen on.', 'Benutzer mit Defender-for-Endpoint-Plan und die onboardeten Client-Geräte, auf denen sie gesehen wurden.'],
    'li.user': ['User', 'Benutzer'], 'li.deviceCount': ['Devices', 'Geräte'], 'lu.InUse': ['In use', 'In Nutzung'], 'lu.NoDevice': ['No device', 'Kein Gerät'], 'lu.OverLimit': ['Above {0} devices', 'Über {0} Geräten'], 'lu.Disabled': ['Account disabled', 'Konto deaktiviert'],
    'li.onlyUnlicensed': ['Unlicensed only', 'Nur unlizenzierte'], 'li.onlyNoDevice': ['Without device only', 'Nur ohne Gerät'],
    'li.usage': ['Usage', 'Nutzung'], 'lg.Personal': ['Personal', 'Persönlich'], 'lg.Shared': ['Shared', 'Geteilt'], 'lg.Kiosk': ['Kiosk / shared PC', 'Kiosk / Shared PC'], 'lg.VDI': ['Virtual desktop', 'Virtueller Desktop'],
    'li.usage.why': ['Why this usage', 'Warum diese Nutzung'], 'li.distinctUsers': ['Distinct people', 'Unterschiedliche Personen'], 'li.model': ['Hardware model', 'Hardwaremodell'], 'li.serviceAccounts': ['Service / admin accounts (not counted)', 'Dienst-/Admin-Konten (nicht gezählt)'],
    'li.clientsShared': ['shared, kiosk or VDI clients', 'geteilte, Kiosk- oder VDI-Clients'], 'li.clientsNoUserPersonal': ['personal clients without any user seen', 'persönliche Clients ohne erkannten Benutzer'], 'li.svcAccounts': ['service / admin accounts ignored', 'Dienst-/Admin-Konten ignoriert'],
    'li.sharedDeviceCount': ['Shared devices', 'Geteilte Geräte'], 'li.sharedDevices.hint': ['Shared, kiosk and VDI devices the user was seen on – they do not count against the limit.', 'Geteilte, Kiosk- und VDI-Geräte, auf denen der Benutzer gesehen wurde – sie zählen nicht gegen das Limit.'],
    'li.serversTable': ['Servers', 'Server'], 'li.servers.lede': ['Onboarded servers are licensed per server (Defender for Servers via Defender for Cloud, or Defender for Endpoint for Servers). Microsoft Graph does not show these; the count is here so you can reconcile it with Azure.', 'Onboardete Server werden pro Server lizenziert (Defender for Servers über Defender for Cloud oder Defender for Endpoint for Servers). Microsoft Graph zeigt diese nicht; die Zahl steht hier zum Abgleich mit Azure.'],
    'li.caveats': ['Read before acting', 'Vor dem Handeln lesen'], 'li.aggregate': ['User details are pseudonymised in this installation (WL_LICENSING_DETAIL=aggregate).', 'Benutzerdetails sind in dieser Installation pseudonymisiert (WL_LICENSING_DETAIL=aggregate).'],
    'li.none': ['No data.', 'Keine Daten.'], 'li.window': ['Observation window: {0} days · device allowance per user used for the hint: {1}', 'Beobachtungszeitraum: {0} Tage · für den Hinweis verwendete Gerätegrenze pro Benutzer: {1}'],
    'dv.sigver': ['Signature version', 'Signaturversion'], 'dv.engver': ['Engine / platform', 'Engine / Plattform'], 'dv.sigtime': ['Signatures published', 'Signaturen veröffentlicht'],
    'dv.target': ['Target', 'Soll'], 'dv.effective': ['On the device', 'Auf dem Gerät'], 'dv.none': ['None.', 'Keine.'],
    'chk.AntivirusEnabled': ['Antivirus enabled', 'Virenschutz aktiv'], 'chk.RealtimeProtection': ['Real-time protection', 'Echtzeitschutz'], 'chk.BehaviorMonitoring': ['Behavior monitoring', 'Verhaltensüberwachung'],
    'chk.CloudProtection': ['Cloud protection', 'Cloudschutz'], 'chk.PUAProtection': ['PUA protection', 'PUA-Schutz'], 'chk.TamperProtection': ['Tamper protection', 'Manipulationsschutz'],
    'chk.NetworkProtection': ['Network protection', 'Netzwerkschutz'], 'chk.ControlledFolderAccess': ['Controlled folder access', 'Überwachter Ordnerzugriff'], 'chk.EdrBlockMode': ['EDR in block mode', 'EDR im Blockmodus'],
    'chk.AntivirusSignatureVersion': ['Signatures current', 'Signaturen aktuell'], 'chk.AntivirusReporting': ['Antivirus reporting', 'Virenschutz-Reporting'], 'chk.SensorEnabled': ['EDR sensor enabled', 'EDR-Sensor aktiv'],
    'chk.SensorDataCollection': ['Sensor data collection', 'Sensor-Datenerfassung'], 'chk.ImpairedCommunications': ['Sensor communication', 'Sensor-Kommunikation'], 'chk.PassiveModeOff': ['Not in passive mode', 'Nicht im Passivmodus'],
    // accepted risks
    'acc.accept': ['Create exception …', 'Ausnahme erstellen …'], 'acc.save': ['Save exception', 'Ausnahme speichern'], 'acc.cancel': ['Cancel', 'Abbrechen'], 'acc.revoke': ['Revoke', 'Widerrufen'],
    'acc.justification': ['Justification', 'Begründung'], 'acc.owner': ['Owner', 'Verantwortlich'], 'acc.ticket': ['Ticket / change (optional)', 'Ticket / Change (optional)'], 'acc.expires': ['Valid until', 'Gültig bis'],
    'acc.until': ['Accepted until {0}', 'Akzeptiert bis {0}'], 'acc.by': ['by {0}', 'von {0}'], 'acc.saved': ['Risk accepted.', 'Risiko akzeptiert.'], 'acc.revoked': ['Acceptance revoked.', 'Akzeptanz widerrufen.'],
    'acc.hide': ['Hide accepted', 'Akzeptierte ausblenden'], 'acc.tag': ['Accepted', 'Akzeptiert'], 'acc.expired': ['Expired', 'Abgelaufen'], 'acc.revokedTag': ['Revoked', 'Widerrufen'],
    'acc.help': ['Accepted findings and exclusions stay visible but no longer count as open and do not trigger notifications. After the expiry date they are open again.', 'Akzeptierte Befunde und Exclusions bleiben sichtbar, zählen aber nicht mehr als offen und lösen keine Benachrichtigung aus. Nach dem Ablaufdatum sind sie wieder offen.'],
    'acc.title': ['Exceptions & assignments', 'Ausnahmen & Zuweisungen'], 'acc.lede': ['Consciously accepted findings and exclusions – with justification, owner and expiry or unlimited – and who is working on what. The record auditors ask for.', 'Bewusst akzeptierte Befunde und Exclusions – mit Begründung, Verantwortlichem und Ablaufdatum oder unbegrenzt – und wer woran arbeitet. Der Nachweis, nach dem Prüfer fragen.'],
    'acc.tab.list': ['Exceptions', 'Ausnahmen'], 'acc.tab.log': ['Audit log', 'Protokoll'], 'acc.what': ['What', 'Was'], 'acc.status': ['Status', 'Status'], 'acc.active': ['Active', 'Aktiv'],
    'acc.at': ['Accepted', 'Akzeptiert am'], 'acc.action': ['Action', 'Aktion'], 'acc.act.accept': ['accepted', 'akzeptiert'], 'acc.act.revoke': ['revoked', 'widerrufen'], 'acc.none': ['No accepted risks yet.', 'Noch keine akzeptierten Risiken.'],
    'acc.err.just': ['Please give a justification (at least 10 characters).', 'Bitte eine Begründung angeben (mindestens 10 Zeichen).'], 'acc.err.owner': ['Please name an owner.', 'Bitte einen Verantwortlichen angeben.'],
    'acc.kind.finding': ['Finding', 'Befund'], 'acc.kind.exclusion': ['Exclusion', 'Exclusion'], 'demo.readonly': ['Demo: changes are not saved.', 'Demo: Änderungen werden nicht gespeichert.'],
    'acc.noExpiry': ['No expiry (unlimited)', 'Kein Ablaufdatum (unbegrenzt)'], 'acc.unlimited': ['Accepted indefinitely', 'Unbegrenzt akzeptiert'], 'acc.never': ['unlimited', 'unbegrenzt'],
    'acc.section.exception': ['Exception', 'Ausnahme'], 'acc.section.assign': ['Assignment', 'Zuweisung'], 'acc.exceptionHelp': ['An exception documents a consciously accepted risk. Choose a date or make it unlimited; it can be revoked at any time.', 'Eine Ausnahme dokumentiert ein bewusst akzeptiertes Risiko. Mit Datum oder unbegrenzt; sie kann jederzeit widerrufen werden.'],
    // assignments
    'asg.assign': ['Assign …', 'Zuweisen …'], 'asg.save': ['Assign', 'Zuweisen'], 'asg.clear': ['Unassign', 'Zuweisung aufheben'], 'asg.to': ['Assigned to {0}', 'Zugewiesen an {0}'], 'asg.by': ['by {0} on {1}', 'von {0} am {1}'],
    'asg.search': ['Search people, groups or distribution lists – or type an e-mail address', 'Personen, Gruppen oder Verteilerlisten suchen – oder E-Mail-Adresse eingeben'], 'asg.note': ['Note (optional)', 'Notiz (optional)'],
    'asg.useEmail': ['Use e-mail address {0}', 'E-Mail-Adresse {0} verwenden'], 'asg.noResults': ['No matches in the directory.', 'Keine Treffer im Verzeichnis.'], 'asg.searching': ['Searching …', 'Suche …'],
    'asg.dirUnavailable': ['Directory search is not available (permission missing) – you can still enter an e-mail address.', 'Verzeichnissuche nicht verfügbar (Berechtigung fehlt) – eine E-Mail-Adresse kann trotzdem eingegeben werden.'],
    'asg.saved': ['Assigned.', 'Zugewiesen.'], 'asg.cleared': ['Assignment removed.', 'Zuweisung aufgehoben.'], 'asg.err.none': ['Please pick a person, group or e-mail address.', 'Bitte eine Person, Gruppe oder E-Mail-Adresse wählen.'],
    'asg.help': ['Assigned items stay open; the assignee is shown in the findings list and sent with notifications so a flow can e-mail them.', 'Zugewiesene Einträge bleiben offen; die zugewiesene Stelle erscheint in der Befundliste und wird mit Benachrichtigungen mitgesendet, damit ein Flow sie per E-Mail erreichen kann.'],
    'asg.col': ['Assigned to', 'Zugewiesen an'], 'asg.any': ['Assigned (any)', 'Zugewiesen (alle)'], 'asg.none': ['Unassigned', 'Nicht zugewiesen'], 'asg.tab': ['Assignments', 'Zuweisungen'], 'asg.at': ['Assigned on', 'Zugewiesen am'], 'asg.empty': ['No assignments yet.', 'Noch keine Zuweisungen.'],
    'asg.type.user': ['User', 'Benutzer'], 'asg.type.group': ['Group', 'Gruppe'], 'asg.type.distributionList': ['Distribution list', 'Verteilerliste'], 'asg.type.email': ['E-mail', 'E-Mail'],
    'acc.act.assign': ['assigned', 'zugewiesen'], 'acc.act.unassign': ['unassigned', 'Zuweisung aufgehoben'],
    'd.aad': ['Entra device ID', 'Entra-Geräte-ID'], 'v.device': ['Device', 'Gerät'], 'v.accepted': ['Exceptions & assignments', 'Ausnahmen & Zuweisungen'],
    'g.registry.na': ['Neither the Agent 365 package catalog (CopilotPackages.Read.All) nor the legacy registry is available in this tenant (no Agent 365 licence or permission not granted). Agents from Entra Agent ID and Defender are still shown.', 'Weder der Agent-365-Paketkatalog (CopilotPackages.Read.All) noch die alte Registry ist in diesem Tenant verfügbar (keine Agent-365-Lizenz oder Berechtigung nicht erteilt). Agents aus Entra Agent ID und Defender werden weiterhin angezeigt.'],
    'g.registry.legacy': ['Agent 365 data comes from the legacy registry (retired from May 2026). Grant CopilotPackages.Read.All to switch to the Agent 365 package catalog.', 'Agent-365-Daten stammen aus der alten Registry (wird ab Mai 2026 abgeschaltet). CopilotPackages.Read.All erteilen, um auf den Agent-365-Paketkatalog umzustellen.'],
    'g.publisher2': ['Publisher', 'Herausgeber'], 'g.blocked': ['Blocked in the organisation', 'In der Organisation blockiert'], 'g.availability': ['Availability / deployment', 'Verfügbarkeit / Bereitstellung'],
    'ai.title': ['Wardline Assistant', 'Wardline-Assistent'], 'ai.open': ['Ask the assistant', 'Assistent fragen'], 'ai.close': ['Close', 'Schließen'],
    'ai.placeholder': ['Ask about findings, devices or where to find something …', 'Frag nach Befunden, Geräten oder wo etwas zu finden ist …'],
    'ai.send': ['Send', 'Senden'], 'ai.thinking': ['Thinking …', 'Denke nach …'], 'ai.clear': ['New conversation', 'Neue Unterhaltung'],
    'ai.intro': ['I answer from the current Wardline data only – read-only, nothing is changed. Try: “What should I fix first?”, “Why is device X flagged?”, “Where do I see unused exclusions?”', 'Ich antworte nur aus den aktuellen Wardline-Daten – nur lesend, nichts wird geändert. Zum Beispiel: „Was soll ich zuerst beheben?“, „Warum ist Gerät X markiert?“, „Wo sehe ich ungenutzte Exclusions?“'],
    'ai.failed': ['The assistant could not answer: {0}', 'Der Assistent konnte nicht antworten: {0}'], 'ai.disclaimer': ['AI-generated via Azure OpenAI in your subscription from your snapshot, live Defender Advanced Hunting data and the Wardline docs. Verify before acting.', 'KI-generiert über Azure OpenAI in Ihrer Subscription aus Ihrem Snapshot, Live-Daten aus Defender Advanced Hunting und der Wardline-Dokumentation. Vor dem Handeln prüfen.'],
    'ai.tools': ['Looked up', 'Nachgeschlagen'], 'ai.sources': ['Sources', 'Quellen'],
    'ai.enterprise': ['The assistant is an Enterprise feature: it reads your findings, queries Defender live and searches the Wardline docs. Enter an Enterprise licence key to use it.', 'Der Assistent ist ein Enterprise-Feature: Er liest Ihre Findings, fragt Defender live ab und durchsucht die Wardline-Doku. Geben Sie einen Enterprise-Lizenzschlüssel ein, um ihn zu nutzen.']
  };
  function t(key, ...args) {
    const v = L[key];
    let s = v ? v[lang === 'de' ? 1 : 0] : key;
    args.forEach((a, i) => { s = s.split(`{${i}}`).join(String(a)); });
    return s;
  }
  /** Bilingual text from the back end ({ en, de }) or a plain string. */
  function tx(v) {
    if (v === null || v === undefined) return '';
    if (typeof v === 'object' && !Array.isArray(v)) return v[lang] || v.en || v.de || '';
    return String(v);
  }
  /** Translated code with fallback to the code itself (e.g. new values from a newer back end). */
  const code = (prefix, c) => (c && L[`${prefix}.${c}`]) ? t(`${prefix}.${c}`) : (c || '–');
  /** Assignment and path texts from the back end ("Group: X", "Excluded: X" …) in German. */
  function assignText(s) {
    if (lang !== 'de' || !s) return s || '';
    return String(s).replace(/^All devices$/, 'Alle Geräte').replace(/^All users$/, 'Alle Benutzer').replace(/^Group: /, 'Gruppe: ').replace(/^Excluded: /, 'Ausgeschlossen: ')
      .replace(/^direct$/, 'direkt').replace(/^PIM for groups: /, 'PIM für Gruppen: ').replace(/^Access package: /, 'Access Package: ').replace(/\(assigned/, '(zugewiesen').replace(/in package/, 'im Paket').replace(/via group/, 'über Gruppe');
  }

  const SEV = ['Critical', 'High', 'Medium', 'Low'];
  const SEV_VAR = { Critical: '--sev-krit', High: '--sev-hoch', Medium: '--sev-mittel', Low: '--sev-niedrig' };
  const state = { me: null, endpoint: null, agents: null, access: null, licensing: null, mine: null, changes: {}, runs: null, view: null, acceptances: null, assignments: null };
  const modules = () => arr(state.me && state.me.modules).length ? arr(state.me.modules) : ['endpoint', 'agents'];
  const hasMod = (m) => modules().includes(m);

  // ---------- DOM helpers ----------
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'style') el.style.cssText = v; // CSSOM instead of an attribute: CSP-compliant without 'unsafe-inline'
        else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const $ = (sel) => document.querySelector(sel);
  const fmtDate = (s) => { if (!s) return '–'; const d = new Date(s); return isNaN(d) ? String(s) : d.toLocaleString(locale(), { dateStyle: 'medium', timeStyle: 'short' }); };
  const fmtDay = (s) => { if (!s) return '–'; const d = new Date(s); return isNaN(d) ? String(s) : d.toLocaleDateString(locale(), { dateStyle: 'medium' }); };
  const num = (n) => Number(n || 0).toLocaleString(locale());
  const arr = (x) => Array.isArray(x) ? x : (x === null || x === undefined ? [] : [x]);
  const sevRank = (s) => { const i = SEV.indexOf(s); return i < 0 ? 9 : i; };

  function toast(msg) {
    const el = $('#toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.remove('show'), 4500);
  }

  async function api(path, opts = {}) {
    // Demo mode (dist/demo): data comes from demo-data.js instead of the API.
    if (window.WARDLINE_DEMO) {
      const d = window.WARDLINE_DEMO;
      const key = path.split('?')[0];
      if (key === 'run') return { message: t('demo.run') };
      if (opts.method === 'POST') return { message: t('demo.readonly') };
      if (key === 'changes') return d.changes || [];
      if (key === 'devices' || key === 'device') return demoDevices(path, d);
      if (key in d) return d[key];
      const e = new Error('No data'); e.status = 404; throw e;
    }
    const res = await fetch(`api/${path}`, { ...opts, credentials: 'same-origin', referrerPolicy: 'same-origin', headers: { 'X-Wardline': '1', ...(opts.headers || {}) } });
    if (res.status === 401) { location.href = '/.auth/login/aad?post_login_redirect_uri=' + encodeURIComponent(location.pathname + location.hash); throw new Error(t('not.signed.in')); }
    let body = null;
    try { body = await res.json(); } catch { body = null; }
    if (!res.ok) { const e = new Error((body && body.message) || `HTTP ${res.status}`); e.status = res.status; throw e; }
    return body;
  }

  // ---------- Cells ----------
  function sevCell(s) { return h('span', { class: `sev sev-${s}` }, s ? code('sev', s) : '–'); }
  function checkCell(v) {
    if (v === 'GOOD') return h('span', { class: 'state good' }, t('ok'));
    if (v === 'BAD') return h('span', { class: 'state bad' }, t('problem'));
    if (v === 'N/A') return h('span', { class: 'muted' }, t('na'));
    return h('span', { class: 'muted' }, '–');
  }
  const typeText = (r) => code('type', r.type);
  const scopeText = (r, catalog) => r.scope === 'ASR' && r.asrRule ? t('scope.ASRRule', (catalog && catalog[r.asrRule]) || r.asrRule) : code('scope', r.scope || 'AV');
  const reasons = (risk) => list(arr(risk && risk.reasons).map(tx));

  function csvExport(name, columns, rows) {
    const esc = (v) => { const s = v === null || v === undefined ? '' : String(v); return /[";\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const lines = [columns.map(c => esc(c.title)).join(';')].concat(rows.map(r => columns.map(c => esc(c.csv ? c.csv(r) : c.text ? c.text(r) : '')).join(';')));
    const blob = new Blob(['﻿' + lines.join('\n')], { type: 'text/csv;charset=utf-8' });
    const a = h('a', { href: URL.createObjectURL(blob), download: `${name}-${new Date().toISOString().slice(0, 10)}.csv` });
    document.body.append(a); a.click(); a.remove();
  }

  /** Community edition: rows beyond the first N arrive masked from the server (_masked = true). */
  const isMasked = (r) => !!(r && r._masked);
  const communityRows = () => (state.me && state.me.tier === 'Community' && Number(state.me.communityRows)) || 0;
  function communityNotice(rows, total, clear) {
    const n = rows.filter(isMasked).length;
    if (!n && total === undefined) return null;
    const all = total || rows.length;
    const shown = clear !== undefined ? Math.min(clear, all) : all - n;
    return h('div', { class: 'community-note', role: 'note' }, t('lic.community.rows', num(shown), num(all)), ' ', h('a', { href: '#/license' }, t('lic.community.link')), ' ', h('span', { class: 'muted' }, t('lic.community.export')));
  }
  function maskRow(tr) { tr.classList.add('masked'); tr.classList.remove('clickable'); tr.removeAttribute('tabindex'); tr.title = t('lic.community.masked'); tr.setAttribute('aria-label', t('lic.community.masked')); }
  const maskedLast = (sort) => (a, b) => (isMasked(a) - isMasked(b)) || (sort ? sort(a, b) : 0);

  /** Table with search, optional filters, detail row and CSV export. */
  function dataTable({ name, columns, rows, search, filters = [], detail, empty, sort, rowClass }) {
    const wrap = h('div');
    const q = h('input', { type: 'search', placeholder: t('search'), 'aria-label': t('search.aria') });
    const filterEls = filters.map(f => {
      if (f.type === 'check') { const cb = h('input', { type: 'checkbox' }); cb.checked = !!f.checked; return { f, el: h('label', { class: 'check' }, cb, f.label), input: cb }; }
      const opts = f.options.map(o => (typeof o === 'object' ? o : { value: o, label: f.optionLabel ? f.optionLabel(o) : o }));
      const sel = h('select', { 'aria-label': f.label }, h('option', { value: '' }, `${f.label}: ${t('all')}`), opts.map(o => h('option', { value: o.value }, o.label)));
      return { f, el: sel, input: sel };
    });
    const exportBtn = h('button', { type: 'button' }, t('export.csv'));
    const toolbar = h('div', { class: 'toolbar' }, q, filterEls.map(x => x.el), h('span', { class: 'spacer' }), exportBtn);
    const count = h('div', { class: 'count' });
    const tbody = h('tbody');
    const table = h('table', null, h('thead', null, h('tr', null, columns.map(c => h('th', { scope: 'col' }, c.title)))), tbody);
    const body = h('div');
    const note = h('div');
    wrap.append(toolbar, count, note, body);

    let current = [];
    function apply() {
      const term = q.value.trim().toLowerCase();
      current = rows.filter(r => {
        if (term && !(isMasked(r) || search(r).toLowerCase().includes(term))) return false;
        for (const { f, input } of filterEls) {
          if (f.type === 'check') { if (input.checked && !f.test(r)) return false; }
          else if (input.value && !f.test(r, input.value)) return false;
        }
        return true;
      });
      if (sort || rows.some(isMasked)) current.sort(maskedLast(sort));
      tbody.replaceChildren();
      const max = 1500;
      for (const r of current.slice(0, max)) {
        const tr = h('tr', { class: [detail ? 'clickable' : '', rowClass ? rowClass(r) : ''].join(' ').trim() || null, tabindex: detail ? '0' : null }, columns.map(c => h('td', null, c.cell ? c.cell(r) : c.text(r))));
        if (isMasked(r)) maskRow(tr);
        else if (detail) {
          const toggle = () => {
            const next = tr.nextElementSibling;
            if (next && next.classList.contains('detail')) { next.remove(); tr.setAttribute('aria-expanded', 'false'); return; }
            tr.after(h('tr', { class: 'detail' }, h('td', { colspan: columns.length }, h('div', { class: 'detail' }, detail(r)))));
            tr.setAttribute('aria-expanded', 'true');
          };
          tr.setAttribute('aria-expanded', 'false');
          tr.addEventListener('click', toggle);
          tr.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
        }
        tbody.append(tr);
      }
      count.textContent = current.length > max ? t('entries.capped', num(current.length), max) : (current.length === 1 ? t('entry') : t('entries', num(current.length)));
      note.replaceChildren(communityNotice(current) || '');
      body.replaceChildren(current.length ? h('div', { class: 'table-wrap' }, table) : h('div', { class: 'empty' }, rows.length ? t('no.match') : (empty || t('no.entries'))));
    }
    q.addEventListener('input', apply);
    filterEls.forEach(x => x.input.addEventListener('change', apply));
    exportBtn.addEventListener('click', () => csvExport(name, columns, current.filter(r => !isMasked(r))));
    apply();
    return wrap;
  }

  function dl(pairs) {
    return h('dl', null, pairs.filter(p => p && p[1] !== undefined && p[1] !== null && p[1] !== '').map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
  }

  /** Device table for large fleets: search and filters run on the server (api/devices), one page at a time. */
  function remoteDeviceTable({ name, columns, filters = [], detail, empty, fixed = {}, size = 200 }) {
    const wrap = h('div');
    const q = h('input', { type: 'search', placeholder: t('search'), 'aria-label': t('search.aria') });
    const filterEls = filters.map(f => {
      if (f.type === 'check') { const cb = h('input', { type: 'checkbox' }); cb.checked = !!f.checked; return { f, el: h('label', { class: 'check' }, cb, f.label), input: cb }; }
      const opts = f.options.map(o => (typeof o === 'object' ? o : { value: o, label: f.optionLabel ? f.optionLabel(o) : o }));
      const sel = h('select', { 'aria-label': f.label }, h('option', { value: '' }, `${f.label}: ${t('all')}`), opts.map(o => h('option', { value: o.value }, o.label)));
      return { f, el: sel, input: sel };
    });
    const exportBtn = h('button', { type: 'button' }, t('export.csv'));
    const prev = h('button', { type: 'button' }, t('d.prev')), next = h('button', { type: 'button' }, t('d.next'));
    const toolbar = h('div', { class: 'toolbar' }, q, filterEls.map(x => x.el), h('span', { class: 'spacer' }), exportBtn);
    const count = h('div', { class: 'count' });
    const tbody = h('tbody');
    const table = h('table', null, h('thead', null, h('tr', null, columns.map(c => h('th', { scope: 'col' }, c.title)))), tbody);
    const body = h('div');
    const pager = h('div', { class: 'toolbar' }, prev, next);
    const note = h('div');
    wrap.append(toolbar, count, note, body, pager);
    let page = 0, current = [], total = 0, pages = 0, seq = 0, timer = null;
    const params = () => {
      const p = new URLSearchParams({ ...fixed, page: String(page), size: String(size) });
      const term = q.value.trim(); if (term) p.set('q', term);
      for (const { f, input } of filterEls) { if (f.type === 'check') { if (input.checked) p.set(f.key, '1'); } else if (input.value) p.set(f.key, input.value); }
      return p.toString();
    };
    async function load() {
      const my = ++seq;
      count.textContent = t('d.remote.loading');
      let res;
      try { res = await api(`devices?${params()}`); } catch (e) { if (my === seq) { count.textContent = ''; body.replaceChildren(h('div', { class: 'empty' }, t('d.remote.error', e.message))); } return; }
      if (my !== seq) return;
      current = arr(res.rows); total = Number(res.total) || 0; pages = Number(res.pages) || 0;
      tbody.replaceChildren();
      for (const r of current) {
        const tr = h('tr', { class: detail ? 'clickable' : null, tabindex: detail ? '0' : null }, columns.map(c => h('td', null, c.cell ? c.cell(r) : c.text(r))));
        if (isMasked(r)) maskRow(tr);
        else if (detail) {
          const toggle = () => {
            const nx = tr.nextElementSibling;
            if (nx && nx.classList.contains('detail')) { nx.remove(); tr.setAttribute('aria-expanded', 'false'); return; }
            tr.after(h('tr', { class: 'detail' }, h('td', { colspan: columns.length }, h('div', { class: 'detail' }, detail(r)))));
            tr.setAttribute('aria-expanded', 'true');
          };
          tr.setAttribute('aria-expanded', 'false');
          tr.addEventListener('click', toggle);
          tr.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
        }
        tbody.append(tr);
      }
      count.textContent = total ? t('d.remote.count', num(total), num(page + 1), num(pages)) : '';
      note.replaceChildren(res.tier === 'Community' && total > communityRows() ? communityNotice(current, total, communityRows()) : '');
      body.replaceChildren(current.length ? h('div', { class: 'table-wrap' }, table) : h('div', { class: 'empty' }, q.value || filterEls.some(x => x.input.value || x.input.checked) ? t('no.match') : (empty || t('no.entries'))));
      prev.disabled = page <= 0; next.disabled = page + 1 >= pages;
      pager.style.display = pages > 1 ? '' : 'none';
    }
    const restart = () => { page = 0; load(); };
    q.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(restart, 300); });
    filterEls.forEach(x => x.input.addEventListener('change', restart));
    prev.addEventListener('click', () => { if (page > 0) { page--; load(); } });
    next.addEventListener('click', () => { if (page + 1 < pages) { page++; load(); } });
    exportBtn.addEventListener('click', () => csvExport(name, columns, current.filter(r => !isMasked(r))));
    wrap.setFilter = (key, value) => { const x = filterEls.find(f => f.f.key === key); if (x) { x.input.value = value; restart(); } };
    load();
    return wrap;
  }
  function list(items) { return h('ul', null, arr(items).map(i => h('li', null, i))); }
  function tabs(view, items, active) {
    return h('div', { class: 'tabs', role: 'tablist' }, items.map(([id, label]) => h('button', { class: 'tab', role: 'tab', type: 'button', 'aria-selected': String(id === active), onclick: () => { location.hash = `#/${view}?tab=${id}`; } }, label)));
  }

  // ---------- Charts: inline SVG, no library. Labels are always text nodes. ----------
  const SVGNS = 'http://www.w3.org/2000/svg';
  function sv(tag, attrs, ...children) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'style') el.style.cssText = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, String(v));
    }
    for (const c of children.flat(Infinity)) { if (c !== null && c !== undefined && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c))); }
    return el;
  }
  let tipEl = null;
  function showTip(x, y, content) {
    if (!tipEl) { tipEl = h('div', { class: 'chart-tip', role: 'tooltip' }); document.body.append(tipEl); }
    tipEl.replaceChildren(...arr(content).flat().filter(Boolean));
    tipEl.classList.add('show');
    const w = tipEl.offsetWidth, ht = tipEl.offsetHeight, pad = 14;
    let left = x + pad, top = y + pad;
    if (left + w > window.innerWidth - 8) left = x - w - pad;
    if (top + ht > window.innerHeight - 8) top = y - ht - pad;
    tipEl.style.left = `${Math.max(8, left)}px`; tipEl.style.top = `${Math.max(8, top)}px`;
  }
  const hideTip = () => { if (tipEl) tipEl.classList.remove('show'); };
  /** Hover, keyboard focus and click for one chart element. */
  function interactive(el, content, onSelect) {
    el.setAttribute('tabindex', '0');
    el.addEventListener('mousemove', e => showTip(e.clientX, e.clientY, content()));
    el.addEventListener('mouseleave', hideTip);
    el.addEventListener('focus', () => { const r = el.getBoundingClientRect(); showTip(r.right, r.top, content()); });
    el.addEventListener('blur', hideTip);
    if (onSelect) {
      el.classList.add('selectable');
      el.addEventListener('click', () => { hideTip(); onSelect(); });
      el.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); hideTip(); onSelect(); } });
    }
    return el;
  }
  function tipBody(title, lines, items) {
    const max = 8, list = arr(items);
    return [h('b', null, title), ...arr(lines).map(l => h('div', null, l)),
      list.length ? h('ul', null, list.slice(0, max).map(i => h('li', null, i)), list.length > max ? h('li', { class: 'muted' }, t('chart.more', list.length - max)) : null) : null];
  }
  const pct = (a, b) => b ? Math.round((a / b) * 100) : 0;
  /** Width available in the content area (views render off-DOM, so measure #main). */
  function contentWidth() { const m = $('#main'); if (!m || !m.clientWidth) return 940; const cs = getComputedStyle(m); return m.clientWidth - parseFloat(cs.paddingLeft || 0) - parseFloat(cs.paddingRight || 0); }

  /** Donut: segments [{ id, label, value, color, items }]. Hover shows the items (e.g. device names), click selects. */
  function donut({ title, segments, centre, sub, onSelect }) {
    const segs = segments.filter(x => x.value > 0);
    const total = segs.reduce((a, x) => a + x.value, 0);
    const C = 50, R = 46, r = 31;
    const pt = (rad, a) => `${(C + rad * Math.cos(a)).toFixed(2)} ${(C + rad * Math.sin(a)).toFixed(2)}`;
    const arcPath = (a0, a1) => {
      if (a1 - a0 > Math.PI * 2 - 1e-3) { const m = a0 + Math.PI; return `${arcPath(a0, m)}${arcPath(m, a0 + Math.PI * 2)}`; }
      const large = a1 - a0 > Math.PI ? 1 : 0;
      return `M${pt(R, a0)}A${R} ${R} 0 ${large} 1 ${pt(R, a1)}L${pt(r, a1)}A${r} ${r} 0 ${large} 0 ${pt(r, a0)}Z`;
    };
    const svg = sv('svg', { viewBox: '0 0 100 100', class: 'donut', role: 'img', 'aria-label': `${title}: ${segs.map(x => `${x.label} ${x.value}`).join(', ')}` });
    if (!total) svg.append(sv('circle', { cx: C, cy: C, r: (R + r) / 2, fill: 'none', 'stroke-width': R - r, style: 'stroke:var(--rule)' }));
    let a0 = -Math.PI / 2;
    for (const x of segs) {
      const a1 = a0 + (x.value / total) * Math.PI * 2;
      const path = sv('path', { d: arcPath(a0, a1), class: segs.length === 1 ? 'seg full' : 'seg', style: `fill:${x.color}` });
      svg.append(interactive(path, () => tipBody(`${title} · ${x.label}`, [t('chart.share', num(x.value), num(total)) + ` (${pct(x.value, total)} %)`], x.items), onSelect ? () => onSelect(x) : null));
      a0 = a1;
    }
    svg.append(sv('text', { x: C, y: sub ? 50 : 54, 'text-anchor': 'middle', class: 'donut-centre' }, centre === undefined ? num(total) : centre));
    if (sub) svg.append(sv('text', { x: C, y: 63, 'text-anchor': 'middle', class: 'donut-sub' }, sub));
    const legend = h('ul', { class: 'chart-legend' }, segments.filter(x => x.value > 0 || x.always).map(x => {
      const li = h('li', { style: `--c:${x.color}` }, h('span', null, x.label), h('b', null, num(x.value)));
      if (onSelect && x.value > 0) { li.classList.add('selectable'); li.setAttribute('tabindex', '0'); li.addEventListener('click', () => onSelect(x)); li.addEventListener('keydown', e => { if (e.key === 'Enter') onSelect(x); }); }
      return li;
    }));
    return h('figure', { class: 'chart donut-card' }, h('figcaption', { title }, title), svg, legend);
  }

  /** Stacked columns: buckets [{ id, label, title, values: { key: n }, items }]; keys [{ id, label, color }]. */
  function columnChart({ title, buckets, keys, onSelect, note, width = 640 }) {
    const W = Math.round(width), H = Math.round(Math.min(220, Math.max(150, width * 0.3))), padL = 34, padB = 24, padT = 8;
    const sums = buckets.map(b => keys.reduce((a, k) => a + (Number(b.values && b.values[k.id]) || 0), 0));
    const raw = Math.max(1, ...sums);
    const step = Math.pow(10, Math.floor(Math.log10(raw)));
    const max = [1, 2, 2.5, 5, 10].map(m => m * step).find(m => m >= raw) || raw;
    const plotW = W - padL - 4, plotH = H - padB - padT;
    const bw = plotW / Math.max(1, buckets.length);
    const y = v => padT + plotH - (v / max) * plotH;
    const svg = sv('svg', { viewBox: `0 0 ${W} ${H}`, class: 'columns', role: 'img', 'aria-label': `${title}: ${buckets.map((b, i) => `${b.label} ${sums[i]}`).join(', ')}` });
    for (const v of [0, max / 2, max]) {
      svg.append(sv('line', { x1: padL, x2: W - 4, y1: y(v), y2: y(v), class: 'grid' }), sv('text', { x: padL - 6, y: y(v) + 3.5, 'text-anchor': 'end', class: 'axis' }, num(Math.round(v * 10) / 10)));
    }
    const every = Math.ceil(buckets.length / (width < 600 ? 5 : 8));
    buckets.forEach((b, i) => {
      const x = padL + i * bw;
      const g = sv('g', { class: 'col' });
      let acc = 0;
      for (const k of keys) {
        const v = Number(b.values && b.values[k.id]) || 0;
        if (!v) continue;
        g.append(sv('rect', { x: x + bw * 0.15, width: Math.max(1, bw * 0.7), y: y(acc + v), height: Math.max(0.5, y(acc) - y(acc + v)), style: `fill:${k.color}` }));
        acc += v;
      }
      if (b.empty) g.append(sv('line', { x1: x + bw * 0.2, x2: x + bw * 0.8, y1: y(0) - 1, y2: y(0) - 1, class: 'nodata' }));
      const hit = sv('rect', { x, width: bw, y: padT, height: plotH, class: 'hit' });
      g.append(hit);
      interactive(hit, () => tipBody(b.title || b.label, b.empty ? [t('chart.noRun')] : [...keys.filter(k => b.values && b.values[k.id]).map(k => `${k.label}: ${num(b.values[k.id])}`), keys.length > 1 ? t('chart.total', num(sums[i])) : null].filter(Boolean), b.items), onSelect && sums[i] ? () => onSelect(b) : null);
      svg.append(g);
      if (i % every === 0 || (i === buckets.length - 1 && i % every >= every / 2)) svg.append(sv('text', { x: x + bw / 2, y: H - 6, 'text-anchor': 'middle', class: 'axis' }, b.label));
    });
    const legend = h('ul', { class: 'chart-legend inline' }, keys.map(k => h('li', { style: `--c:${k.color}` }, h('span', null, k.label))));
    return h('figure', { class: 'chart columns-card' }, h('figcaption', null, title), svg, legend, note ? h('p', { class: 'muted small' }, note) : null);
  }
  /** Day keys (local yyyy-mm-dd) for the last n days, oldest first. */
  function lastDays(n) {
    const out = [], d = new Date(); d.setHours(12, 0, 0, 0);
    for (let i = n - 1; i >= 0; i--) { const x = new Date(d); x.setDate(d.getDate() - i); out.push(dayKey(x)); }
    return out;
  }
  function dayKey(v) { const d = v instanceof Date ? v : new Date(v); if (isNaN(d)) return ''; return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; }
  const dayShort = (k) => new Date(`${k}T12:00:00`).toLocaleDateString(locale(), { day: 'numeric', month: 'short' });
  const dayLong = (k) => new Date(`${k}T12:00:00`).toLocaleDateString(locale(), { dateStyle: 'full' });
  const DRIFT_KEYS = () => [
    { id: 'Added', label: code('ch', 'Added'), color: 'var(--sev-ok)' },
    { id: 'Changed', label: code('ch', 'Changed'), color: 'var(--sev-mittel)' },
    { id: 'Removed', label: code('ch', 'Removed'), color: 'var(--sev-krit)' }];

  /** Before/after with the differing parts marked (separators ; and , keep their place). */
  function diffParts(before, after) {
    const split = (v) => String(v || '').split(/(;\s*|,\s*)/);
    const sep = (x) => !x || /^[;,]\s*$/.test(x);
    const bag = (parts) => { const m = new Map(); parts.forEach(x => { if (!sep(x)) m.set(x, (m.get(x) || 0) + 1); }); return m; };
    const mark = (parts, other, cls) => parts.map(x => { if (sep(x)) return x; const n = other.get(x) || 0; if (n > 0) { other.set(x, n - 1); return x; } return h('mark', { class: cls }, x); });
    const b = split(before), a = split(after);
    return { before: mark(b, bag(a), 'del'), after: mark(a, bag(b), 'ins') };
  }
  const stateText = (v) => v === 'present' ? t('ch.state.present') : v === 'removed' ? t('ch.state.removed') : (v || '–');
  function changeCells(r) {
    // Added: After shows the new state in green. Removed: Before shows what was there, After says "removed" in red.
    if (r.change === 'Added') return { before: h('span', { class: 'muted' }, '–'), after: h('span', { class: 'diff ins-all' }, stateText(r.after)) };
    if (r.change === 'Removed') return { before: h('span', null, stateText(r.before)), after: h('span', { class: 'diff del-all' }, t('ch.state.removed')) };
    const d = diffParts(r.before, r.after);
    return { before: h('span', { class: 'diff' }, d.before), after: h('span', { class: 'diff' }, d.after) };
  }
  const changeKind = (r) => h('span', { class: `chg chg-${r.change}` }, code('ch', r.change));

  /** Overview: open findings and drift per day over the last 30 days, from the run index. */
  function trendCharts(runs, avail) {
    const chartW = avail && avail > 760 ? (avail - 14) / 2 - 30 : Math.max(340, (avail || 700) - 30);
    const days = lastDays(30);
    const withFindings = runs.filter(r => r.findings && (r.module === 'endpoint' || r.module === 'agents' || r.module === 'access' || r.module === 'licensing'));
    if (!runs.length) return null;
    // Open findings: the last run of each module per day, carried forward over days without a run
    const perModule = {};
    for (const r of [...withFindings].sort((a, b) => String(a.at).localeCompare(String(b.at)))) (perModule[r.module] = perModule[r.module] || {})[dayKey(r.at)] = r.findings;
    const last = {};
    const fBuckets = days.map(k => {
      const values = {}; let any = false;
      for (const m of Object.keys(perModule)) {
        if (perModule[m][k]) last[m] = perModule[m][k];
        else if (!last[m]) { const before = Object.keys(perModule[m]).filter(d => d < k).sort().pop(); if (before) last[m] = perModule[m][before]; }
        if (last[m]) { any = true; for (const sv2 of SEV) values[sv2] = (values[sv2] || 0) + (Number(last[m][sv2]) || 0); }
      }
      return { id: k, label: dayShort(k), title: dayLong(k), values, empty: !any };
    });
    const dBuckets = days.map(k => {
      const values = {}; const mods = {};
      for (const r of runs.filter(x => dayKey(x.at) === k)) {
        const d = r.drift || {};
        let known = 0;
        for (const key of ['Added', 'Changed', 'Removed']) { values[key] = (values[key] || 0) + (Number(d[key]) || 0); known += Number(d[key]) || 0; }
        const rest = Math.max(0, (Number(r.changes) || 0) - known); if (rest) values.Other = (values.Other || 0) + rest;
        if (r.changes) mods[r.module] = (mods[r.module] || 0) + Number(r.changes);
      }
      const top = Object.entries(mods).sort((a, b) => b[1] - a[1])[0];
      return { id: k, label: dayShort(k), title: dayLong(k), values, module: top ? top[0] : 'endpoint', items: Object.entries(mods).map(([m, n]) => `${code('mod', m)}: ${num(n)}`) };
    });
    const out = h('div', { class: 'trend' });
    if (withFindings.length) out.append(columnChart({ width: chartW, title: t('ov.trend.findings'), buckets: fBuckets, keys: SEV.map(x => ({ id: x, label: code('sev', x), color: `var(${SEV_VAR[x]})` })), onSelect: () => { location.hash = '#/findings'; } }));
    out.append(columnChart({
      width: chartW, title: t('ov.trend.drift'), buckets: dBuckets, keys: [...DRIFT_KEYS(), ...(dBuckets.some(b => b.values.Other) ? [{ id: 'Other', label: code('ch', 'Other'), color: 'var(--muted)' }] : [])],
      onSelect: b => { location.hash = `#/changes?module=${b.module}&day=${b.id}`; }
    }));
    if (!withFindings.length) out.append(h('p', { class: 'muted small' }, t('ov.trend.none')));
    return out;
  }

  // ---------- Loading data ----------
  // Demo: the paged device API (search, page, detail) emulated on the inline demo data. ?large in the URL shows the large-fleet view.
  function demoDevices(path, d) {
    const p = new URLSearchParams(path.split('?')[1] || '');
    const all = arr(state.demoDevices || (d.endpoint && d.endpoint.devices));
    if (path.startsWith('device?')) { const x = all.find(r => r.deviceId === p.get('id')); if (!x) { const e = new Error('Device not found.'); e.status = 404; throw e; } return { device: x }; }
    const onOff = (v) => v === 'GOOD' ? 'on' : v === 'BAD' ? 'off' : v === 'N/A' ? 'na' : 'unknown';
    const chartState = (r, id) => id === 'sig' ? (/^(true|1)$/i.test(String(r.signatureUpToDate)) ? 'on' : /^(false|0)$/i.test(String(r.signatureUpToDate)) ? 'off' : 'unknown')
      : id === 'sensor' ? (!r.sensorHealth ? 'unknown' : /^active$/i.test(r.sensorHealth) ? 'on' : 'off')
        : id === 'mode' ? (r.avMode === '0' ? 'Active' : r.avMode === '4' ? 'EdrBlock' : r.avMode === '1' || r.avMode === '2' ? 'Passive' : 'Unknown')
          : id === 'os' ? (r.os || '–') : onOff(r.checks ? r.checks[id] : undefined);
    const issue = r => Object.values(r.checks || {}).includes('BAD') || (r.avMode && r.avMode !== '0') || r.localExclusions > 0 || r.exclusionAlerts > 0 || r.asrBelowMinimum > 0;
    const q = (p.get('q') || '').toLowerCase(), [cid, sid] = (p.get('chart') || '|').split('|');
    const hits = all.filter(r => (!p.get('os') || r.os === p.get('os')) && (!p.get('group') || r.deviceGroup === p.get('group')) && (p.get('issues') !== '1' || issue(r)) && (p.get('asrBelow') !== '1' || r.asrBelowMinimum > 0)
      && (!cid || chartState(r, cid) === sid) && (!q || `${r.deviceName} ${r.os} ${r.deviceGroup || ''} ${r.lastUser || ''}`.toLowerCase().includes(q)))
      .sort((a, b) => (issue(b) - issue(a)) || String(a.deviceName).localeCompare(String(b.deviceName)));
    const size = Math.max(1, Number(p.get('size')) || 200), page = Number(p.get('page')) || 0;
    return { total: hits.length, page, size, pages: Math.ceil(hits.length / size), rows: hits.slice(page * size, (page + 1) * size) };
  }

  // Device collections are stored in pages. Up to INLINE_MAX devices are loaded completely (tables and charts work
  // locally); above that the Devices view switches to server-side search (large fleets with hundreds of thousands of devices).
  const INLINE_MAX = 10000;
  async function loadPages(name, meta, maxPages) {
    const n = Math.min(Number(meta.pages) || 0, maxPages);
    const pages = await Promise.all(Array.from({ length: n }, (_, i) => api(`${name}?page=${i}`).catch(() => [])));
    return pages.flatMap(p => arr(p));
  }
  async function loadEndpoint(force) {
    if (!state.endpoint || force) {
      const ep = await api('endpoint');
      if (!ep.devices && ep.devicesPages) {
        ep.largeFleet = Number(ep.devicesPages.count) > INLINE_MAX;
        if (!ep.largeFleet) ep.devices = await loadPages('devices', ep.devicesPages, 1000);
      }
      if (!ep.coverage && ep.coveragePages) {
        const maxPages = Math.ceil(INLINE_MAX / (Number(ep.coveragePages.pageSize) || 2000));
        ep.coverage = await loadPages('coverage', ep.coveragePages, maxPages);
        ep.coverageTruncated = Number(ep.coveragePages.pages) > maxPages;
      }
      if (window.WARDLINE_DEMO && /[?&]large\b/.test(location.search) && ep.devices && ep.deviceStats) {
        // Demo of the large-fleet view: the list comes from the emulated paged API
        state.demoDevices = ep.devices;
        ep.devicesPages = { count: ep.devices.length, pages: 1, pageSize: 2000 }; ep.largeFleet = true; delete ep.devices;
      }
      state.endpoint = ep;
    }
    return state.endpoint;
  }
  async function loadDevice(ep, id) {
    const local = arr(ep.devices).find(x => x.deviceId === id);
    if (local || !ep.devicesPages) return local || null;
    try { const r = await api(`device?id=${encodeURIComponent(id)}`); return (r && r.device) || null; } catch { return null; }
  }
  async function loadAccess(force) { if (!state.access || force) state.access = await api('access'); return state.access; }
  async function loadLicensing(force) { if (!state.licensing || force) state.licensing = await api('licensing'); return state.licensing; }
  async function loadAgents(force) { if (!state.agents || force) state.agents = await api('agents'); return state.agents; }
  async function loadAcceptances(force) {
    if (!state.acceptances || force) {
      await Promise.all([
        api('acceptances').then(x => { state.acceptances = arr(x.acceptances); }).catch(() => { state.acceptances = []; }),
        api('assignments').then(x => { state.assignments = arr(x.assignments); }).catch(() => { state.assignments = []; })]);
    }
    return state.acceptances;
  }
  const acceptedMap = () => { const m = {}; for (const a of arr(state.acceptances)) if (a.active) m[a.key] = a; return m; };
  const assignedMap = () => { const m = {}; for (const a of arr(state.assignments)) if (a.assignee) m[a.key] = a; return m; };
  const assigneeText = (a) => !a ? '' : a.mail && a.mail !== a.displayName ? `${a.displayName} <${a.mail}>` : (a.displayName || a.mail || '');
  const assigneeChip = (a, onRemove) => h('span', { class: `chip chip-${a.type}` }, h('span', { class: 'chip-type' }, t(`asg.type.${a.type}`) || a.type), ' ', a.displayName || a.mail, a.mail && a.mail !== a.displayName ? h('span', { class: 'muted small' }, ` ${a.mail}`) : null,
    onRemove ? h('button', { type: 'button', class: 'chip-x', 'aria-label': t('asg.clear'), onclick: (e) => { e.stopPropagation(); onRemove(); } }, '×') : null);
  const yesNo = (v) => v === true || /^(true|1)$/i.test(String(v)) ? t('yes') : v === false || /^(false|0)$/i.test(String(v)) ? t('no') : (v || null);
  const deviceLink = (id, name) => id ? h('a', { href: `#/device?id=${encodeURIComponent(id)}`, onclick: (e) => e.stopPropagation() }, name || id) : (name || '–');
  const usageCell = (r) => !r.usage ? h('span', { class: 'muted' }, '–') : h('span', { class: `state ${r.usage === 'Unused' ? 'warn' : r.usage === 'Used' ? 'good' : ''}`, title: r.usageHits ? t('x.usageHits', num(r.usageHits), fmtDay(r.usageLast)) : t('x.usage.help') }, code('use', r.usage));

  /** People picker: searches users, groups and distribution lists via the API; a typed e-mail address is always an option. */
  function peoplePicker() {
    let chosen = null, timer = null, seq = 0;
    const isMail = (s) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);
    const input = h('input', { type: 'search', autocomplete: 'off', placeholder: t('asg.search'), 'aria-label': t('asg.search') });
    const list = h('ul', { class: 'picker-list', hidden: true, role: 'listbox' });
    const chosenBox = h('div', { class: 'picker-chosen', hidden: true });
    const el = h('div', { class: 'picker' }, chosenBox, input, list);
    const pick = (a) => { chosen = a; chosenBox.replaceChildren(assigneeChip(a, () => pick(null))); chosenBox.hidden = !a; input.hidden = !!a; list.hidden = true; if (!a) { input.value = ''; input.focus(); } };
    const render = (items, notice) => {
      list.replaceChildren();
      const q = input.value.trim();
      for (const a of items) list.append(h('li', { role: 'option', tabindex: '0', onclick: () => pick(a), onkeydown: (e) => { if (e.key === 'Enter') pick(a); } },
        h('span', { class: `chip-type chip-${a.type}` }, t(`asg.type.${a.type}`)), ' ', h('strong', null, a.displayName), a.mail ? h('span', { class: 'muted small' }, ` ${a.mail}`) : null));
      if (isMail(q) && !items.some(a => (a.mail || '').toLowerCase() === q.toLowerCase())) list.append(h('li', { role: 'option', tabindex: '0', onclick: () => pick({ type: 'email', mail: q, displayName: q }) }, h('span', { class: 'chip-type chip-email' }, t('asg.type.email')), ' ', t('asg.useEmail', q)));
      if (notice) list.append(h('li', { class: 'muted small picker-note' }, notice));
      else if (!list.children.length && q.length >= 2) list.append(h('li', { class: 'muted small picker-note' }, t('asg.noResults')));
      list.hidden = !list.children.length;
    };
    input.addEventListener('input', () => {
      clearTimeout(timer);
      const q = input.value.trim();
      if (q.length < 2) { list.hidden = true; return; }
      timer = setTimeout(async () => {
        const my = ++seq; render([], t('asg.searching'));
        try {
          const r = await api(`directory/search?q=${encodeURIComponent(q)}`);
          if (my !== seq) return;
          const unavailable = arr(r.notices).length && !arr(r.results).length;
          render(arr(r.results), unavailable ? t('asg.dirUnavailable') : null);
        } catch { if (my === seq) render([], t('asg.dirUnavailable')); }
      }, 250);
    });
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); const q = input.value.trim(); if (isMail(q)) pick({ type: 'email', mail: q, displayName: q }); else if (list.firstElementChild && list.firstElementChild.getAttribute('role') === 'option') list.firstElementChild.click(); } });
    return { el, get: () => chosen || (isMail(input.value.trim()) ? { type: 'email', mail: input.value.trim(), displayName: input.value.trim() } : null) };
  }

  const post = (path, body) => api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

  /** Workflow block for a detail row: assignment (who works on it) and exception (accepted risk with or without expiry). */
  function acceptBox(item, kind, module, title) {
    const box = h('div', { class: 'accept' });
    const after = async (msg) => { await loadAcceptances(true); toast(msg); route(); };
    const stop = (e) => e.stopPropagation();

    // --- Assignment
    const asg = assignedMap()[item.key];
    const asgSec = h('div', { class: 'wf-section' }, h('h4', null, t('acc.section.assign')));
    if (asg) {
      asgSec.append(h('p', null, assigneeChip(asg.assignee, async () => { try { await post('assignments/clear', { key: item.key }); await after(t('asg.cleared')); } catch (err) { toast(t('error', err.message)); } }), ' ', h('span', { class: 'muted small' }, t('asg.by', asg.assignedBy, fmtDay(asg.assignedAt)))),
        asg.note ? h('p', { class: 'muted small' }, asg.note) : null);
    } else {
      const openA = h('button', { type: 'button' }, t('asg.assign'));
      const picker = peoplePicker();
      const note = h('input', { type: 'text', maxlength: '1000', 'aria-label': t('asg.note'), placeholder: t('asg.note') });
      const formA = h('form', { class: 'accept-form', hidden: true, onclick: stop }, picker.el, note,
        h('div', { class: 'accept-actions' }, h('button', { type: 'submit', class: 'primary' }, t('asg.save')), h('button', { type: 'button', onclick: () => { formA.hidden = true; openA.hidden = false; } }, t('acc.cancel'))));
      openA.addEventListener('click', (e) => { stop(e); formA.hidden = false; openA.hidden = true; picker.el.querySelector('input').focus(); });
      formA.addEventListener('submit', async (e) => {
        e.preventDefault();
        const who = picker.get(); if (!who) { toast(t('asg.err.none')); return; }
        try { await post('assignments', { key: item.key, kind, module, title, assignee: who, note: note.value.trim() }); await after(t('asg.saved')); } catch (err) { toast(t('error', err.message)); }
      });
      asgSec.append(h('p', { class: 'muted small' }, t('asg.help')), openA, formA);
    }

    // --- Exception
    const a = acceptedMap()[item.key];
    const excSec = h('div', { class: 'wf-section' }, h('h4', null, t('acc.section.exception')));
    if (a) {
      excSec.append(h('p', null, h('span', { class: 'tag accepted' }, a.expires ? t('acc.until', fmtDay(a.expires)) : t('acc.unlimited')), ' ', t('acc.by', a.acceptedBy), ' · ', a.owner, a.ticket ? ` · ${a.ticket}` : ''),
        h('p', { class: 'muted small' }, a.justification),
        h('button', { type: 'button', onclick: async (e) => { stop(e); try { await post('acceptances/revoke', { key: item.key }); await after(t('acc.revoked')); } catch (err) { toast(t('error', err.message)); } } }, t('acc.revoke')));
    } else {
      const open = h('button', { type: 'button' }, t('acc.accept'));
      const d = new Date(); d.setDate(d.getDate() + 90);
      const iso = (x) => x.toISOString().slice(0, 10);
      const just = h('textarea', { rows: '3', maxlength: '1000', 'aria-label': t('acc.justification') });
      const owner = h('input', { type: 'text', maxlength: '200', 'aria-label': t('acc.owner') });
      const ticket = h('input', { type: 'text', maxlength: '100', 'aria-label': t('acc.ticket') });
      const exp = h('input', { type: 'date', value: iso(d), min: iso(new Date(Date.now() + 864e5)), 'aria-label': t('acc.expires') });
      const never = h('input', { type: 'checkbox' });
      never.addEventListener('change', () => { exp.disabled = never.checked; });
      const form = h('form', { class: 'accept-form', hidden: true, onclick: stop },
        h('label', null, t('acc.justification'), just), h('label', null, t('acc.owner'), owner), h('label', null, t('acc.ticket'), ticket),
        h('label', null, t('acc.expires'), exp), h('label', { class: 'check' }, never, ' ', t('acc.noExpiry')),
        h('div', { class: 'accept-actions' }, h('button', { type: 'submit', class: 'primary' }, t('acc.save')), h('button', { type: 'button', onclick: () => { form.hidden = true; open.hidden = false; } }, t('acc.cancel'))));
      open.addEventListener('click', (e) => { stop(e); form.hidden = false; open.hidden = true; just.focus(); });
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (just.value.trim().length < 10) { toast(t('acc.err.just')); return; }
        if (!owner.value.trim()) { toast(t('acc.err.owner')); return; }
        try {
          await post('acceptances', { key: item.key, kind, module, title, justification: just.value.trim(), owner: owner.value.trim(), ticket: ticket.value.trim(), expires: never.checked ? null : exp.value });
          await after(t('acc.saved'));
        } catch (err) { toast(t('error', err.message)); }
      });
      excSec.append(h('p', { class: 'muted small' }, t('acc.exceptionHelp')), open, form);
    }
    box.append(h('div', { class: 'workflow' }, asgSec, excSec));
    return box;
  }

  const ASR_MODES = ['Block', 'Warn', 'Audit', 'Off'];
  function modeCell(m) {
    if (!m) return h('span', { class: 'muted' }, '–');
    if (m === 'n/a') return h('span', { class: 'muted' }, t('na'));
    return h('span', { class: `state ${m === 'Block' ? 'good' : m === 'Off' ? 'bad' : 'warn'}` }, code('asr', m));
  }
  function modeBar(c) {
    const total = ASR_MODES.reduce((a, k) => a + (c[k] || 0), 0);
    if (!total) return h('span', { class: 'muted' }, t('a.noDeviceData'));
    const col = { Block: '--sev-ok', Warn: '--sev-niedrig', Audit: '--sev-mittel', Off: '--sev-krit' };
    return h('span', { class: 'modebar', title: ASR_MODES.map(k => `${code('asr', k)}: ${c[k] || 0}`).join(', ') },
      h('span', { class: 'modebar-track' }, ASR_MODES.filter(k => c[k]).map(k => h('span', { style: `width:${(c[k] / total) * 100}%;background:var(${col[k]})` }))),
      h('span', { class: 'small muted' }, ASR_MODES.filter(k => c[k]).map(k => `${c[k]} ${code('asr', k)}`).join(' · ')));
  }
  const modeSummary = (c) => ASR_MODES.map(k => `${code('asr', k)} ${(c || {})[k] || 0}`).join(', ');
  const caClass = (st) => st === 'Protected' ? 'good' : (st === 'ReportOnly' || st === 'Unclear') ? 'warn' : (st === 'NoAgentId' || st === 'UserContext' ? '' : 'bad');
  function caCell(ca) { if (!ca) return h('span', { class: 'muted' }, '–'); return h('span', { class: `state ${caClass(ca.status)}` }, code('ca', ca.status)); }
  function controlsText(p) {
    const c = arr(p.controls);
    let s = c.length ? c.map(x => code('ctl', x)).join(p.operator === 'OR' ? t('ctl.or') : t('ctl.and')) : t('ctl.none');
    if (arr(p.riskLevels).length) s += t('ctl.risk', arr(p.riskLevels).join(', '));
    return s;
  }
  const viaText = (p) => p.excluded ? t('g.excluded') : `${code('via', p.via)}${p.filter ? ` (${p.filter})` : ''}`;
  const caPolicyLine = (p) => `${p.name} (${code('pst', p.state)}) – ${viaText(p)}; ${controlsText(p)}`;

  function warningsBlock(warnings) {
    const w = arr(warnings);
    if (!w.length) return null;
    return h('details', { class: 'warnings' }, h('summary', null, t('warnings', w.length)), list(w));
  }

  function noData(err, module) {
    const box = h('div', { class: 'empty' });
    if (err && err.status === 404) {
      const isAdmin = state.me && state.me.isAdmin;
      box.append(h('p', null, isAdmin ? t('nodata.admin') : t('nodata.user')),
        isAdmin ? h('button', { class: 'primary', type: 'button', onclick: (e) => runNow(module, e.target) }, t('run.now')) : null);
    } else {
      box.append(h('p', null, t('load.failed', err ? err.message : t('unknown.error'))));
    }
    return box;
  }

  // ---------- Views ----------
  const views = {
    async noaccess(main) {
      main.append(h('h1', null, 'Wardline'), h('div', { class: 'empty' }, t('noaccess')));
    },

    async overview(main) {
      let ep = null, ac = null, ag = null, li = null, epErr = null, acErr = null, agErr = null;
      await Promise.all([
        loadEndpoint().then(x => ep = x).catch(e => epErr = e),
        hasMod('agents') ? loadAgents().then(x => ag = x).catch(e => agErr = e) : null,
        hasMod('access') ? loadAccess().then(x => ac = x).catch(e => acErr = e) : null,
        hasMod('licensing') ? loadLicensing().then(x => li = x).catch(() => null) : null]);
      main.append(h('h1', null, t('ov.title')));
      if (!ep && !ac && !ag) { main.append(noData(epErr || agErr || acErr, 'all')); return; }

      if (ep || ag) {
        await loadAcceptances();
        const acc = acceptedMap();
        const counts = {};
        for (const f of [...arr(ep && ep.findings), ...arr(ag && ag.findings)]) if (!acc[f.key]) counts[f.severity] = (counts[f.severity] || 0) + 1;
        const total = SEV.reduce((a, s) => a + (counts[s] || 0), 0);
        const line = h('div', { class: 'ward-line', role: 'img', 'aria-label': t('ov.aria', SEV.map(s => `${code('sev', s)} ${counts[s] || 0}`).join(', ')) },
          total ? SEV.filter(s => counts[s]).map(s => h('span', { style: `width:${(counts[s] / total) * 100}%;background:var(${SEV_VAR[s]})`, title: `${code('sev', s)}: ${counts[s]}` })) : h('span', { style: 'width:100%;background:var(--sev-ok)' }));
        const legend = h('div', { class: 'ward-legend' }, SEV.map(s => h('a', { href: `#/findings?sev=${encodeURIComponent(s)}`, style: `--c:var(${SEV_VAR[s]})` }, h('b', null, num(counts[s])), h('i', null, code('sev', s)))));
        const crit = counts.Critical || 0;
        const comb = [...arr(ep && ep.findings), ...arr(ag && ag.findings)].filter(f => f.category === 'Combined').length;
        const statement = total === 0 ? t('ov.clean') : `${t('ov.open', num(total))}${crit ? t('ov.crit', crit) : ''}.${comb ? t('ov.combined', comb) : ''}`;
        main.append(h('section', { class: 'ward', 'aria-label': t('v.findings') }, line, legend, h('p', { class: 'ward-statement' }, statement)));
      }
      const fact = (b, s) => h('div', { class: 'fact' }, h('b', null, b), h('span', null, s));
      if (ep) {
        const s = ep.summary;
        main.append(h('h2', null, t('nav.endpoint')), h('div', { class: 'facts' },
          fact(num(s.devices), t('ov.devices')), fact(num(s.policyExclusions), t('ov.policyExcl')), fact(num(s.localExclusionsPresent), t('ov.localExcl')),
          fact(num(s.edrExclusions), t('ov.edr')), fact(t('ov.of', s.asrRulesOk || 0, s.asrRulesTotal || 0), t('ov.asr')), fact(t('ov.of', s.baselineOk || 0, s.baselineTotal || 0), t('ov.baseline')),
          s.coverageGaps !== undefined ? fact(num(s.coverageGaps), t('ov.coverage')) : null, s.unusedExclusions !== undefined ? fact(num(s.unusedExclusions), t('ov.unused')) : null,
          s.fleet ? fact(num(s.fleet.tampering30d), t('ov.tampering')) : null, s.fleet ? fact(num(s.fleet.internetFacingHigh), t('ov.inetHigh')) : null,
          s.fleet && s.fleet.inactive90d !== null && s.fleet.inactive90d !== undefined ? fact(num(s.fleet.inactive90d), t('ov.inactive')) : null,
          s.fleet && s.fleet.thirdPartyAv ? fact(num(s.fleet.thirdPartyAv), t('ov.thirdParty')) : null));
      } else {
        main.append(noData(epErr, 'endpoint'));
      }
      if (hasMod('agents')) {
        if (ag) {
          const s = ag.summary;
          main.append(h('h2', null, t('nav.agents')), h('div', { class: 'facts' },
            fact(num(s.cloudAgents), t('ov.cloud', s.withEntraId || 0)), fact(t('ov.of', s.identitiesCovered || 0, s.withEntraId || 0), t('ov.caId')),
            fact(t('ov.of', s.usersCovered || 0, s.agentUsers || 0), t('ov.caUser')), fact(num(s.localAgents), t('ov.local', s.localDevices || 0)),
            fact(num(s.localAutoApprove), t('ov.autoApprove'))));
        } else main.append(h('h2', null, t('nav.agents')), noData(agErr, 'agents'));
      }
      if (ac) {
        const s = ac.summary;
        main.append(h('h2', null, t('nav.access')), h('div', { class: 'facts' },
          fact(num(s.standingPrivileged !== undefined ? s.standingPrivileged : s.privilegedActive), t('ov.priv')), fact(num(s.eligible), t('ov.elig')),
          s.unusedActive !== undefined ? fact(num(s.unusedActive), t('ov.unusedAcc')) : null, s.bypassUsers !== undefined ? fact(num(s.bypassUsers), t('ov.bypass')) : null,
          s.openAudiences ? fact(num(s.openAudiences), t('ov.openPkg')) : null));
      }
      if (li && li.summary) {
        const s = li.summary;
        main.append(h('h2', null, h('a', { href: '#/licensing' }, t('nav.licensing'))), h('div', { class: 'facts' },
          fact(`${num(s.p2Consumed)} / ${num(s.p2Enabled)}`, `${t('li.tier.P2')} · ${t('li.consumed').toLowerCase()} / ${t('li.enabled').toLowerCase()}`),
          fact(num(s.licensedUsers), t('li.licensedUsers')), fact(num(s.clients), t('li.clients')), fact(num(s.clientsUnlicensed), t('li.clientsUnlicensed')),
          fact(num(s.usersNoDevice), t('li.usersNoDevice')), fact(num(s.servers), t('li.servers'))));
      }

      const runs = await api('runs').catch(() => []);
      const trend = trendCharts(arr(runs), contentWidth());
      if (trend) main.append(h('h2', null, t('ov.trend')), trend);
      if (arr(runs).length) {
        main.append(h('h2', null, t('ov.runs')), dataTable({
          name: 'runs', rows: arr(runs).slice(0, 20), search: r => r.module,
          columns: [
            { title: t('col.time'), text: r => fmtDate(r.at) },
            { title: t('col.module'), text: r => code('mod', r.module) },
            { title: t('col.changes'), text: r => r.changes },
            { title: t('col.notices'), text: r => r.warnings },
            { title: t('col.duration'), text: r => r.durationSec ? `${r.durationSec} s` : '–' }]
        }));
      }
      main.append(warningsBlock([...arr(ep && ep.warnings), ...arr(ag && ag.warnings), ...arr(ac && ac.warnings), ...arr(li && li.warnings)]) || '');
    },

    async findings(main, params) {
      main.append(h('h1', null, t('v.findings')), h('p', { class: 'lede' }, t('f.lede')));
      let ep = null, ag = null, ac = null, li = null, err = null;
      await Promise.all([loadEndpoint().then(x => ep = x).catch(e => err = e), hasMod('agents') ? loadAgents().then(x => ag = x).catch(() => null) : null,
        hasMod('access') ? loadAccess().then(x => ac = x).catch(() => null) : null, hasMod('licensing') ? loadLicensing().then(x => li = x).catch(() => null) : null]);
      if (!ep && !ag && !ac && !li) { main.append(noData(err, 'endpoint')); return; }
      await loadAcceptances();
      const acc = acceptedMap(), asg = assignedMap();
      const rows = [...arr(ep && ep.findings).map(f => ({ ...f, module: 'endpoint' })), ...arr(ag && ag.findings).map(f => ({ ...f, module: 'agents' })), ...arr(ac && ac.findings).map(f => ({ ...f, module: 'access' })), ...arr(li && li.findings).map(f => ({ ...f, module: 'licensing' }))].map(f => ({ ...f, accepted: acc[f.key] || null, assigned: asg[f.key] ? asg[f.key].assignee : null }));
      const cats = [...new Set(rows.map(r => r.category))].sort();
      const assignees = [...new Set(rows.filter(r => r.assigned).map(r => r.assigned.displayName))].sort();
      const table = dataTable({
        name: 'findings', rows, sort: (a, b) => sevRank(a.severity) - sevRank(b.severity),
        search: r => `${tx(r.title)} ${tx(r.detail)} ${r.deviceName || ''} ${code('cat', r.category)} ${assigneeText(r.assigned)}`,
        filters: [
          { label: t('f.severity'), options: SEV, optionLabel: s => code('sev', s), test: (r, v) => r.severity === v },
          { label: t('f.category'), options: cats, optionLabel: c => code('cat', c), test: (r, v) => r.category === v },
          { label: t('col.module'), options: [...new Set(rows.map(r => r.module))], optionLabel: m => code('mod', m), test: (r, v) => r.module === v },
          { label: t('asg.col'), options: ['__any', '__none', ...assignees], optionLabel: v => v === '__any' ? t('asg.any') : v === '__none' ? t('asg.none') : v, test: (r, v) => v === '__any' ? !!r.assigned : v === '__none' ? !r.assigned : (r.assigned && r.assigned.displayName === v) },
          { type: 'check', label: t('acc.hide'), checked: true, test: r => !r.accepted }],
        columns: [
          { title: t('f.severity'), cell: r => sevCell(r.severity), text: r => code('sev', r.severity) },
          { title: t('f.finding'), cell: r => h('span', null, tx(r.title), r.accepted ? h('span', { class: 'tag accepted' }, t('acc.tag')) : null), text: r => tx(r.title) + (r.accepted ? ` (${t('acc.tag')})` : '') },
          { title: t('f.category'), text: r => `${code('mod', r.module)} · ${code('cat', r.category)}` },
          { title: t('f.device'), cell: r => r.deviceCount ? h('span', { title: arr(r.deviceSample).join(', ') }, t('f.devicesN', num(r.deviceCount))) : deviceLink(r.deviceId, r.deviceName), text: r => r.deviceCount ? t('f.devicesN', num(r.deviceCount)) : (r.deviceName || '–') },
          { title: t('asg.col'), cell: r => r.assigned ? assigneeChip(r.assigned) : h('span', { class: 'muted' }, '–'), text: r => assigneeText(r.assigned) || '–' }],
        detail: r => h('div', null, dl([[t('f.description'), tx(r.detail)], [t('f.recommendation'), tx(r.recommendation)], [t('f.device'), r.deviceCount ? list(arr(r.deviceSample)) : r.deviceName]]), acceptBox(r, 'finding', r.module, tx(r.title))),
        empty: t('f.none')
      });
      main.append(table);
      if (params.get('sev')) { const sel = table.querySelector('select'); sel.value = params.get('sev'); sel.dispatchEvent(new Event('change')); }
    },

    async exclusions(main, params) {
      main.append(h('h1', null, t('x.title')), h('p', { class: 'lede' }, t('x.lede')));
      let ep; try { ep = await loadEndpoint(); } catch (e) { main.append(noData(e, 'endpoint')); return; }
      await loadAcceptances();
      const acc = acceptedMap();
      const accTag = (r) => acc[r.key] ? h('span', { class: 'tag accepted' }, t('acc.tag')) : null;
      const usageFilter = { type: 'check', label: t('x.onlyUnused'), test: r => r.usage === 'Unused' };
      const usageCol = { title: t('x.usage'), cell: usageCell, text: r => r.usage ? code('use', r.usage) : '' };
      const active = params.get('tab') || 'policy';
      main.append(tabs('exclusions', [['policy', t('x.tab.policy')], ['local', t('x.tab.local')], ['indicators', t('x.tab.indicators')], ['edr', t('x.tab.edr')]], active));
      const asrNames = {}; arr(ep.asrCatalog).forEach(x => { asrNames[x.id] = x.name; });
      const riskCol = { title: t('x.risk'), cell: r => sevCell(r.risk && r.risk.level), text: r => r.risk && code('sev', r.risk.level) };
      const riskSort = (a, b) => (b.risk ? b.risk.score : 0) - (a.risk ? a.risk.score : 0);
      const riskFilter = { label: t('x.risk'), options: SEV, optionLabel: s => code('sev', s), test: (r, v) => r.risk && r.risk.level === v };
      const assigns = (r) => arr(r.assignments).map(assignText).join(', ');

      if (active === 'policy') {
        const rows = arr(ep.policyExclusions);
        main.append(dataTable({
          name: 'exclusions-policies', rows, sort: riskSort,
          search: r => `${r.value} ${r.policyName} ${typeText(r)} ${assigns(r)}`,
          filters: [riskFilter,
            { label: t('x.type'), options: [...new Set(rows.map(r => r.type))].sort(), optionLabel: c => code('type', c), test: (r, v) => r.type === v },
            { label: t('x.platform'), options: [...new Set(rows.map(r => r.platform))].sort(), test: (r, v) => r.platform === v },
            { type: 'check', label: t('x.onlyGlobal'), test: r => r.scope === 'Global' }, usageFilter],
          columns: [riskCol,
            { title: t('x.type'), text: typeText },
            { title: t('x.value'), cell: r => h('span', null, h('span', { class: 'mono' }, r.value), accTag(r)), text: r => r.value },
            usageCol,
            { title: t('x.effect'), text: r => scopeText(r, asrNames) },
            { title: t('x.policy'), text: r => r.policyName },
            { title: t('x.assignment'), cell: r => r.assigned === false ? h('span', null, h('span', { class: 'tag' }, t('x.notEffective')), ' ', assigns(r) || t('x.unassigned')) : assigns(r), text: r => (r.assigned === false ? `${t('x.notEffective')}: ` : '') + (assigns(r) || t('x.unassigned')) }],
          detail: r => h('div', null, dl([[t('x.rating'), reasons(r.risk)], [t('x.usage'), r.usageHits ? t('x.usageHits', num(r.usageHits), fmtDay(r.usageLast)) : (r.usage ? code('use', r.usage) : null)], [t('x.source'), code('src', r.source)], [t('x.platform'), r.platform], [t('x.setting'), h('span', { class: 'mono' }, r.definitionId || '')], [t('x.modified'), fmtDate(r.lastModified)]]), acceptBox(r, 'exclusion', 'endpoint', `${r.value} (${r.policyName})`)),
          empty: t('x.none.policy')
        }));
      } else if (active === 'local') {
        const rows = arr(ep.localExclusions);
        main.append(h('p', { class: 'muted small' }, ep.localDetection === 'AdvancedHuntingAndInventory' ? t('x.local.inv') : t('x.local.ah')));
        main.append(dataTable({
          name: 'exclusions-local', rows, sort: riskSort,
          search: r => `${r.value} ${r.deviceName} ${typeText(r)} ${r.addedBy ? r.addedBy.process : ''}`,
          filters: [riskFilter,
            { label: t('x.origin'), options: [...new Set(rows.map(r => r.origin))].sort(), optionLabel: c => code('origin', c), test: (r, v) => r.origin === v },
            { label: t('x.platform'), options: [...new Set(rows.map(r => r.platform).filter(Boolean))].sort(), test: (r, v) => r.platform === v },
            { type: 'check', label: t('x.onlyPresent'), checked: true, test: r => r.present }, usageFilter],
          columns: [riskCol,
            { title: t('x.type'), text: typeText },
            { title: t('x.value'), cell: r => h('span', null, h('span', { class: 'mono' }, r.value), accTag(r)), text: r => r.value },
            { title: t('d.device'), cell: r => deviceLink(r.deviceId, r.deviceName), text: r => r.deviceName },
            usageCol,
            { title: t('x.origin'), text: r => code('origin', r.origin) },
            { title: t('x.setBy'), cell: r => h('span', { class: 'mono' }, (r.addedBy && r.addedBy.process) || '–'), text: r => r.addedBy && r.addedBy.process },
            { title: t('x.status'), cell: r => r.present ? h('span', { class: 'state warn' }, t('x.present')) : h('span', { class: 'muted' }, t('x.removed', fmtDay(r.removedAt))), text: r => r.present ? t('x.present') : t('x.removed', fmtDay(r.removedAt)) }],
          detail: r => h('div', null, dl([[t('x.rating'), reasons(r.risk)], [t('x.usage'), r.usageHits ? t('x.usageHits', num(r.usageHits), fmtDay(r.usageLast)) : (r.usage ? code('use', r.usage) : null)], [t('x.detectedBy'), code('src', r.source || 'AdvancedHunting')], [t('x.confirmed'), r.confirmedAt ? fmtDate(r.confirmedAt) : null], [t('x.firstSeen'), fmtDate(r.firstSeen)], [t('x.lastChange'), fmtDate(r.lastChange)],
            [t('x.cmd'), h('span', { class: 'mono' }, (r.addedBy && r.addedBy.commandLine) || '–')], [t('x.account'), (r.addedBy && r.addedBy.account) || '–'], [t('x.effect'), scopeText(r, asrNames)]]),
            r.present ? acceptBox(r, 'exclusion', 'endpoint', `${r.value} @ ${r.deviceName}`) : null),
          empty: t('x.none.local')
        }));
      } else if (active === 'edr') {
        main.append(h('p', { class: 'muted small' }, t('x.edr.lede')));
        const rows = [
          ...arr(ep.policyExclusions).filter(r => r.scope === 'Global').map(r => ({ ...r, where: t('x.where.policy', r.policyName), kind: t('x.kind.global') })),
          ...arr(ep.localExclusions).filter(r => r.present && r.scope === 'Global').map(r => ({ ...r, where: t('x.where.local', r.deviceName), kind: t('x.kind.globalLocal') })),
          ...arr(ep.indicators).map(r => ({ ...r, where: arr(r.deviceGroups).length ? t('x.where.groups', arr(r.deviceGroups).join(', ')) : t('x.allDevices'), kind: t('x.kind.ind', r.type), platform: t('all') }))];
        main.append(dataTable({
          name: 'edr-exclusions', rows, sort: riskSort,
          search: r => `${r.value} ${r.where} ${r.kind}`,
          filters: [riskFilter, { label: t('x.kind'), options: [...new Set(rows.map(r => r.kind))].sort(), test: (r, v) => r.kind === v }],
          columns: [riskCol,
            { title: t('x.kind'), text: r => r.kind },
            { title: t('x.value'), cell: r => h('span', { class: 'mono' }, r.value), text: r => r.value },
            { title: t('x.platform'), text: r => r.platform || '–' },
            { title: t('x.where'), text: r => r.where }],
          detail: r => dl([[t('x.rating'), reasons(r.risk)], [t('x.source'), r.source ? code('src', r.source) : null], [t('x.createdBy'), r.createdBy], [t('x.expires'), r.expires ? fmtDay(r.expires) : null]]),
          empty: t('x.none.edr')
        }));
      } else {
        const rows = arr(ep.indicators);
        main.append(dataTable({
          name: 'allow-indicators', rows, sort: riskSort,
          search: r => `${r.value} ${r.title} ${r.type} ${r.createdBy}`,
          filters: [riskFilter, { label: t('x.type'), options: [...new Set(rows.map(r => r.type))].sort(), test: (r, v) => r.type === v }],
          columns: [riskCol,
            { title: t('x.type'), text: r => r.type },
            { title: t('x.value'), cell: r => h('span', { class: 'mono' }, r.value), text: r => r.value },
            { title: t('x.title.col'), text: r => r.title },
            { title: t('x.createdBy'), text: r => r.createdBy },
            { title: t('x.expires'), text: r => r.expires ? fmtDay(r.expires) : t('never') }],
          detail: r => dl([[t('x.rating'), reasons(r.risk)], [t('x.created'), fmtDate(r.created)], [t('x.deviceGroups'), arr(r.deviceGroups).join(', ') || t('all')]]),
          empty: t('x.none.ind')
        }));
      }
    },

    async devices(main, params) {
      main.append(h('h1', null, t('v.devices')), h('p', { class: 'lede' }, t('d.lede')));
      let ep; try { ep = await loadEndpoint(); } catch (e) { main.append(noData(e, 'endpoint')); return; }
      const rows = arr(ep.devices);
      const cov = arr(ep.coverage);
      const large = !!ep.largeFleet;
      const devCount = large ? Number(ep.devicesPages.count) : rows.length;
      const covCount = ep.coveragePages ? Number(ep.coveragePages.count) : cov.length;
      const active = params.get('tab') || 'devices';
      main.append(tabs('devices', [['devices', t('d.tab.devices', num(devCount))], ['coverage', t('d.tab.coverage', num(covCount))]], active));
      if (active === 'coverage') {
        main.append(h('p', { class: 'muted small' }, t('d.cov.lede')));
        if (ep.coverageTruncated) main.append(h('p', { class: 'muted small' }, t('d.cov.truncated', num(cov.length))));
        const hasDevice = (id) => large ? !!id : rows.some(d => d.deviceId === id);
        main.append(dataTable({
          name: 'coverage', rows: cov, sort: (a, b) => String(a.status).localeCompare(String(b.status)) || String(a.deviceName).localeCompare(String(b.deviceName)),
          search: r => `${r.deviceName} ${r.os || ''} ${r.user || ''}`,
          filters: [
            { label: t('d.cov.status'), options: [...new Set(cov.map(r => r.status))].sort(), optionLabel: c => code('cov', c), test: (r, v) => r.status === v },
            { label: t('d.cov.source'), options: [...new Set(cov.map(r => r.source))].sort(), optionLabel: c => code('covsrc', c), test: (r, v) => r.source === v }],
          columns: [
            { title: t('d.device'), cell: r => r.deviceId && hasDevice(r.deviceId) ? deviceLink(r.deviceId, r.deviceName) : r.deviceName, text: r => r.deviceName },
            { title: t('d.cov.status'), cell: r => h('span', { class: `state ${r.status === 'CanBeOnboarded' ? 'warn' : 'bad'}` }, code('cov', r.status)), text: r => code('cov', r.status) },
            { title: t('d.platform'), text: r => r.os || '–' },
            { title: t('d.cov.source'), text: r => code('covsrc', r.source) },
            { title: t('d.cov.user'), text: r => r.user || '–' },
            { title: t('d.lastSeen'), text: r => fmtDate(r.lastSeen) }],
          detail: r => dl([[t('d.aad'), r.aadDeviceId ? h('span', { class: 'mono' }, r.aadDeviceId) : null], [t('dv.links'), r.intuneDeviceId ? h('a', { href: `https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/${encodeURIComponent(r.intuneDeviceId)}`, target: '_blank', rel: 'noopener noreferrer' }, t('dv.intune')) : null]]),
          empty: t('d.cov.none')
        }));
        main.append(h('p', { class: 'muted small' }, t('d.cov.feature')));
        return;
      }
      const c = (r, k) => r.checks ? r.checks[k] : undefined;
      const problem = r => Object.values(r.checks || {}).includes('BAD') || (r.avMode && r.avMode !== '0') || r.localExclusions > 0 || r.exclusionAlerts > 0 || r.asrBelowMinimum > 0;
      const asrName = {}; arr(ep.asrCatalog).forEach(x => { asrName[x.id] = x.name; });
      const modeText = (r) => L[`mode.${r.avModeText}`] ? t(`mode.${r.avModeText}`) : (r.avModeText || '–');

      // Charts: one donut per protection feature (+ platform, antivirus mode, sensor, signatures)
      const onOff = (v) => v === 'GOOD' ? 'on' : v === 'BAD' ? 'off' : v === 'N/A' ? 'na' : 'unknown';
      const STATE_SEGS = [['on', 'chart.on', 'var(--sev-ok)'], ['off', 'chart.off', 'var(--sev-krit)'], ['na', 'chart.na', 'var(--rule)'], ['unknown', 'chart.unknown', 'var(--muted)']];
      const PALETTE = ['var(--accent)', 'var(--sev-niedrig)', 'var(--sev-mittel)', 'var(--sev-hoch)', 'var(--ink-2)', 'var(--muted)', 'var(--rule-strong)'];
      const modeClass = (r) => r.avMode === '0' ? 'Active' : r.avMode === '4' ? 'EdrBlock' : r.avMode === '1' || r.avMode === '2' ? 'Passive' : 'Unknown';
      const sigState = (r) => /^(true|1)$/i.test(String(r.signatureUpToDate)) ? 'on' : /^(false|0)$/i.test(String(r.signatureUpToDate)) ? 'off' : 'unknown';
      const sensorState = (r) => !r.sensorHealth ? 'unknown' : /^active$/i.test(r.sensorHealth) ? 'on' : 'off';
      const FEATURES = ['TamperProtection', 'RealtimeProtection', 'CloudProtection', 'BehaviorMonitoring', 'PUAProtection', 'NetworkProtection', 'ControlledFolderAccess', 'EdrBlockMode'];
      const charts = [
        ...FEATURES.map(k => ({ id: k, title: code('chk', k), get: r => onOff(c(r, k)), segs: STATE_SEGS, rate: true })),
        { id: 'sig', title: t('d.sigs'), get: sigState, segs: STATE_SEGS, rate: true },
        { id: 'sensor', title: t('d.sensorHealth'), get: sensorState, segs: [['on', 'chart.on', 'var(--sev-ok)'], ['off', 'problem', 'var(--sev-krit)'], ['unknown', 'chart.unknown', 'var(--muted)']], rate: true, label: (r) => r.sensorHealth },
        { id: 'mode', title: t('d.runmode'), get: modeClass, segs: [['Active', 'mode.Active', 'var(--sev-ok)'], ['EdrBlock', 'mode.EdrBlock', 'var(--sev-hoch)'], ['Passive', 'mode.Passive', 'var(--sev-krit)'], ['Unknown', 'mode.Unknown', 'var(--muted)']] },
        { id: '3pav', title: t('d.thirdParty'), get: r => arr(r.thirdPartyAv).length ? '1' : '0', segs: [['1', 'chart.3pav.1', 'var(--sev-mittel)'], ['0', 'chart.3pav.0', 'var(--sev-ok)']], label: r => arr(r.thirdPartyAv).join(', ') },
        { id: 'os', title: t('d.platforms'), get: r => r.os || '–', segs: (large ? Object.keys((ep.deviceStats && ep.deviceStats.charts.os) || {}) : [...new Set(rows.map(r => r.os || '–'))]).sort().map((o, i) => [o, null, PALETTE[i % PALETTE.length]]) }];
      const chartOptions = [];
      charts.forEach(ch => ch.segs.forEach(([id, lk]) => chartOptions.push({ value: `${ch.id}|${id}`, label: `${ch.title}: ${lk ? t(lk) : id}` })));
      const chartTest = (r, v) => { const [cid, sid] = v.split('|'); const ch = charts.find(x => x.id === cid); return ch ? ch.get(r) === sid : true; };
      const columns = [
        { title: t('d.device'), cell: r => deviceLink(r.deviceId, r.deviceName), text: r => r.deviceName },
        { title: t('d.platform'), text: r => r.os },
        { title: t('d.mode'), cell: r => h('span', { class: `state ${r.avMode === '0' ? 'good' : r.avMode ? 'bad' : ''}` }, modeText(r)), text: modeText },
        { title: t('d.tamper'), cell: r => checkCell(c(r, 'TamperProtection')), text: r => c(r, 'TamperProtection') },
        { title: t('d.rtp'), cell: r => checkCell(c(r, 'RealtimeProtection')), text: r => c(r, 'RealtimeProtection') },
        { title: t('d.cloud'), cell: r => checkCell(c(r, 'CloudProtection')), text: r => c(r, 'CloudProtection') },
        { title: t('d.bm'), cell: r => checkCell(c(r, 'BehaviorMonitoring')), text: r => c(r, 'BehaviorMonitoring') },
        { title: t('d.pua'), cell: r => checkCell(c(r, 'PUAProtection')), text: r => c(r, 'PUAProtection') },
        { title: t('d.np'), cell: r => checkCell(c(r, 'NetworkProtection')), text: r => c(r, 'NetworkProtection') },
        { title: t('d.asrBelow'), cell: r => r.asrBelowMinimum === null || r.asrBelowMinimum === undefined ? h('span', { class: 'muted' }, '–') : h('span', { class: `state ${r.asrBelowMinimum ? 'bad' : 'good'}` }, String(r.asrBelowMinimum)), text: r => r.asrBelowMinimum },
        { title: t('d.policyExcl'), cell: r => r.policyExclusions === null || r.policyExclusions === undefined ? h('span', { class: 'muted' }, '–') : h('span', { class: r.policyExclusions ? 'state warn' : 'muted' }, String(r.policyExclusions)), text: r => r.policyExclusions },
        { title: t('d.local'), cell: r => r.localExclusions ? h('span', { class: `state ${r.localExclusionsHighRisk ? 'bad' : 'warn'}` }, String(r.localExclusions)) : h('span', { class: 'muted' }, '0'), text: r => r.localExclusions }];
      const detail = r => dl([[t('d.device'), h('a', { href: `#/device?id=${encodeURIComponent(r.deviceId)}` }, t('d.open'))], [t('d.group'), r.deviceGroup], [t('d.os'), [r.os, r.osVersion].filter(Boolean).join(' ')], [t('d.lastSeen'), fmtDate(r.lastSeen)],
        [t('d.sig'), yesNo(r.signatureUpToDate)], [t('d.plat'), yesNo(r.platformUpToDate)], [t('d.alerts'), r.exclusionAlerts],
        [t('d.checks'), list(Object.entries(r.checks || {}).map(([k, v]) => `${code('chk', k)}: ${v === 'GOOD' ? t('ok') : v === 'BAD' ? t('problem') : t('na')}`))],
        [t('d.asr'), r.asr ? list(Object.entries(r.asr).map(([k, v]) => `${asrName[k] || k}: ${v === 'n/a' ? t('na') : code('asr', v)}`)) : null]]);

      if (large) {
        // Server-side search: the list comes from api/devices?q=..., the charts from the aggregates of the last run.
        const st = ep.deviceStats || { charts: {}, groups: {} };
        main.append(h('p', { class: 'muted small' }, t('d.large', num(devCount))));
        const table = remoteDeviceTable({
          name: 'devices', columns, detail, empty: t('d.none'),
          filters: [
            { key: 'chart', label: t('d.chartFilter'), options: chartOptions },
            { key: 'os', label: t('d.platform'), options: Object.keys(st.charts.os || {}).filter(o => o !== '–').sort() },
            { key: 'group', label: t('d.group'), options: Object.keys(st.groups || {}).sort() },
            { key: 'issues', type: 'check', label: t('d.onlyIssues') }]
        });
        const select = (cid, sid) => { table.setFilter('chart', `${cid}|${sid}`); table.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
        const cards = charts.map(ch => {
          const counts = st.charts[ch.id] || {};
          const segments = ch.segs.map(([id, lk, color]) => ({ id, label: lk ? t(lk) : id, color, value: counts[id] || 0 }));
          const total = devCount, on = counts.on || counts.Active || 0, na = counts.na || 0, unknown = counts.unknown || counts.Unknown || 0;
          const base = total - na, known = total - unknown - na;
          return donut({
            title: ch.title, segments, centre: ch.rate || ch.id === 'mode' ? (known ? `${pct(on, base)} %` : '–') : num(total),
            sub: !(ch.rate || ch.id === 'mode') ? t('v.devices') : !known ? t('chart.unknown') : ch.id === 'mode' ? t('mode.Active').toLowerCase() : t('chart.onShort'),
            onSelect: x => select(ch.id, x.id)
          });
        });
        main.append(h('h2', null, t('d.glance')), h('p', { class: 'muted small' }, t('d.glance.lede')), h('div', { class: 'glance' }, cards));
        main.append(table);
        return;
      }

      const table = dataTable({
        name: 'devices', rows, sort: (a, b) => (problem(b) - problem(a)) || String(a.deviceName).localeCompare(String(b.deviceName)),
        search: r => `${r.deviceName} ${r.os} ${r.deviceGroup || ''}`,
        filters: [
          { label: t('d.chartFilter'), options: chartOptions, test: chartTest },
          { label: t('d.platform'), options: [...new Set(rows.map(r => r.os).filter(Boolean))].sort(), test: (r, v) => r.os === v },
          { label: t('d.group'), options: [...new Set(rows.map(r => r.deviceGroup).filter(Boolean))].sort(), test: (r, v) => r.deviceGroup === v },
          { type: 'check', label: t('d.onlyIssues'), test: problem }],
        columns, detail,
        empty: t('d.none')
      });
      if (rows.length) {
        const chartSel = table.querySelector('select');
        const select = (cid, sid) => { chartSel.value = `${cid}|${sid}`; chartSel.dispatchEvent(new Event('change')); table.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
        const cards = charts.map(ch => {
          const groups = {};
          for (const r of rows) (groups[ch.get(r)] = groups[ch.get(r)] || []).push(r);
          const segments = ch.segs.map(([id, lk, color]) => ({
            id, label: lk ? t(lk) : id, color, value: (groups[id] || []).length,
            items: (groups[id] || []).map(r => `${r.deviceName}${ch.label && ch.label(r) ? ` (${ch.label(r)})` : ''}`).sort()
          }));
          // Share of devices with the feature on – unknown counts against it, not applicable does not count
          const on = (groups.on || groups.Active || []).length, base = rows.length - (groups.na || []).length;
          const known = rows.length - (groups.unknown || groups.Unknown || []).length - (groups.na || []).length;
          return donut({
            title: ch.title, segments, centre: ch.rate || ch.id === 'mode' ? (known ? `${pct(on, base)} %` : '–') : num(rows.length),
            sub: !(ch.rate || ch.id === 'mode') ? t('v.devices') : !known ? t('chart.unknown') : ch.id === 'mode' ? t('mode.Active').toLowerCase() : t('chart.onShort'),
            onSelect: x => select(ch.id, x.id)
          });
        });
        main.append(h('h2', null, t('d.glance')), h('p', { class: 'muted small' }, t('d.glance.lede')), h('div', { class: 'glance' }, cards));
      }
      main.append(table);
    },

    async device(main, params) {
      const id = params.get('id') || '';
      main.append(h('p', null, h('a', { href: '#/devices' }, t('dv.back'))));
      let ep; try { ep = await loadEndpoint(); } catch (e) { main.append(noData(e, 'endpoint')); return; }
      const d = await loadDevice(ep, id);
      if (!d) { main.append(h('h1', null, t('v.device')), h('div', { class: 'empty' }, t('dv.notfound'))); return; }
      await loadAcceptances();
      const acc = acceptedMap();
      let ag = null; if (hasMod('agents')) { try { ag = await loadAgents(); } catch { ag = null; } }
      const modeText = L[`mode.${d.avModeText}`] ? t(`mode.${d.avModeText}`) : (d.avModeText || '–');
      const links = [h('a', { href: `https://security.microsoft.com/machines/v2/${encodeURIComponent(d.deviceId)}/overview`, target: '_blank', rel: 'noopener noreferrer' }, t('dv.defender'))];
      if (d.intuneDeviceId) links.push(' · ', h('a', { href: `https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/${encodeURIComponent(d.intuneDeviceId)}`, target: '_blank', rel: 'noopener noreferrer' }, t('dv.intune')));
      main.append(h('h1', null, d.deviceName), h('p', { class: 'lede' }, [d.os, d.osVersion].filter(Boolean).join(' '), d.deviceGroup ? ` · ${d.deviceGroup}` : '', d.deviceType ? ` · ${d.deviceType}` : ''));
      main.append(h('div', { class: 'detail card' }, dl([
        [t('d.mode'), h('span', { class: `state ${d.avMode === '0' ? 'good' : d.avMode ? 'bad' : ''}` }, modeText)],
        [t('dv.sensor'), d.sensorHealth || '–'], [t('dv.exposure'), d.exposure || null], [t('dv.user'), d.lastUser || null], [t('dv.join'), d.joinType || null],
        [t('dv.tags'), arr(d.tags).length ? arr(d.tags).join(', ') : null], [t('dv.inet'), d.internetFacing === true ? h('span', { class: d.exposure === 'High' ? 'state bad' : 'state warn' }, t('yes')) : (d.internetFacing === false ? t('no') : null)],
        [t('dv.assetValue'), d.assetValue || null], [t('dv.tvmExcluded'), d.tvmExcluded === true ? `${t('yes')}${d.tvmExclusionReason ? ` – ${d.tvmExclusionReason}` : ''}` : null],
        [t('dv.tampering'), d.tampering30d > 0 ? h('span', { class: 'state bad' }, `${d.tampering30d}${d.tamperingLast ? ` · ${fmtDate(d.tamperingLast)}` : ''}`) : null],
        [t('dv.thirdParty'), arr(d.thirdPartyAv).length ? h('span', { class: d.avMode === '0' ? 'state warn' : '' }, arr(d.thirdPartyAv).join(', ')) : null],
        [t('dv.troubleshooting'), d.troubleshooting30d > 0 || d.troubleshootingActive ? h('span', { class: d.troubleshootingActive ? 'state bad' : 'state warn' }, `${d.troubleshooting30d || 0}${d.troubleshootingActive ? ` · ${t('dv.tsActive')}` : ''}${d.troubleshootingLast ? ` · ${fmtDate(d.troubleshootingLast)}` : ''}`) : null],
        [t('dv.clientVersion'), d.clientVersion || null],
        [t('d.lastSeen'), fmtDate(d.lastSeen)], [t('dv.sigver'), d.avSignatureVersion || null], [t('dv.engver'), [d.avEngineVersion, d.avPlatformVersion].filter(Boolean).join(' / ') || null],
        [t('dv.sigtime'), d.avSignatureTime ? fmtDate(d.avSignatureTime) : null], [t('d.sig'), yesNo(d.signatureUpToDate)], [t('d.plat'), yesNo(d.platformUpToDate)],
        [t('d.aad'), d.aadDeviceId ? h('span', { class: 'mono small' }, d.aadDeviceId) : null], [t('dv.links'), h('span', null, links)]])));

      const order = ['AntivirusEnabled', 'RealtimeProtection', 'BehaviorMonitoring', 'CloudProtection', 'PUAProtection', 'TamperProtection', 'NetworkProtection', 'ControlledFolderAccess', 'EdrBlockMode', 'AntivirusSignatureVersion', 'SensorEnabled', 'ImpairedCommunications', 'PassiveModeOff'];
      const checks = Object.keys(d.checks || {}).sort((a, b) => (order.indexOf(a) + 1 || 99) - (order.indexOf(b) + 1 || 99));
      main.append(h('h2', null, t('dv.protection')), checks.length ? h('div', { class: 'checks' }, checks.map(k => h('div', { class: 'check-item' }, checkCell(d.checks[k]), ' ', code('chk', k)))) : h('p', { class: 'muted' }, t('dv.none')),
        d.networkProtectionSource ? h('p', { class: 'muted small' }, t(`dv.np.${d.networkProtectionSource}`)) : null);

      const cat = {}; arr(ep.asrCatalog).forEach(x => { cat[x.id] = x; });
      const rules = arr(ep.asrRules);
      if (d.asr) {
        const asrRows = Object.entries(d.asr).map(([k, v]) => ({ id: k, mode: v, rule: rules.find(r => r.id === k) || {} }));
        main.append(h('h2', null, t('dv.asr')), dataTable({
          name: `asr-${d.deviceName}`, rows: asrRows, search: r => (cat[r.id] && cat[r.id].name) || r.id,
          columns: [
            { title: t('a.rule'), text: r => (cat[r.id] && cat[r.id].name) || r.id },
            { title: t('dv.target'), text: r => r.rule.minimum ? `${code('asr', r.rule.minimum)} → ${code('asr', r.rule.recommended || r.rule.minimum)}` : '–' },
            { title: t('dv.effective'), cell: r => modeCell(r.mode), text: r => r.mode === 'n/a' ? t('na') : code('asr', r.mode) }]
        }));
      }

      const locals = arr(ep.localExclusions).filter(x => x.deviceId === d.deviceId);
      main.append(h('h2', null, t('dv.local')), locals.length ? dataTable({
        name: `local-${d.deviceName}`, rows: locals, search: r => `${r.value} ${r.addedBy ? r.addedBy.commandLine : ''}`,
        filters: [{ type: 'check', label: t('x.onlyPresent'), checked: true, test: r => r.present }],
        columns: [
          { title: t('x.risk'), cell: r => sevCell(r.risk && r.risk.level), text: r => r.risk && code('sev', r.risk.level) },
          { title: t('x.type'), text: typeText },
          { title: t('x.value'), cell: r => h('span', null, h('span', { class: 'mono' }, r.value), acc[r.key] ? h('span', { class: 'tag accepted' }, t('acc.tag')) : null), text: r => r.value },
          { title: t('x.setBy'), cell: r => h('span', { class: 'mono' }, (r.addedBy && r.addedBy.process) || '–'), text: r => r.addedBy && r.addedBy.process },
          { title: t('x.firstSeen'), text: r => fmtDate(r.firstSeen) },
          { title: t('x.status'), text: r => r.present ? t('x.present') : t('x.removed', fmtDay(r.removedAt)) }],
        detail: r => h('div', null, dl([[t('x.cmd'), h('span', { class: 'mono' }, (r.addedBy && r.addedBy.commandLine) || '–')], [t('x.account'), (r.addedBy && r.addedBy.account) || '–'], [t('x.rating'), reasons(r.risk)]]), r.present ? acceptBox(r, 'exclusion', 'endpoint', `${r.value} @ ${r.deviceName}`) : null)
      }) : h('p', { class: 'muted' }, t('dv.none')));

      const findings = [...arr(ep.findings), ...arr(ag && ag.findings)].filter(f => f.deviceId === d.deviceId || (f.deviceName && f.deviceName === d.deviceName));
      main.append(h('h2', null, t('dv.findings')), findings.length ? dataTable({
        name: `findings-${d.deviceName}`, rows: findings, sort: (a, b) => sevRank(a.severity) - sevRank(b.severity), search: r => tx(r.title),
        columns: [
          { title: t('f.severity'), cell: r => sevCell(r.severity), text: r => code('sev', r.severity) },
          { title: t('f.finding'), cell: r => h('span', null, tx(r.title), acc[r.key] ? h('span', { class: 'tag accepted' }, t('acc.tag')) : null), text: r => tx(r.title) }],
        detail: r => h('div', null, dl([[t('f.description'), tx(r.detail)], [t('f.recommendation'), tx(r.recommendation)]]), acceptBox(r, 'finding', ag && arr(ag.findings).includes(r) ? 'agents' : 'endpoint', tx(r.title)))
      }) : h('p', { class: 'muted' }, t('dv.none')));

      if (ag) {
        const agents = arr(ag.agents).filter(a => a.agentType === 'Local' && a.device && (a.device.id === d.deviceId || a.device.name === d.deviceName));
        main.append(h('h2', null, t('dv.agents')), agents.length ? list(agents.map(a => `${a.name}${a.vendor ? ` (${a.vendor})` : ''}${a.user ? ` · ${a.user}` : ''}${a.autoApprove ? ` · ${t('g.autoApprove')}` : ''}${arr(a.mcpServers).length ? ` · MCP: ${arr(a.mcpServers).map(m => m.name).join(', ')}` : ''}`)) : h('p', { class: 'muted' }, t('dv.none')));
      }

      const pols = arr(ep.policyExclusions);
      const byPolicy = {}; pols.forEach(p => { (byPolicy[p.policyId] = byPolicy[p.policyId] || { id: p.policyId, name: p.policyName, platform: p.platform, assignments: p.assignments, assigned: p.assigned, n: 0 }).n++; });
      const plat = String(d.os || '').toLowerCase().slice(0, 3);
      const matchedPolicyIds = new Set(arr(d.policyExclusionPolicyIds));
      const relevant = matchedPolicyIds.size
        ? Object.values(byPolicy).filter(p => matchedPolicyIds.has(p.id))
        : Object.values(byPolicy).filter(p => String(p.platform || '').toLowerCase().startsWith(plat));
      const resolved = d.policyExclusions === null || d.policyExclusions === undefined ? '–' : String(d.policyExclusions);
      main.append(h('h2', null, t('dv.policies')), h('p', { class: 'muted small' }, t('dv.policies.count', resolved)), h('p', { class: 'muted small' }, t('dv.policies.note')), relevant.length ? list(relevant.map(p => `${p.name}: ${p.n} · ${arr(p.assignments).map(assignText).join(', ') || t('x.unassigned')}`)) : h('p', { class: 'muted' }, t('dv.none')));

      let changes = []; try { changes = arr(state.changes.endpoint || (state.changes.endpoint = await api('changes?module=endpoint'))); } catch { changes = []; }
      const mine = changes.filter(c => JSON.stringify(c.label || '').includes(d.deviceName)).slice(0, 50);
      main.append(h('h2', null, t('dv.changes')), mine.length ? dataTable({
        name: `changes-${d.deviceName}`, rows: mine, search: r => tx(r.label),
        rowClass: r => `chg-row chg-row-${r.change}`,
        columns: [{ title: t('col.time'), text: r => fmtDate(r.at) }, { title: t('ch.kind'), cell: changeKind, text: r => code('ch', r.change) }, { title: t('ch.what'), text: r => tx(r.label) },
          { title: t('ch.before'), cell: r => changeCells(r).before, text: r => r.before || '–' }, { title: t('ch.after'), cell: r => changeCells(r).after, text: r => r.after || '–' }]
      }) : h('p', { class: 'muted' }, t('dv.none')));
    },

    async accepted(main, params) {
      main.append(h('h1', null, t('acc.title')), h('p', { class: 'lede' }, t('acc.lede')));
      const active = params.get('tab') || 'list';
      main.append(tabs('accepted', [['list', t('acc.tab.list')], ['assignments', t('asg.tab')], ['log', t('acc.tab.log')]], active));
      if (active === 'log') {
        let log = []; try { log = arr(await api('acceptances/log')); } catch (e) { main.append(noData(e, 'endpoint')); return; }
        main.append(dataTable({
          name: 'acceptance-log', rows: log, search: r => `${r.title} ${r.by} ${r.justification || ''} ${r.ticket || ''} ${assigneeText(r.assignee)}`,
          columns: [
            { title: t('col.time'), text: r => fmtDate(r.at) }, { title: t('acc.action'), text: r => t(`acc.act.${r.action}`) }, { title: t('acc.what'), text: r => r.title || r.key },
            { title: t('acc.by', ''), text: r => r.by }, { title: t('acc.expires'), text: r => r.expires ? fmtDay(r.expires) : (r.action === 'accept' ? t('acc.never') : '–') },
            { title: t('asg.col'), text: r => assigneeText(r.assignee) || '–' }, { title: t('acc.justification'), text: r => r.justification || '–' }],
          empty: t('acc.none')
        }));
        return;
      }
      await loadAcceptances(true);
      if (active === 'assignments') {
        const rows = arr(state.assignments);
        main.append(h('p', { class: 'muted small' }, t('asg.help')));
        main.append(dataTable({
          name: 'assignments', rows, sort: (a, b) => String(b.assignedAt).localeCompare(String(a.assignedAt)),
          search: r => `${r.title} ${assigneeText(r.assignee)} ${r.note || ''}`,
          filters: [{ label: t('asg.col'), options: ['user', 'group', 'distributionList', 'email'], optionLabel: v => t(`asg.type.${v}`), test: (r, v) => r.assignee && r.assignee.type === v }],
          columns: [
            { title: t('acc.what'), text: r => `${t(`acc.kind.${r.kind}`) || r.kind}: ${r.title}` },
            { title: t('asg.col'), cell: r => assigneeChip(r.assignee), text: r => assigneeText(r.assignee) },
            { title: t('asg.at'), text: r => `${fmtDate(r.assignedAt)} · ${r.assignedBy}` }, { title: t('asg.note'), text: r => r.note || '–' }],
          detail: r => h('div', null, h('button', { type: 'button', onclick: async () => { try { await post('assignments/clear', { key: r.key }); await loadAcceptances(true); toast(t('asg.cleared')); route(); } catch (err) { toast(t('error', err.message)); } } }, t('asg.clear'))),
          empty: t('asg.empty')
        }));
        return;
      }
      const rows = arr(state.acceptances);
      const status = (r) => r.revokedAt ? 'revoked' : r.active ? 'active' : 'expired';
      main.append(dataTable({
        name: 'acceptances', rows, sort: (a, b) => String(a.expires || '9999').localeCompare(String(b.expires || '9999')),
        search: r => `${r.title} ${r.owner} ${r.ticket || ''} ${r.justification}`,
        filters: [{ label: t('acc.status'), options: ['active', 'expired', 'revoked'], optionLabel: c => c === 'active' ? t('acc.active') : c === 'expired' ? t('acc.expired') : t('acc.revokedTag'), test: (r, v) => status(r) === v }],
        columns: [
          { title: t('acc.what'), text: r => `${t(`acc.kind.${r.kind}`) || r.kind}: ${r.title}` },
          { title: t('acc.status'), cell: r => h('span', { class: `state ${status(r) === 'active' ? 'good' : 'warn'}` }, status(r) === 'active' ? t('acc.active') : status(r) === 'expired' ? t('acc.expired') : t('acc.revokedTag')), text: status },
          { title: t('acc.owner'), text: r => r.owner }, { title: t('acc.expires'), text: r => r.expires ? fmtDay(r.expires) : t('acc.never') }, { title: t('acc.ticket'), text: r => r.ticket || '–' }],
        detail: r => h('div', null, dl([[t('acc.justification'), r.justification], [t('acc.at'), `${fmtDate(r.acceptedAt)} · ${r.acceptedBy}`], [t('acc.revokedTag'), r.revokedAt ? `${fmtDate(r.revokedAt)} · ${r.revokedBy}` : null]]),
          r.active ? h('button', { type: 'button', onclick: async () => { try { await post('acceptances/revoke', { key: r.key }); await loadAcceptances(true); toast(t('acc.revoked')); route(); } catch (err) { toast(t('error', err.message)); } } }, t('acc.revoke')) : null),
        empty: t('acc.none')
      }));
    },

    async asr(main, params) {
      main.append(h('h1', null, t('v.asr')), h('p', { class: 'lede' }, t('a.lede')));
      let ep; try { ep = await loadEndpoint(); } catch (e) { main.append(noData(e, 'endpoint')); return; }
      const rules = arr(ep.asrRules);
      if (!rules.length) { main.append(h('div', { class: 'empty' }, t('a.none'))); return; }
      const active = params.get('tab') || 'rules';
      main.append(tabs('asr', [['rules', t('a.tab.rules')], ['groups', t('a.tab.groups')], ['devices', t('a.tab.devices')], ['exclusions', t('a.tab.exclusions')]], active));
      const stClass = s => s === 'OK' ? 'good' : (s === 'NoDeviceData' ? '' : (s === 'BlockRecommended' ? 'warn' : 'bad'));
      const grp = (g) => g === '(no group)' ? t('a.ownGroup') : g;
      if (active === 'rules') {
        main.append(dataTable({
          name: 'asr-rules', rows: rules, sort: (a, b) => (a.status === 'OK') - (b.status === 'OK') || sevRank(a.severity) - sevRank(b.severity),
          search: r => `${r.name} ${r.guid} ${code('st', r.status)}`,
          filters: [{ label: t('b.status'), options: [...new Set(rules.map(r => r.status))].sort(), optionLabel: s => code('st', s), test: (r, v) => r.status === v }],
          columns: [
            { title: t('b.weight'), cell: r => sevCell(r.severity), text: r => code('sev', r.severity) },
            { title: t('a.rule'), text: r => r.name },
            { title: t('b.target'), text: r => r.minimum === r.recommended ? code('asr', r.minimum) : t('a.target2', code('asr', r.minimum), code('asr', r.recommended)) },
            { title: t('a.configured'), text: r => { const a = arr(r.configured).filter(c => c.assigned); return a.length ? [...new Set(a.map(c => code('asr', c.mode)))].join(' / ') : t('x.unassigned'); } },
            { title: t('a.effective'), cell: r => modeBar(r.effective || {}), text: r => modeSummary(r.effective) },
            { title: t('b.status'), cell: r => h('span', { class: `state ${stClass(r.status)}` }, code('st', r.status)), text: r => code('st', r.status) }],
          detail: r => dl([[t('a.guid'), h('span', { class: 'mono' }, r.guid)], [t('a.note'), tx(r.note)],
            [t('a.policies'), arr(r.configured).length ? list(arr(r.configured).map(c => `${c.policyName}: ${code('asr', c.mode)}${c.assigned ? ` – ${arr(c.assignments).map(assignText).join(', ')}` : t('b.notAssigned')}`)) : t('none')],
            [t('a.belowByGroup'), arr(r.belowByGroup).length ? list(arr(r.belowByGroup).map(g => t('a.devicesN', grp(g.group), g.devices))) : t('none')],
            [t('a.naUnknown'), `${(r.effective || {}).NotApplicable || 0} / ${(r.effective || {}).Unknown || 0}`]])
        }));
      } else if (active === 'groups') {
        const groups = arr(ep.asrGroups);
        const sel = h('select', { 'aria-label': t('d.group') }, groups.map(g => h('option', { value: g.group }, t('a.groupOpt', grp(g.group), g.devices, g.devicesBelow))));
        const out = h('div');
        const render = () => {
          const g = groups.find(x => x.group === sel.value);
          out.replaceChildren();
          if (!g) return;
          const rows = rules.map(r => ({ rule: r, c: (g.rules || {})[r.id] || {} }));
          out.append(dataTable({
            name: `asr-group-${g.group}`, rows, sort: (a, b) => (b.c.below || 0) - (a.c.below || 0),
            search: x => x.rule.name,
            columns: [
              { title: t('a.rule'), text: x => x.rule.name },
              { title: t('b.target'), text: x => code('asr', x.rule.minimum) },
              { title: t('a.modeInGroup'), cell: x => modeBar(x.c), text: x => modeSummary(x.c) },
              { title: t('a.below'), cell: x => h('span', { class: `state ${x.c.below ? 'bad' : 'good'}` }, String(x.c.below || 0)), text: x => x.c.below || 0 }]
          }));
        };
        sel.addEventListener('change', render);
        main.append(h('p', { class: 'muted small' }, t('a.groups.lede')), h('div', { class: 'toolbar' }, sel), out);
        if (!groups.length) main.append(h('div', { class: 'empty' }, t('a.noGroups')));
        render();
      } else if (active === 'devices' && ep.largeFleet) {
        const st = ep.deviceStats || { groups: {} };
        main.append(h('p', { class: 'muted small' }, t('d.large', num(ep.devicesPages.count))));
        main.append(remoteDeviceTable({
          name: 'asr-devices', fixed: { asrBelow: '1' }, empty: t('a.noWin'),
          filters: [{ key: 'group', label: t('d.group'), options: Object.keys(st.groups || {}).sort() }],
          columns: [
            { title: t('d.device'), cell: d => deviceLink(d.deviceId, d.deviceName), text: d => d.deviceName },
            { title: t('d.group'), text: d => d.deviceGroup || '–' },
            { title: t('a.block'), text: d => d.asrBlocked ?? '–' },
            { title: t('a.below'), cell: d => h('span', { class: `state ${d.asrBelowMinimum ? 'bad' : 'good'}` }, String(d.asrBelowMinimum)), text: d => d.asrBelowMinimum }]
        }));
      } else if (active === 'devices') {
        const devs = arr(ep.devices).filter(d => /^Windows/.test(d.os || ''));
        main.append(dataTable({
          name: 'asr-devices', rows: devs, sort: (a, b) => (b.asrBelowMinimum || 0) - (a.asrBelowMinimum || 0),
          search: d => `${d.deviceName} ${d.deviceGroup || ''}`,
          filters: [{ label: t('d.group'), options: [...new Set(devs.map(d => d.deviceGroup).filter(Boolean))].sort(), test: (d, v) => d.deviceGroup === v },
            { type: 'check', label: t('a.onlyBelow'), test: d => d.asrBelowMinimum > 0 }],
          columns: [
            { title: t('d.device'), text: d => d.deviceName },
            { title: t('d.group'), text: d => d.deviceGroup || '–' },
            { title: t('a.block'), text: d => d.asrBlocked ?? '–' },
            { title: t('a.below'), cell: d => d.asrBelowMinimum === null || d.asrBelowMinimum === undefined ? h('span', { class: 'muted' }, '–') : h('span', { class: `state ${d.asrBelowMinimum ? 'bad' : 'good'}` }, String(d.asrBelowMinimum)), text: d => d.asrBelowMinimum }],
          detail: d => h('table', { class: 'mini' }, h('tbody', null, rules.map(r => h('tr', null, h('td', null, r.name), h('td', null, modeCell(d.asr ? d.asr[r.id] : null)), h('td', { class: 'muted small' }, t('a.targetN', code('asr', r.minimum))))))),
          empty: t('a.noWin')
        }));
      } else {
        const names = {}; arr(ep.asrCatalog).forEach(x => { names[x.id] = x.name; });
        const rows = [...arr(ep.policyExclusions).filter(r => r.type === 'ASR').map(r => ({ ...r, where: r.policyName })),
          ...arr(ep.localExclusions).filter(r => r.present && r.type === 'ASR').map(r => ({ ...r, where: t('x.where.local', r.deviceName) }))];
        main.append(dataTable({
          name: 'asr-exclusions', rows, sort: (a, b) => (b.risk ? b.risk.score : 0) - (a.risk ? a.risk.score : 0),
          search: r => `${r.value} ${scopeText(r, names)} ${r.where}`,
          columns: [
            { title: t('x.risk'), cell: r => sevCell(r.risk && r.risk.level), text: r => r.risk && code('sev', r.risk.level) },
            { title: t('x.value'), cell: r => h('span', { class: 'mono' }, r.value), text: r => r.value },
            { title: t('a.appliesTo'), text: r => scopeText(r, names) },
            { title: t('x.where'), text: r => r.where }],
          detail: r => dl([[t('x.rating'), reasons(r.risk)], [t('x.assignment'), arr(r.assignments).map(assignText).join(', ')]]),
          empty: t('a.noExcl')
        }));
      }
    },

    async agents(main, params) {
      main.append(h('h1', null, t('g.title')), h('p', { class: 'lede' }, t('g.lede')), h('p', { class: 'muted small' }, t('g.beta')));
      let ag; try { ag = await loadAgents(); } catch (e) { main.append(noData(e, 'agents')); return; }
      if (ag.securityDefaults) main.append(h('div', { class: 'warnings' }, t('g.secdef')));
      if (ag.registryStatus === 'NotAvailable') main.append(h('p', { class: 'muted small' }, t('g.registry.na')));
      else if (ag.registrySource === 'AgentRegistry') main.append(h('p', { class: 'muted small' }, t('g.registry.legacy')));
      const all = arr(ag.agents);
      const cloud = all.filter(a => a.agentType !== 'Local');
      const local = all.filter(a => a.agentType === 'Local');
      const active = params.get('tab') || 'cloud';
      main.append(tabs('agents', [['cloud', t('g.tab.cloud', cloud.length)], ['local', t('g.tab.local', local.length)]], active));
      const mono = (v) => v ? h('span', { class: 'mono small' }, v) : h('span', { class: 'muted' }, '–');

      if (active === 'local') {
        main.append(h('p', { class: 'muted small' }, t('g.local.lede')));
        const devState = (a) => {
          const d = a.device || {};
          const bad = [];
          if (d.tamper === 'BAD') bad.push(t('g.tamperOff'));
          if (d.localExclusions > 0) bad.push(t('g.localExcl', d.localExclusions));
          return bad;
        };
        main.append(dataTable({
          name: 'local-agents', rows: local, sort: (a, b) => (b.autoApprove === true) - (a.autoApprove === true) || devState(b).length - devState(a).length || String(a.name).localeCompare(String(b.name)),
          search: a => `${a.name} ${a.vendor || ''} ${(a.device && a.device.name) || ''} ${a.user || ''}`,
          filters: [
            { label: t('g.vendor'), options: [...new Set(local.map(a => a.vendor).filter(Boolean))].sort(), test: (a, v) => a.vendor === v },
            { label: t('d.group'), options: [...new Set(local.map(a => a.device && a.device.group).filter(Boolean))].sort(), test: (a, v) => a.device && a.device.group === v },
            { type: 'check', label: t('g.onlyAuto'), test: a => a.autoApprove === true }],
          columns: [
            { title: t('g.agent'), cell: a => h('span', null, a.name || '–', h('br'), h('span', { class: 'muted small' }, a.vendor || '')), text: a => a.name },
            { title: t('g.device'), text: a => (a.device && a.device.name) || '–' },
            { title: t('g.user'), text: a => a.user || '–' },
            { title: t('g.autoApprove'), cell: a => a.autoApprove ? h('span', { class: 'state bad' }, t('yes')) : h('span', { class: 'muted' }, t('no')), text: a => a.autoApprove ? t('yes') : t('no') },
            { title: t('g.mcp'), cell: a => { const n = arr(a.mcpServers).length, u = arr(a.mcpServers).filter(m => m.unpinned).length; return u ? h('span', { class: 'state warn' }, t('g.mcpUnpinned', n, u)) : String(n); }, text: a => arr(a.mcpServers).length },
            { title: t('g.deviceState'), cell: a => { const b = devState(a); return b.length ? h('span', { class: 'state bad' }, b.join(', ')) : (a.device && a.device.tamper ? h('span', { class: 'state good' }, t('g.deviceOk')) : h('span', { class: 'muted' }, '–')); }, text: a => devState(a).join(', ') }],
          detail: a => dl([[t('g.process'), a.process ? h('span', { class: 'mono' }, a.process) : null], [t('g.trusted'), a.trustedProcess === null || a.trustedProcess === undefined ? null : (a.trustedProcess ? t('yes') : t('no'))],
            [t('g.version'), a.version], [t('g.devGroup'), a.device && a.device.group], [t('g.avMode'), a.device && a.device.avMode ? code('mode', a.device.avMode) : null],
            [t('g.asrBelow'), a.device && a.device.asrBelowMinimum !== null && a.device.asrBelowMinimum !== undefined ? String(a.device.asrBelowMinimum) : null],
            [t('g.mcpList'), arr(a.mcpServers).length ? list(arr(a.mcpServers).map(m => `${m.name}${m.command ? ` – ${m.command}` : ''}${m.endpoint ? ` – ${m.endpoint}` : ''}${m.unpinned ? ` (${t('g.unpinned')})` : ''}`)) : t('none')],
            [t('g.sources'), arr(a.sources).map(s => code('src', s)).join(', ')]]),
          empty: t('g.none.local')
        }));
      } else {
        main.append(dataTable({
          name: 'cloud-agents', rows: cloud, sort: (a, b) => (caClass(b.caIdentity && b.caIdentity.status) === 'bad') - (caClass(a.caIdentity && a.caIdentity.status) === 'bad') || String(a.name).localeCompare(String(b.name)),
          search: r => `${r.name} ${r.platform} ${r.blueprintAppId || ''} ${r.agentId || ''} ${r.agentUserId || ''} ${r.agentUserUpn || ''} ${r.blueprintName || ''}`,
          filters: [
            { label: t('d.platform'), options: [...new Set(cloud.map(r => r.platform).filter(Boolean))].sort(), test: (r, v) => r.platform === v },
            { label: t('g.caAgent'), options: [...new Set(cloud.map(r => r.caIdentity && r.caIdentity.status).filter(Boolean))].sort(), optionLabel: s => code('ca', s), test: (r, v) => r.caIdentity && r.caIdentity.status === v },
            { type: 'check', label: t('g.onlyOpen'), test: r => caClass(r.caIdentity && r.caIdentity.status) === 'bad' || (r.caUser && caClass(r.caUser.status) === 'bad') }],
          columns: [
            { title: t('g.agent'), cell: r => h('span', null, r.name || '–', h('br'), h('span', { class: 'muted small' }, `${r.platform || ''}${r.agentEnabled === false ? ` · ${t('g.disabled')}` : ''}`)), text: r => r.name },
            { title: t('g.bpId'), cell: r => mono(r.blueprintAppId), text: r => r.blueprintAppId },
            { title: t('g.agentId'), cell: r => mono(r.agentId), text: r => r.agentId },
            { title: t('g.userId'), cell: r => mono(r.agentUserId), text: r => r.agentUserId },
            { title: t('g.caAgent'), cell: r => caCell(r.caIdentity), text: r => r.caIdentity && code('ca', r.caIdentity.status) },
            { title: t('g.caUser'), cell: r => r.agentUserId ? caCell(r.caUser) : h('span', { class: 'muted' }, t('g.noUser')), text: r => r.caUser ? code('ca', r.caUser.status) : '' }],
          detail: r => dl([
            [t('g.blueprint'), r.blueprintName ? `${r.blueprintName}${r.blueprintPublisher ? ` (${r.blueprintPublisher})` : ''}` : (r.blueprintAppId ? t('g.bpInvisible') : null)],
            [t('g.bpObj'), [r.blueprintId, r.blueprintPrincipalId].filter(Boolean).join(' / ') || null],
            [t('g.agentApp'), r.agentAppId], [t('g.agentUser'), r.agentUserUpn], [t('g.sponsors'), arr(r.sponsors).length ? list(r.sponsors) : t('none')],
            [t('g.publisher2'), r.publisher || null], [t('g.blocked'), r.blocked === true ? t('yes') : null], [t('g.availability'), r.availableTo ? `${r.availableTo} / ${r.deployedTo || '–'}` : null],
            [t('g.sources'), arr(r.sources).map(s => code('src', s)).join(', ')], [t('g.defStatus'), [r.publishedStatus, r.lifecycle, r.availability].filter(Boolean).join(' · ') || null], [t('g.created'), fmtDate(r.created)],
            [t('g.owners'), arr(r.owners).length ? list(r.owners) : null], [t('g.model'), r.model || null], [t('g.version'), r.version || null], [t('g.instances'), r.instanceCount ?? null],
            [t('g.guardrails'), r.guardrails === null || r.guardrails === undefined ? null : (r.guardrails === 0 ? h('span', { class: 'state warn' }, t('none')) : String(r.guardrails))],
            [t('g.tools'), r.tools === null && r.dataSources === null ? null : `${r.tools ?? '–'} / ${r.dataSources ?? '–'}`],
            [t('g.permissions'), r.permissions ?? null], [t('g.sharedWith'), r.sharedWith ?? null],
            [t('g.endpoints'), arr(r.endpoints).length ? list(arr(r.endpoints).map(e => `${e.url || '?'}${e.transport ? ` – ${e.transport}` : ''}${e.external ? ` (${t('g.external')})` : ''}`)) : null],
            [t('g.mcpList'), arr(r.mcpServers).length ? list(arr(r.mcpServers).map(m => `${m.name || '?'}${m.kind ? ` – ${m.kind}` : ''}${m.endpoint && m.endpoint !== m.name ? ` – ${m.endpoint}` : ''}`)) : null],
            [t('g.connected'), arr(r.connectedAgents).length ? list(r.connectedAgents) : null], [t('g.channels'), arr(r.channels).length ? arr(r.channels).join(', ') : null],
            [t('g.caPolAgent'), arr(r.caIdentity && r.caIdentity.policies).length ? list(arr(r.caIdentity.policies).map(caPolicyLine)) : t('none')],
            [t('g.caPolUser'), r.caUser ? (arr(r.caUser.policies).length ? list(arr(r.caUser.policies).map(caPolicyLine)) : t('none')) : null]]),
          empty: t('g.none.cloud')
        }));
        const bps = arr(ag.blueprints);
        if (bps.length) {
          main.append(h('h2', null, t('g.blueprints')), dataTable({
            name: 'blueprints', rows: bps, search: r => `${r.name} ${r.appId} ${r.publisher || ''}`,
            columns: [
              { title: t('g.blueprint'), text: r => r.name },
              { title: t('g.bpAppId'), cell: r => h('span', { class: 'mono small' }, r.appId), text: r => r.appId },
              { title: t('g.publisher'), text: r => r.publisher || '–' },
              { title: t('g.agents'), text: r => r.agents }]
          }));
        }
      }
      main.append(warningsBlock(ag.warnings) || '');
    },

    async agentca(main) {
      main.append(h('h1', null, t('c.title')), h('p', { class: 'lede' }, t('c.lede')));
      let ag; try { ag = await loadAgents(); } catch (e) { main.append(noData(e, 'agents')); return; }
      const pols = arr(ag.policies);
      const targetText = (r) => arr(r.targets).map(x => t(`tg.${x.code}`, x.count || x.rule || '')).join('; ') + (r.excludes ? t('c.excludes', r.excludes) : '');
      const resText = (r) => !r.resources ? '–' : (L[`res.${r.resources}`] ? t(`res.${r.resources}`) : t('res.n', r.resources));
      main.append(dataTable({
        name: 'ca-agents', rows: pols, sort: (a, b) => String(a.state).localeCompare(String(b.state)),
        search: r => `${r.name} ${targetText(r)} ${controlsText(r)}`,
        columns: [
          { title: t('c.policy'), text: r => r.name },
          { title: t('c.state'), cell: r => h('span', { class: r.state === 'Enabled' ? 'state good' : r.state === 'ReportOnly' ? 'state warn' : 'muted' }, code('pst', r.state)), text: r => code('pst', r.state) },
          { title: t('c.target'), text: targetText },
          { title: t('c.resources'), text: resText },
          { title: t('c.effect'), text: controlsText },
          { title: t('c.covers'), text: r => t('c.coversN', r.coveredIdentities, r.coveredUsers) }],
        empty: t('c.none')
      }));
      const weak = (ca) => ca && !['Protected', 'NoAgentId', 'UserContext'].includes(ca.status);
      const open = arr(ag.agents).filter(a => a.agentType !== 'Local' && ((a.agentId && weak(a.caIdentity)) || (a.agentUserId && weak(a.caUser))));
      main.append(h('h2', null, t('c.weak')), h('p', { class: 'muted small' }, t('c.weak.lede')), dataTable({
        name: 'agents-unprotected', rows: open, search: r => `${r.name} ${r.agentId || ''} ${r.agentUserUpn || ''}`,
        columns: [
          { title: t('g.agent'), text: r => r.name },
          { title: t('g.agentId'), cell: r => h('span', { class: 'mono small' }, r.agentId || '–'), text: r => r.agentId },
          { title: t('g.caAgent'), cell: r => caCell(r.caIdentity), text: r => r.caIdentity && code('ca', r.caIdentity.status) },
          { title: t('g.caUser'), cell: r => r.agentUserId ? caCell(r.caUser) : h('span', { class: 'muted' }, '–'), text: r => r.caUser ? code('ca', r.caUser.status) : '' }],
        empty: t('c.allOk')
      }));
    },

    async baseline(main) {
      main.append(h('h1', null, t('b.title')));
      let ep; try { ep = await loadEndpoint(); } catch (e) { main.append(noData(e, 'endpoint')); return; }
      main.append(h('p', { class: 'lede' }, t('b.lede', tx(ep.baselineName) || 'Wardline', ep.baselineSource === 'custom' ? t('b.src.custom') : t('b.src.default'))));
      const rows = arr(ep.baseline);
      const stClass = s => (s === 'OK' || s === 'Default') ? 'good' : (s === 'NotRelevant' || s === 'NoData') ? '' : (s === 'Inconsistent' ? 'warn' : 'bad');
      main.append(dataTable({
        name: 'baseline', rows, sort: (a, b) => (a.status === 'OK') - (b.status === 'OK') || sevRank(a.severity) - sevRank(b.severity),
        search: r => `${tx(r.title)} ${tx(r.category)} ${r.platform} ${code('st', r.status)}`,
        filters: [
          { label: t('d.platform'), options: [...new Set(rows.map(r => r.platform))].sort(), test: (r, v) => r.platform === v },
          { label: t('b.status'), options: [...new Set(rows.map(r => r.status))].sort(), optionLabel: s => code('st', s), test: (r, v) => r.status === v }],
        columns: [
          { title: t('b.weight'), cell: r => sevCell(r.severity), text: r => code('sev', r.severity) },
          { title: t('b.check'), text: r => tx(r.title) },
          { title: t('d.platform'), text: r => r.platform },
          { title: t('b.target'), text: r => tx(r.expected) },
          { title: t('b.status'), cell: r => h('span', { class: `state ${stClass(r.status)}` }, code('st', r.status)), text: r => code('st', r.status) },
          { title: t('b.devices'), text: r => r.effective ? t('b.devCount', r.effective.good, r.effective.bad) : '–' }],
        detail: r => dl([[t('b.why'), tx(r.rationale)], [t('b.fix'), tx(r.remediation)],
          [t('b.configuredIn'), arr(r.configured).length ? list(arr(r.configured).map(c => `${c.policyName}: ${c.value} – ${c.ok ? t('b.meets') : t('b.deviates')}${c.assigned === false ? t('b.notAssigned') : ''}`)) : t('b.noPolicy')],
          [t('b.setting'), h('span', { class: 'mono' }, r.definitionId || t('b.deviceOnly'))]])
      }));
      if (arr(ep.seenDefenderSettings).length) {
        main.append(h('details', { class: 'warnings' }, h('summary', null, t('b.seen', arr(ep.seenDefenderSettings).length)), h('ul', null, arr(ep.seenDefenderSettings).map(s => h('li', { class: 'mono' }, s)))));
      }
    },

    async access(main) {
      main.append(h('h1', null, t('nav.access')), h('p', { class: 'lede' }, t('r.lede')));
      let ac; try { ac = await loadAccess(); } catch (e) { main.append(noData(e, 'access')); return; }
      const rows = arr(ac.entitlements);
      if (ac.usageObservedSince) main.append(h('p', { class: 'muted small' }, t('r.usageNote', fmtDay(ac.usageObservedSince), ac.unusedDays || 30)));
      const usageCell = r => {
        const cls = r.usage === 'Unused' ? 'tag warn' : r.usage === 'Used' ? 'tag' : 'tag muted';
        return h('span', null, h('span', { class: cls }, code('au', r.usage || 'Unknown')), r.lastUsed ? [' ', h('span', { class: 'muted small' }, fmtDay(r.lastUsed))] : null,
          r.lastActivated ? [h('br'), h('span', { class: 'muted small' }, t('r.activated', fmtDay(r.lastActivated)))] : null);
      };
      main.append(dataTable({
        name: 'access', rows, sort: (a, b) => String(a.displayName).localeCompare(String(b.displayName)) || String(a.role).localeCompare(String(b.role)),
        search: r => `${r.displayName} ${r.upn} ${r.role} ${r.via} ${r.assignment || ''} ${r.scope || ''}`,
        filters: [
          { label: t('r.state'), options: [...new Set(rows.map(r => r.state))].sort(), optionLabel: s => code('rs', s), test: (r, v) => r.state === v },
          { label: t('r.role'), options: [...new Set(rows.map(r => r.role))].sort(), test: (r, v) => r.role === v },
          { type: 'check', label: t('r.onlyPriv'), test: r => r.privileged === true },
          { type: 'check', label: t('r.onlyUnused'), test: r => r.usage === 'Unused' }],
        columns: [
          { title: t('r.person'), cell: r => h('span', null, r.displayName || r.principalId, h('br'), h('span', { class: 'muted small' }, r.upn || r.principalType)), text: r => r.upn || r.displayName },
          { title: t('r.role'), cell: r => h('span', null, r.role, r.privileged === true ? [' ', h('span', { class: 'tag' }, t('r.privileged'))] : null, h('br'), h('span', { class: 'muted small' }, arr(r.permissionGroups).join(', '))), text: r => r.role },
          { title: t('r.state'), text: r => code('rs', r.state) },
          { title: t('r.path'), cell: r => h('span', null, assignText(r.via), r.assignment ? [h('br'), h('span', { class: 'muted small' }, r.assignment)] : null), text: r => assignText(r.via) },
          { title: t('r.scope'), text: r => r.scope },
          { title: t('r.lastUsed'), cell: usageCell, text: r => code('au', r.usage || 'Unknown') },
          { title: t('r.ends'), text: r => r.end ? fmtDay(r.end) : t('unlimited') }],
        empty: t('r.none')
      }));
      const byp = arr(ac.bypass);
      if (byp.length) {
        main.append(h('h2', null, t('r.bypass')), h('p', { class: 'lede' }, t('r.bypass.lede')));
        main.append(dataTable({
          name: 'access-bypass', rows: byp, sort: (a, b) => String(a.level).localeCompare(String(b.level)) || String(a.displayName).localeCompare(String(b.displayName)),
          search: r => `${r.displayName} ${r.upn} ${r.role}`,
          columns: [
            { title: t('r.person'), text: r => r.upn || r.displayName },
            { title: t('r.role'), text: r => r.role },
            { title: t('r.level'), cell: r => h('span', { class: r.level === 'High' ? 'tag warn' : 'tag' }, code('lvl', r.level)), text: r => code('lvl', r.level) },
            { title: t('r.path'), text: r => assignText(r.via) },
            { title: t('r.lastUsed'), text: r => r.lastUsed ? fmtDay(r.lastUsed) : code('au', 'Unknown') }]
        }));
      }
      const aud = arr(ac.audiences);
      if (aud.length) {
        main.append(h('h2', null, t('r.open')), h('p', { class: 'lede' }, t('r.open.lede')));
        main.append(dataTable({
          name: 'open-packages', rows: aud, search: r => `${r.accessPackage} ${r.policy}`,
          columns: [
            { title: t('r.package'), text: r => r.accessPackage },
            { title: t('r.policy'), text: r => r.policy },
            { title: t('r.who'), text: r => code('aud', r.audience) },
            { title: t('r.grants'), text: r => arr(r.grants).map(g => `${g.role} (${code('rs', g.state)})`).join(', ') }]
        }));
      }
      main.append(warningsBlock(ac.warnings) || '');
    },

    async licensing(main, params) {
      main.append(h('h1', null, t('v.licensing')));
      let li; try { li = await loadLicensing(); } catch (e) { main.append(noData(e, 'licensing')); return; }
      const s = li.summary || {};
      main.append(h('p', { class: 'lede' }, t('li.lede', s.observedDays || 30)));
      if (li.detail === 'aggregate') main.append(h('p', { class: 'muted small' }, t('li.aggregate')));
      const active = params.get('tab') || 'overview';
      main.append(tabs('licensing', [['overview', t('li.tab.overview')], ['mde', t('li.sec.mde')], ['mdo', t('li.sec.mdo')]], active));
      const fact = (b, sub, cls) => h('div', { class: `fact${cls ? ` ${cls}` : ''}` }, h('b', null, b), h('span', null, sub));
      const skus = arr(li.skus);
      const mdeSkus = skus.filter(r => !r.product || r.product === 'MDE');
      const mdoSkus = skus.filter(r => r.product === 'MDO');
      const mdoUsers = arr(li.mdoUsers);
      const skuTable = (rows, name, withProduct) => dataTable({
        name, rows, sort: (a, b) => String(a.product || 'MDE').localeCompare(String(b.product || 'MDE')) || String(a.tier).localeCompare(String(b.tier)) || String(a.skuName || a.skuPartNumber).localeCompare(String(b.skuName || b.skuPartNumber)),
        search: r => `${r.skuName || ''} ${r.skuPartNumber} ${r.tier} ${r.product || ''}`,
        columns: [
          withProduct ? { title: t('li.product'), text: r => code('lp', r.product || 'MDE') } : null,
          { title: t('li.sku'), cell: r => h('span', { title: r.skuPartNumber }, r.skuName || r.skuPartNumber, r.skuName && r.skuName !== r.skuPartNumber ? h('div', { class: 'muted mono small' }, r.skuPartNumber) : null), text: r => r.skuName || r.skuPartNumber },
          { title: t('li.tier'), text: r => r.isServer ? t('li.tier.Server') : code('li.tier', r.tier) },
          { title: t('li.enabled'), text: r => num(r.enabled) },
          { title: t('li.consumed'), cell: r => h('span', { class: r.consumed > r.enabled ? 'state bad' : '' }, `${num(r.consumed)}${r.consumed > r.enabled ? ` · ${t('li.over')}` : ''}`), text: r => num(r.consumed) },
          { title: t('li.free'), text: r => num(Math.max(0, (r.enabled || 0) - (r.consumed || 0))) }].filter(Boolean),
        empty: t('li.none')
      });
      const findings = arr(li.findings);
      const caveatsBlock = () => { const cav = arr(li.caveats); return cav.length ? h('details', { class: 'warnings' }, h('summary', null, t('li.caveats')), h('ul', null, cav.map(c => h('li', null, tx(c))))) : null; };

      if (active === 'overview') {
        // One card per product: what is bought, what is assigned, who holds it.
        const card = (title, href, rows, note) => h('a', { class: 'lic-card', href }, h('h3', null, title),
          h('div', { class: 'lic-rows' }, rows.filter(Boolean).map(([k, v, cls]) => h('div', { class: 'lic-row' }, h('span', null, k), h('b', { class: cls || '' }, v)))),
          note ? h('p', { class: 'muted small' }, note) : null);
        const pct = (c, e) => e ? ` (${Math.round(c / e * 100)} %)` : '';
        main.append(h('div', { class: 'lic-cards' },
          card(t('li.sec.mde'), '#/licensing?tab=mde', [
            s.p2Enabled || s.p2Consumed ? [t('li.tier.P2'), `${num(s.p2Consumed)} / ${num(s.p2Enabled)}${pct(s.p2Consumed, s.p2Enabled)}`, s.p2Consumed > s.p2Enabled ? 'bad' : ''] : null,
            s.p1Enabled || s.p1Consumed ? [t('li.tier.P1'), `${num(s.p1Consumed)} / ${num(s.p1Enabled)}${pct(s.p1Consumed, s.p1Enabled)}`, s.p1Consumed > s.p1Enabled ? 'bad' : ''] : null,
            s.mdbEnabled || s.mdbConsumed ? [t('li.tier.MDB'), `${num(s.mdbConsumed)} / ${num(s.mdbEnabled)}${pct(s.mdbConsumed, s.mdbEnabled)}`, s.mdbConsumed > s.mdbEnabled ? 'bad' : ''] : null,
            [t('li.licensedUsers'), num(s.licensedUsers)],
            [t('li.clients'), num(s.clients)],
            [t('li.clientsUnlicensed'), num(s.clientsUnlicensed), s.clientsUnlicensed ? 'bad' : ''],
            [t('li.servers'), num(s.servers)]], t('li.ov.mde.note')),
          card(t('li.sec.mdo'), '#/licensing?tab=mdo', (mdoSkus.length || mdoUsers.length) ? [
            s.mdoP2Enabled || s.mdoP2Consumed ? [t('li.tier.P2'), `${num(s.mdoP2Consumed)} / ${num(s.mdoP2Enabled)}${pct(s.mdoP2Consumed, s.mdoP2Enabled)}`, s.mdoP2Consumed > s.mdoP2Enabled ? 'bad' : ''] : null,
            s.mdoP1Enabled || s.mdoP1Consumed ? [t('li.tier.P1'), `${num(s.mdoP1Consumed)} / ${num(s.mdoP1Enabled)}${pct(s.mdoP1Consumed, s.mdoP1Enabled)}`, s.mdoP1Consumed > s.mdoP1Enabled ? 'bad' : ''] : null,
            [t('li.mdoUsers'), num(s.mdoUsers)],
            s.mdoUsersDisabled ? [t('li.mdoDisabled'), num(s.mdoUsersDisabled), 'warn'] : null,
            s.mdoUsersWithoutMde ? [t('li.mdoWithoutMde'), num(s.mdoUsersWithoutMde)] : null] : [[t('li.mdo.none'), '']], t('li.ov.mdo.note'))));
        main.append(h('h2', null, t('li.skus')), h('p', { class: 'lede' }, t('li.skus.lede')));
        main.append(skuTable(skus, 'lic-skus-all', true));
        if (findings.length) {
          main.append(h('h2', null, t('v.findings')));
          main.append(dataTable({
            name: 'lic-findings', rows: findings, sort: (a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity), search: r => `${tx(r.title)} ${tx(r.detail)}`,
            columns: [
              { title: t('f.severity'), cell: r => sevCell(r.severity), text: r => code('sev', r.severity) },
              { title: t('f.finding'), text: r => tx(r.title) }],
            detail: r => dl([[t('f.description'), tx(r.detail)], [t('f.recommendation'), tx(r.recommendation)]]),
            empty: t('f.none')
          }));
        }
        main.append(caveatsBlock() || '', warningsBlock(li.warnings) || '');
        return;
      }

      if (active === 'mdo') {
        main.append(h('p', { class: 'lede' }, t('li.mdo.lede')));
        if (!mdoSkus.length && !mdoUsers.length) { main.append(h('p', { class: 'muted' }, t('li.mdo.none'))); return; }
        main.append(h('div', { class: 'facts' },
          fact(`${num(s.mdoP2Consumed)} / ${num(s.mdoP2Enabled)}`, `${t('li.tier.P2')} · ${t('li.consumed').toLowerCase()} / ${t('li.enabled').toLowerCase()}`),
          s.mdoP1Enabled || s.mdoP1Consumed ? fact(`${num(s.mdoP1Consumed)} / ${num(s.mdoP1Enabled)}`, `${t('li.tier.P1')} · ${t('li.consumed').toLowerCase()} / ${t('li.enabled').toLowerCase()}`) : null,
          fact(num(s.mdoUsers), t('li.mdoUsers')), fact(num(s.mdoUsersP2), t('li.mdoUsersP2')), s.mdoUsersP1 ? fact(num(s.mdoUsersP1), t('li.mdoUsersP1')) : null,
          s.mdoUsersDisabled ? fact(num(s.mdoUsersDisabled), t('li.mdoDisabled')) : null,
          s.mdoUsersWithoutMde ? fact(num(s.mdoUsersWithoutMde), t('li.mdoWithoutMde')) : null, s.mdeUsersWithoutMdo ? fact(num(s.mdeUsersWithoutMdo), t('li.mdeWithoutMdo')) : null));
        main.append(h('h2', null, t('li.skus')));
        main.append(skuTable(mdoSkus, 'lic-mdo-skus', false));
        main.append(h('h2', null, t('li.mdoUserTable')));
        main.append(dataTable({
          name: 'lic-mdo-users', rows: mdoUsers, sort: (a, b) => String(b.tier).localeCompare(String(a.tier)) || String(a.upn).localeCompare(String(b.upn)),
          search: r => `${r.upn} ${r.displayName || ''} ${r.tier} ${r.mdeTier || ''}`,
          filters: [
            { label: t('li.tier'), options: [...new Set(mdoUsers.map(r => r.tier))].sort(), optionLabel: v => code('li.tier', v), test: (r, v) => r.tier === v },
            { type: 'check', label: t('li.mdoWithoutMde'), test: r => !r.mdeTier }],
          columns: [
            { title: t('li.user'), cell: r => h('span', null, r.displayName || r.upn, r.displayName && r.upn !== r.displayName ? [h('br'), h('span', { class: 'muted small' }, r.upn)] : null), text: r => r.upn },
            { title: t('li.tier'), text: r => code('li.tier', r.tier) },
            { title: t('li.mdeTier'), cell: r => h('span', { class: r.mdeTier ? '' : 'muted' }, r.mdeTier ? code('li.tier', r.mdeTier) : '–'), text: r => r.mdeTier ? code('li.tier', r.mdeTier) : '' },
            { title: t('li.state'), cell: r => h('span', { class: `state ${r.state === 'InUse' ? 'good' : 'warn'}` }, code('lu', r.state)), text: r => code('lu', r.state) }],
          empty: t('li.none')
        }));
        main.append(caveatsBlock() || '');
        return;
      }

      // ---- Defender for Endpoint ----
      main.append(h('p', { class: 'muted small' }, t('li.window', s.observedDays || 30, s.devicesPerUser || 5)));
      main.append(h('div', { class: 'facts' },
        fact(num(s.licensedUsers), t('li.licensedUsers')), fact(num(s.clients), t('li.clients')),
        fact(num(s.clientsLicensed), code('ls', 'Licensed')), fact(num(s.clientsUnlicensed), t('li.clientsUnlicensed')), fact(num(s.clientsNoUserPersonal !== undefined ? s.clientsNoUserPersonal : s.clientsNoUser), t(s.clientsNoUserPersonal !== undefined ? 'li.clientsNoUserPersonal' : 'li.clientsNoUser')),
        s.clientsShared !== undefined ? fact(num((s.clientsShared || 0) + (s.clientsKiosk || 0) + (s.clientsVdi || 0)), t('li.clientsShared')) : null,
        s.serviceAccounts ? fact(num(s.serviceAccounts), t('li.svcAccounts')) : null,
        fact(num(s.usersNoDevice), t('li.usersNoDevice')), fact(num(s.usersOverLimit), t('li.usersOver', s.devicesPerUser || 5)),
        s.clientsP1Only ? fact(num(s.clientsP1Only), t('li.p1only')) : null, fact(num(s.servers), t('li.servers'))));

      // Purchased plans (MDE)
      main.append(h('h2', null, t('li.skus')));
      main.append(skuTable(mdeSkus, 'lic-skus', false));

      // Client devices
      const devs = arr(li.devices);
      const confText = d => code('lc', d.confidence || 'None');
      const usersCell = d => arr(d.users).length ? h('span', null, arr(d.users).map((u, i) => [i ? ', ' : null, h('span', { class: u.tier ? '' : 'muted' }, u.upn || u.displayName || '–', u.tier ? ` (${code('li.tier', u.tier)})` : '')])) : h('span', { class: 'muted' }, '–');
      main.append(h('h2', null, t('li.devices')), h('p', { class: 'lede' }, t('li.devices.lede')));
      main.append(dataTable({
        name: 'lic-devices', rows: devs, sort: (a, b) => (['Unlicensed', 'NoUser', 'Licensed'].indexOf(a.state) - ['Unlicensed', 'NoUser', 'Licensed'].indexOf(b.state)) || String(a.deviceName).localeCompare(String(b.deviceName)),
        search: r => `${r.deviceName} ${r.os || ''} ${r.deviceGroup || ''} ${arr(r.users).map(u => u.upn).join(' ')} ${r.licensedBy || ''} ${r.usage || ''}`,
        filters: [
          { label: t('li.state'), options: [...new Set(devs.map(r => r.state))].sort(), optionLabel: v => code('ls', v), test: (r, v) => r.state === v },
          { label: t('li.usage'), options: [...new Set(devs.map(r => r.usage || 'Personal'))].sort(), optionLabel: v => code('lg', v), test: (r, v) => (r.usage || 'Personal') === v },
          { label: t('d.platform'), options: [...new Set(devs.map(r => r.os).filter(Boolean))].sort(), test: (r, v) => r.os === v },
          { type: 'check', label: t('li.onlyUnlicensed'), test: r => r.state !== 'Licensed' }],
        columns: [
          { title: t('d.device'), cell: r => deviceLink(r.deviceId, r.deviceName), text: r => r.deviceName },
          { title: t('d.platform'), text: r => r.os },
          { title: t('li.state'), cell: r => h('span', { class: `state ${r.state === 'Licensed' ? 'good' : r.state === 'Unlicensed' ? 'bad' : 'warn'}` }, code('ls', r.state)), text: r => code('ls', r.state) },
          { title: t('li.usage'), cell: r => h('span', { class: (r.usage || 'Personal') === 'Personal' ? 'muted' : 'state warn', title: arr(r.usageReasons).join('\n') }, code('lg', r.usage || 'Personal')), text: r => code('lg', r.usage || 'Personal') },
          { title: t('li.tier'), text: r => r.tier ? code('li.tier', r.tier) : '–' },
          { title: t('li.users'), cell: usersCell, text: r => arr(r.users).map(u => u.upn).join(', ') },
          { title: t('li.confidence'), text: confText },
          { title: t('d.lastSeen'), text: r => fmtDate(r.lastSeen) }],
        detail: r => dl([[t('li.licensedBy'), r.licensedBy || null], [t('li.usage.why'), arr(r.usageReasons).length ? list(arr(r.usageReasons)) : null], [t('li.distinctUsers'), r.distinctUsers !== undefined ? num(r.distinctUsers) : null],
          [t('li.serviceAccounts'), arr(r.serviceAccounts).length ? list(arr(r.serviceAccounts)) : null], [t('li.model'), r.model || null], [t('d.group'), r.deviceGroup || null], [t('d.aad'), r.aadDeviceId ? h('span', { class: 'mono small' }, r.aadDeviceId) : null]]),
        empty: t('li.none')
      }));

      // Licensed users
      const users = arr(li.users);
      main.append(h('h2', null, t('li.userTable')), h('p', { class: 'lede' }, t('li.userTable.lede')));
      main.append(dataTable({
        name: 'lic-users', rows: users, sort: (a, b) => (b.deviceCount || 0) - (a.deviceCount || 0) || String(a.upn).localeCompare(String(b.upn)),
        search: r => `${r.upn} ${r.displayName || ''} ${r.tier} ${arr(r.devices).join(' ')}`,
        filters: [
          { label: t('li.tier'), options: [...new Set(users.map(r => r.tier))].sort(), optionLabel: v => code('li.tier', v), test: (r, v) => r.tier === v },
          { label: t('li.state'), options: [...new Set(users.map(r => r.state))].sort(), optionLabel: v => v === 'OverLimit' ? t('lu.OverLimit', s.devicesPerUser || 5) : code('lu', v), test: (r, v) => r.state === v },
          { type: 'check', label: t('li.onlyNoDevice'), test: r => r.state === 'NoDevice' }],
        columns: [
          { title: t('li.user'), cell: r => h('span', null, r.displayName || r.upn, r.displayName && r.upn !== r.displayName ? [h('br'), h('span', { class: 'muted small' }, r.upn)] : null), text: r => r.upn },
          { title: t('li.tier'), text: r => code('li.tier', r.tier) },
          { title: t('li.state'), cell: r => h('span', { class: `state ${r.state === 'InUse' ? 'good' : r.state === 'OverLimit' ? 'bad' : 'warn'}` }, r.state === 'OverLimit' ? t('lu.OverLimit', s.devicesPerUser || 5) : code('lu', r.state)), text: r => code('lu', r.state) },
          { title: t('li.deviceCount'), text: r => num(r.deviceCount || 0) },
          { title: t('li.sharedDeviceCount'), cell: r => h('span', { class: r.sharedDeviceCount ? '' : 'muted', title: t('li.sharedDevices.hint') }, num(r.sharedDeviceCount || 0)), text: r => num(r.sharedDeviceCount || 0) }],
        detail: r => dl([[t('li.deviceCount'), arr(r.devices).length ? list(arr(r.devices)) : null], [t('li.sharedDeviceCount'), arr(r.sharedDevices).length ? list(arr(r.sharedDevices)) : null]]),
        empty: t('li.none')
      }));

      // Servers (separate licensing)
      const srv = arr(li.servers);
      if (srv.length) {
        main.append(h('h2', null, t('li.serversTable')), h('p', { class: 'lede' }, t('li.servers.lede')));
        main.append(dataTable({
          name: 'lic-servers', rows: srv, sort: (a, b) => String(a.deviceName).localeCompare(String(b.deviceName)), search: r => `${r.deviceName} ${r.os || ''} ${r.deviceGroup || ''}`,
          columns: [
            { title: t('d.device'), cell: r => deviceLink(r.deviceId, r.deviceName), text: r => r.deviceName },
            { title: t('d.platform'), text: r => r.os }, { title: t('d.group'), text: r => r.deviceGroup || '–' }, { title: t('d.lastSeen'), text: r => fmtDate(r.lastSeen) }]
        }));
      }
      main.append(caveatsBlock() || '', warningsBlock(li.warnings) || '');
    },

    async whocan(main, params) {
      main.append(h('h1', null, t('v.whocan')), h('p', { class: 'lede' }, t('w.lede')));
      let ac; try { ac = await loadAccess(); } catch (e) { main.append(noData(e, 'access')); return; }
      const input = h('input', { type: 'search', placeholder: t('w.input'), 'aria-label': t('w.input'), value: params.get('q') || '' });
      const out = h('div');
      const covers = (action, q) => {
        const a = action.toLowerCase();
        if (a.includes(q)) return true;
        const base = a.replace(/\/(allproperties\/)?alltasks$/, '/');
        return q.startsWith('microsoft.') && base.endsWith('/') && q.startsWith(base);
      };
      // All rows: unified RBAC entitlements + Entra roles that bypass unified RBAC (role id "entra:<name>")
      const all = [...arr(ac.entitlements),
        ...arr(ac.bypass).map(b => ({ ...b, roleId: `entra:${b.role}`, role: `${b.role} (Entra)`, entra: true }))];
      // Role list for multi-select: every unified RBAC role (also unassigned ones) + Entra bypass roles in use
      const roleList = [...arr(ac.roles).map(r => ({ id: r.id, name: r.name, actions: arr(r.actions), entra: false })),
        // all Entra roles that bypass unified RBAC – also unassigned ones (older snapshots: only the ones in use)
        ...[...new Set([...arr(ac.bypassRoles).map(b => `entra:${b.name}`), ...all.filter(r => r.entra).map(r => r.roleId)])]
          .map(id => ({ id, name: `${id.slice(6)} (Entra)`, actions: [], entra: true }))]
        .sort((a, b) => (a.entra - b.entra) || a.name.localeCompare(b.name));
      const count = id => new Set(all.filter(r => r.roleId === id).map(r => r.principalId)).size;
      const selected = new Set((params.get('roles') || '').split(',').filter(Boolean));
      let personSel = null;

      // People picker with autocomplete (users and groups behind the assignments)
      const people = new Map();
      for (const r of all) if (r.principalId && !people.has(r.principalId)) people.set(r.principalId, { id: r.principalId, name: r.displayName || r.upn || r.principalId, upn: r.upn || '', type: r.principalType || 'user' });
      const sugg = h('div', { class: 'ac-list', role: 'listbox' });
      const pick = p => { personSel = p; input.value = p.name; sugg.replaceChildren(); run(); };
      input.setAttribute('autocomplete', 'off');
      input.addEventListener('input', () => {
        personSel = null;
        const q = input.value.trim().toLowerCase();
        sugg.replaceChildren();
        if (q.length >= 1) {
          const hits = [...people.values()].filter(p => `${p.name} ${p.upn}`.toLowerCase().includes(q)).slice(0, 8);
          for (const p of hits) sugg.append(h('button', { type: 'button', class: 'ac-item', role: 'option', onclick: () => pick(p) },
            h('span', { class: `chip-type chip-${p.type}` }, p.type === 'group' ? t('w.group') : t('w.user')), ' ', h('strong', null, p.name), p.upn ? h('span', { class: 'muted small' }, ` ${p.upn}`) : null));
        }
        clearTimeout(run._t); run._t = setTimeout(run, 200);
      });
      input.addEventListener('keydown', e => { if (e.key === 'Enter') { const f = sugg.querySelector('.ac-item'); if (f) { e.preventDefault(); f.click(); } } if (e.key === 'Escape') sugg.replaceChildren(); });

      // Role chips (multi-select)
      const chips = h('div', { class: 'role-chips' });
      const drawChips = () => chips.replaceChildren(
        ...roleList.map(r => h('button', {
          type: 'button', class: `role-chip${selected.has(r.id) ? ' on' : ''}${r.entra ? ' entra' : ''}`, 'aria-pressed': String(selected.has(r.id)),
          title: r.actions.slice(0, 12).join('\n'),
          onclick: () => { selected.has(r.id) ? selected.delete(r.id) : selected.add(r.id); drawChips(); run(); }
        }, r.name, h('span', { class: 'role-chip-n' }, String(count(r.id))))),
        selected.size ? h('button', { type: 'button', class: 'link', onclick: () => { selected.clear(); drawChips(); run(); } }, t('w.clear')) : null);
      drawChips();

      main.append(h('div', { class: 'toolbar ac' }, input, sugg), h('h3', null, t('w.pickRoles')), chips, out);

      function run() {
        const q = input.value.trim().toLowerCase();
        out.replaceChildren();
        // Free text that is not a person: match role names / permissions (e.g. "liveresponse", "microsoft.xdr/...")
        const textRoles = !personSel && q.length >= 3 ? roleList.filter(r => r.name.toLowerCase().includes(q) || r.actions.some(a => covers(a, q)) || (r.entra && q.startsWith('microsoft.'))) : [];
        const textPeople = !personSel && q.length >= 2 ? new Set([...people.values()].filter(p => `${p.name} ${p.upn}`.toLowerCase().includes(q)).map(p => p.id)) : new Set();
        const roleIds = new Set([...selected, ...textRoles.map(r => r.id)]);
        if (!roleIds.size && !personSel && !textPeople.size) {
          out.append(h('div', { class: 'empty' }, q.length ? t('w.noRole') : t('w.start'))); return;
        }
        const rows = all.filter(r => {
          const roleOk = !roleIds.size || roleIds.has(r.roleId);
          const personOk = personSel ? r.principalId === personSel.id : (textPeople.size && !selected.size && !textRoles.length ? textPeople.has(r.principalId) : true);
          return roleOk && personOk;
        });
        if (textRoles.length && !selected.size) out.append(h('p', null, t('w.roles', textRoles.map(r => r.name).join(', '))));
        if (rows.some(r => r.entra)) out.append(h('p', { class: 'muted' }, t('w.bypass')));
        const kinds = r => r.entra ? 'Entra' : /PIM/i.test(r.via || '') || r.state === 'Eligible' ? 'PIM' : /Access package/i.test(r.via || '') ? 'Access package' : /^Group/i.test(r.via || '') ? t('w.group') : t('w.direct');
        out.append(dataTable({
          name: 'who-can', rows, sort: (a, b) => String(a.displayName).localeCompare(String(b.displayName)) || String(a.role).localeCompare(String(b.role)),
          search: r => `${r.displayName} ${r.upn} ${r.role} ${r.via}`,
          filters: [
            { label: t('r.state'), options: [...new Set(rows.map(r => r.state))].sort(), optionLabel: s => code('rs', s), test: (r, v) => r.state === v },
            { label: t('w.kind'), options: [...new Set(rows.map(kinds))].sort(), test: (r, v) => kinds(r) === v }],
          columns: [
            { title: t('r.person'), cell: r => h('span', null, r.displayName || r.principalId, h('br'), h('span', { class: 'muted small' }, r.upn || r.principalType)), text: r => r.upn || r.displayName },
            { title: t('r.role'), text: r => r.role },
            { title: t('r.state'), text: r => code('rs', r.state) },
            { title: t('w.kind'), text: kinds },
            { title: t('r.path'), cell: r => h('span', null, assignText(r.via), r.assignment ? [h('br'), h('span', { class: 'muted small' }, r.assignment)] : null), text: r => assignText(r.via) },
            { title: t('r.ends'), text: r => r.end ? fmtDate(r.end) : (r.state === 'Active' ? t('w.permanent') : '–') }],
          empty: t('w.nobody')
        }));
      }
      run();
    },

    async mine(main) {
      main.append(h('h1', null, t('v.mine')), h('p', { class: 'lede' }, t('m.lede')));
      let m; try { m = state.mine || (state.mine = await api('access/me')); } catch (e) { main.append(noData(e, 'access')); return; }
      const ents = arr(m.entitlements);
      const tenant = m.tenantId || (state.me && state.me.tenantId) || '';
      const pimUrl = 'https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadmigratedroles';
      const myAccess = id => `https://myaccess.microsoft.com/@${encodeURIComponent(tenant)}#/access-packages/${encodeURIComponent(id || '')}`;
      const group = (title, intro, items, action) => h('section', null, h('h2', null, title), h('p', { class: 'muted' }, intro),
        items.length ? h('div', null, items.map(e => h('div', { class: 'right' }, h('span', { class: 'role' }, e.role, e.privileged === true ? [' ', h('span', { class: 'tag' }, t('r.privileged'))] : null), h('span', { class: 'via' }, `${assignText(e.via)}${e.scope ? ` · ${e.scope}` : ''}${e.end ? t('m.until', fmtDay(e.end)) : ''}`), action ? action(e) : null)))
          : h('p', { class: 'empty' }, t('m.none')));
      main.append(h('div', { class: 'rights' },
        group(t('m.active'), t('m.active.i'), ents.filter(e => e.state === 'Active' || e.state === 'Activated')),
        group(t('m.pim'), t('m.pim.i'), ents.filter(e => e.state === 'Eligible'), () => h('a', { href: pimUrl, target: '_blank', rel: 'noopener' }, t('m.activate'))),
        group(t('m.req'), t('m.req.i'), ents.filter(e => e.state === 'Requestable'), e => h('a', { href: myAccess(e.accessPackageId), target: '_blank', rel: 'noopener' }, t('m.request'))),
        arr(m.audiences).length ? h('section', null, h('h2', null, t('m.all')), h('p', { class: 'muted' }, t('m.all.i')),
          h('div', null, arr(m.audiences).map(a => h('div', { class: 'right' }, h('span', { class: 'role' }, a.accessPackage), h('span', { class: 'via' }, arr(a.grants).map(g => `${g.role} (${code('rs', g.state)})`).join(', ')), h('a', { href: myAccess(a.accessPackageId), target: '_blank', rel: 'noopener' }, t('m.request')))))) : null));
      main.append(h('p', { class: 'muted small' }, t('m.asof', fmtDate(m.generatedAt))));
    },

    async license(main) {
      main.append(h('h1', null, t('v.license')), h('p', { class: 'lede' }, t('lic.lede', num(communityRows() || 10))));
      let l; try { l = await api('license'); } catch (e) { main.append(noData(e, 'endpoint')); return; }
      const st = h('span', { class: `state ${l.status === 'Valid' ? 'good' : l.status === 'ExpiringSoon' || l.status === 'None' ? 'warn' : 'bad'}` }, code('lic.st', l.status));
      main.append(h('div', { class: 'detail card' }, dl([
        [t('lic.status'), h('span', null, st, l.daysLeft !== null && l.daysLeft !== undefined && l.daysLeft >= 0 && l.status !== 'Expired' ? h('span', { class: 'muted' }, ` · ${t('lic.days', l.daysLeft)}`) : null)],
        [t('lic.customer'), l.customer], [t('lic.plan'), l.plan ? code('lic.plan', l.plan) : null], [t('lic.expires'), l.expires ? fmtDay(l.expires) : null],
        [t('lic.id'), l.licenseId ? h('span', { class: 'mono' }, l.licenseId) : null], [t('lic.tenant'), l.tenantId ? h('span', { class: 'mono' }, l.tenantId) : (state.me.tenantId || null)],
        [t('lic.source'), l.source === 'Portal' ? t('lic.src.Portal', l.setBy || '–', fmtDate(l.setAt)) : l.source ? t('lic.src.AppSetting') : null]])));
      const ta = h('textarea', { rows: '4', spellcheck: 'false', autocomplete: 'off', class: 'mono', placeholder: 'WL1.…', 'aria-label': t('lic.key') });
      const form = h('form', { class: 'license-form' }, h('label', null, t('lic.key'), ta),
        h('div', { class: 'accept-actions' }, h('button', { type: 'submit', class: 'primary' }, t('lic.save')), h('a', { class: 'btn', href: 'https://wardline.cloud/pricing', target: '_blank', rel: 'noopener noreferrer' }, t('lic.buy'))));
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
          const r = await api('license', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: ta.value.trim() }) });
          if (r && r.status) { state.me.license = { status: r.status, plan: r.plan, customer: r.customer, expires: r.expires, daysLeft: r.daysLeft }; renderChrome(); }
          toast(r && r.message ? r.message : t('lic.saved')); route();
        } catch (err) { toast(t('error', err.message)); }
      });
      main.append(h('h2', null, t('lic.enter')), form);
    },

    async changes(main, params) {
      main.append(h('h1', null, t('v.changes')), h('p', { class: 'lede' }, t('ch.lede')));
      const mod = modules().includes(params.get('module')) ? params.get('module') : 'endpoint';
      main.append(h('div', { class: 'tabs', role: 'tablist' }, modules().map(id => h('button', { class: 'tab', role: 'tab', type: 'button', 'aria-selected': String(id === mod), onclick: () => { location.hash = `#/changes?module=${id}`; } }, code('mod', id)))));
      let rows; try { rows = state.changes[mod] || (state.changes[mod] = await api(`changes?module=${mod}`)); } catch (e) { main.append(noData(e, mod)); return; }
      rows = arr(rows);
      const area = (r) => code('coll', r.collection);
      const days = [...new Set(rows.map(r => dayKey(r.at)).filter(Boolean))].sort().reverse();
      const table = dataTable({
        name: `changes-${mod}`, rows,
        search: r => `${tx(r.label)} ${r.before || ''} ${r.after || ''}`,
        filters: [
          { label: t('ch.day'), options: days, optionLabel: dayShort, test: (r, v) => dayKey(r.at) === v },
          { label: t('ch.kind'), options: ['Added', 'Changed', 'Removed'], optionLabel: c => code('ch', c), test: (r, v) => r.change === v },
          { label: t('ch.area'), options: [...new Set(rows.map(r => r.collection))].sort(), optionLabel: c => code('coll', c), test: (r, v) => r.collection === v }],
        rowClass: r => `chg-row chg-row-${r.change}`,
        columns: [
          { title: t('col.time'), text: r => fmtDate(r.at) },
          { title: t('ch.kind'), cell: changeKind, text: r => code('ch', r.change) },
          { title: t('ch.area'), text: area },
          { title: t('ch.what'), text: r => tx(r.label) },
          { title: t('ch.before'), cell: r => changeCells(r).before, text: r => r.before || '–' },
          { title: t('ch.after'), cell: r => changeCells(r).after, text: r => r.after || '–' }],
        empty: t('ch.none')
      });
      if (rows.length) {
        // Changes per day: from the first change (at least 14, at most 90 days)
        const first = days.length ? days[days.length - 1] : dayKey(new Date());
        const span = Math.min(90, Math.max(14, Math.round((Date.now() - new Date(`${first}T12:00:00`)) / 864e5) + 1));
        const byDay = {};
        for (const r of rows) {
          const k = dayKey(r.at); if (!k) continue;
          const b = byDay[k] || (byDay[k] = { values: {}, areas: {} });
          b.values[r.change] = (b.values[r.change] || 0) + 1;
          b.areas[r.collection] = (b.areas[r.collection] || 0) + 1;
        }
        const buckets = lastDays(span).map(k => ({
          id: k, label: dayShort(k), title: dayLong(k), values: (byDay[k] || {}).values || {},
          items: Object.entries((byDay[k] || {}).areas || {}).sort((a, b) => b[1] - a[1]).map(([c, n]) => `${code('coll', c)}: ${num(n)}`)
        }));
        const daySel = table.querySelector('select');
        main.append(columnChart({
          width: Math.max(480, contentWidth() - 30), title: t('ch.chart'), buckets, keys: DRIFT_KEYS(), note: t('ch.chart.hint'),
          onSelect: b => { daySel.value = b.id; daySel.dispatchEvent(new Event('change')); table.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
        }));
      }
      main.append(table);
      if (params.get('day') && days.includes(params.get('day'))) { const sel = table.querySelector('select'); sel.value = params.get('day'); sel.dispatchEvent(new Event('change')); }
    }
  };

  const NAV = [
    { group: 'nav.endpoint', admin: true, items: ['overview', 'findings', 'exclusions', 'asr', 'devices', 'baseline'] },
    { group: 'nav.agents', admin: true, module: 'agents', items: ['agents', 'agentca'] },
    { group: 'nav.access', admin: true, module: 'access', items: ['access', 'whocan'] },
    { group: 'nav.licensing', admin: true, module: 'licensing', items: ['licensing'] },
    { group: 'nav.everyone', admin: false, module: 'access', items: ['mine'] },
    { group: 'nav.history', admin: true, items: ['changes', 'accepted'] },
    { group: 'nav.settings', admin: true, items: ['license'] }
  ];
  const VIEW_MODULE = { agents: 'agents', agentca: 'agents', access: 'access', whocan: 'access', mine: 'access', licensing: 'licensing' };
  const NAV_ALIAS = { device: 'devices' };
  let navCollapsed = {};
  try { navCollapsed = JSON.parse(localStorage.getItem('wardline-nav') || '{}') || {}; } catch { navCollapsed = {}; }
  const navGroupOf = (view) => { const v = NAV_ALIAS[view] || view; const g = NAV.find(g => g.items.includes(v)); return g ? g.group : null; };

  function renderNav() {
    const isAdmin = state.me && state.me.isAdmin;
    const active = navGroupOf(state.view);
    const groups = NAV.filter(g => (isAdmin || !g.admin) && (!g.module || hasMod(g.module)));
    $('#nav').replaceChildren(...groups.map(g => {
      const open = g.group === active || !navCollapsed[g.group];
      const btn = h('button', { type: 'button', class: 'nav-group-title', 'aria-expanded': String(open), onclick: () => { navCollapsed[g.group] = open; try { localStorage.setItem('wardline-nav', JSON.stringify(navCollapsed)); } catch { /* ignore */ } renderNav(); } },
        h('span', null, t(g.group)), h('span', { class: 'chev', 'aria-hidden': 'true' }, '›'));
      const links = g.items.map(id => h('a', { class: 'nav-link', href: `#/${id}`, 'data-view': id, onclick: () => closeDrawer() }, t(`v.${id}`)));
      if (state.view && (NAV_ALIAS[state.view] || state.view) && g.items.includes(NAV_ALIAS[state.view] || state.view)) links.forEach(a => { if (a.dataset.view === (NAV_ALIAS[state.view] || state.view)) a.setAttribute('aria-current', 'page'); });
      return h('div', { class: `nav-group${open ? '' : ' collapsed'}` }, btn, h('div', { class: 'nav-items' }, links));
    }));
  }
  function closeDrawer() { document.body.classList.remove('nav-open'); const b = $('#menu-btn'); if (b) b.setAttribute('aria-expanded', 'false'); }
  function toggleDrawer() { const open = document.body.classList.toggle('nav-open'); const b = $('#menu-btn'); if (b) b.setAttribute('aria-expanded', String(open)); }

  async function runNow(module, btn) {
    if (btn) btn.disabled = true;
    try {
      const r = await api(`run?module=${module}`, { method: 'POST' });
      toast(window.WARDLINE_DEMO ? r.message : t('run.started'));
    } catch (e) {
      const detail = e.status && !new RegExp(`\\b${e.status}\\b`).test(e.message || '') ? `${e.message} (HTTP ${e.status})` : e.message;
      toast(e.status === 403 && !/Wardline.Admin/.test(e.message) ? t('run.403') : t('run.failed', detail));
    }
    finally { if (btn) setTimeout(() => { btn.disabled = false; }, 4000); }
  }

  function setLang(l) {
    lang = LANGS[l] ? l : 'en';
    try { localStorage.setItem('wardline-lang', lang); } catch { /* storage not available */ }
    document.documentElement.lang = lang;
    renderChrome();
    route();
  }

  function renderChrome() {
    const isAdmin = state.me && state.me.isAdmin;
    document.documentElement.lang = lang;
    const skip = document.querySelector('.skip'); if (skip) skip.textContent = lang === 'de' ? 'Zum Inhalt springen' : 'Skip to content';
    renderNav();
    const mb = $('#menu-btn'); if (mb) { mb.setAttribute('aria-label', t('nav.menu')); mb.onclick = toggleDrawer; }
    const sc = $('#scrim'); if (sc) sc.onclick = closeDrawer;
    $('#who').replaceChildren(h('strong', null, state.me.displayName || state.me.upn || t('signed.in')), h('span', null, isAdmin ? t('role.admin') : t('role.user')), h('br'), h('a', { href: '/.auth/logout', style: 'color:#A9D9DE' }, t('signout')));
    const up = state.me.update;
    $('#who').append(h('div', { class: 'version' }, state.me.version ? t('version', state.me.version) : null,
      isAdmin && up && up.available && /^https:\/\/github\.com\//.test(up.url || '') ? h('a', { class: 'update-link', href: up.url, target: '_blank', rel: 'noopener noreferrer' }, t('update.available', up.latest)) : null,
      isAdmin && state.me.license ? h('a', { class: `license-link lic-${state.me.license.status}`, href: '#/license' }, t('lic.side', licenseShort(state.me.license))) : null));
    renderNotice();
    renderAssistant();
    const langSel = h('select', { 'aria-label': t('language'), onchange: (e) => setLang(e.target.value) }, Object.entries(LANGS).map(([k, v]) => { const o = h('option', { value: k }, v); if (k === lang) o.selected = true; return o; }));
    const actions = $('#actions');
    actions.replaceChildren(h('label', { class: 'lang-switch' }, t('language'), langSel));
    if (isAdmin) {
      actions.append(
        h('button', { type: 'button', onclick: async () => { state.endpoint = state.agents = state.access = state.licensing = state.mine = null; state.changes = {}; await route(); toast(t('reloaded')); } }, t('reload')),
        h('button', { type: 'button', class: 'primary', onclick: (e) => runNow('all', e.currentTarget) }, t('run.now')));
    }
  }

  const licenseShort = (l) => l.status === 'Valid' ? `${code('lic.plan', l.plan)} · ${fmtDay(l.expires)}` : code('lic.st', l.status);

  // ---------- Assistant (optional, WL_ASSISTANT) ----------
  const ai = { history: [], open: false, busy: false };
  function renderAssistant() {
    let fab = $('#ai-fab'), panel = $('#ai-panel');
    const enabled = state.me && state.me.isAdmin && (state.me.assistant || state.me.assistantConfigured) && !window.WARDLINE_DEMO;
    const licensed = Boolean(state.me && state.me.assistant);
    if (!enabled) { if (fab) fab.remove(); if (panel) panel.remove(); return; }
    if (!fab) {
      fab = h('button', { id: 'ai-fab', type: 'button', class: 'ai-fab', onclick: () => { ai.open = !ai.open; renderAssistant(); if (ai.open) { const i = $('#ai-input'); if (i) i.focus(); } } }, '✦');
      document.body.append(fab);
    }
    fab.setAttribute('aria-label', t('ai.open')); fab.title = t('ai.open'); fab.setAttribute('aria-expanded', String(ai.open));
    if (!ai.open) { if (panel) panel.remove(); return; }
    if (!panel) { panel = h('section', { id: 'ai-panel', class: 'ai-panel', role: 'dialog', 'aria-label': t('ai.title') }); document.body.append(panel); }
    const log = h('div', { class: 'ai-log', 'aria-live': 'polite' },
      h('p', { class: 'ai-msg ai-sys' }, licensed ? t('ai.intro') : t('ai.enterprise'), licensed ? null : h('div', { class: 'ai-links' }, h('a', { href: '#/license', onclick: () => { ai.open = false; renderAssistant(); } }, t('v.license')))),
      ai.history.map(m => h('div', { class: `ai-msg ai-${m.role}` }, h('p', null, m.content),
        m.links && m.links.length ? h('div', { class: 'ai-links' }, m.links.map(l => h('a', { href: l.view, onclick: () => { ai.open = false; renderAssistant(); } }, l.label))) : null,
        (m.sources && m.sources.length) || (m.tools && m.tools.length) ? h('p', { class: 'ai-meta muted' },
          m.tools && m.tools.length ? `${t('ai.tools')}: ${m.tools.map(x => x.name).join(', ')}` : '',
          m.sources && m.sources.length ? `${m.tools && m.tools.length ? ' · ' : ''}${t('ai.sources')}: ${m.sources.join('; ')}` : '') : null)),
      ai.busy ? h('p', { class: 'ai-msg ai-assistant muted' }, t('ai.thinking')) : null);
    const input = h('textarea', { id: 'ai-input', rows: 2, placeholder: t('ai.placeholder'), maxlength: 2000, disabled: (ai.busy || !licensed) || null,
      onkeydown: (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); askAssistant(); } } });
    const form = h('form', { class: 'ai-form', onsubmit: (e) => { e.preventDefault(); askAssistant(); } }, input,
      h('div', { class: 'ai-actions' },
        h('button', { type: 'button', class: 'quiet', onclick: () => { ai.history = []; renderAssistant(); } }, t('ai.clear')),
        h('button', { type: 'submit', class: 'primary', disabled: (ai.busy || !licensed) || null }, t('ai.send'))));
    panel.replaceChildren(
      h('header', null, h('strong', null, t('ai.title')), h('button', { type: 'button', class: 'quiet', 'aria-label': t('ai.close'), onclick: () => { ai.open = false; renderAssistant(); } }, '×')),
      log, form, h('p', { class: 'ai-foot muted' }, t('ai.disclaimer')));
    log.scrollTop = log.scrollHeight;
  }
  async function askAssistant() {
    const input = $('#ai-input'); const q = input && input.value.trim();
    if (!q || ai.busy) return;
    const hist = ai.history.map(m => ({ role: m.role, content: m.content }));
    ai.history.push({ role: 'user', content: q }); ai.busy = true; renderAssistant();
    try {
      const r = await api('assistant', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question: q, history: hist.slice(-6), lang }) });
      ai.history.push({ role: 'assistant', content: r.answer || '', links: arr(r.links), sources: arr(r.sources), tools: arr(r.tools) });
    } catch (e) { ai.history.push({ role: 'assistant', content: t('ai.failed', e.message) }); }
    finally { ai.busy = false; renderAssistant(); const i = $('#ai-input'); if (i) i.focus(); }
  }
  function renderNotice() {
    const bar = $('#notice'); if (!bar) return;
    const l = state.me && state.me.isAdmin && state.me.license;
    if (!l || l.status === 'Valid') { bar.hidden = true; bar.replaceChildren(); return; }
    const text = l.status === 'ExpiringSoon' ? t('lic.n.ExpiringSoon', l.daysLeft) : l.status === 'Expired' ? t('lic.n.Expired', fmtDay(l.expires)) : t(`lic.n.${l.status}`, num(communityRows() || 10));
    bar.className = `notice-bar lic-${l.status}`;
    bar.replaceChildren(h('span', null, text), ' ', h('a', { href: '#/license' }, t('lic.n.action')));
    bar.hidden = false;
  }

  function updateMeta() {
    const ep = state.endpoint, ac = state.access, mi = state.mine, ag = state.agents, li = state.licensing;
    const ts = [ep && ep.generatedAt, ag && ag.generatedAt, ac && ac.generatedAt, mi && mi.generatedAt, li && li.generatedAt].filter(Boolean).sort().pop();
    $('#meta').textContent = ts ? t('data.as.of', fmtDate(ts)) : 'Wardline';
  }

  async function route() {
    const raw = location.hash.replace(/^#\/?/, '');
    const [name, query] = raw.split('?');
    const isAdmin = state.me && state.me.isAdmin;
    const fallback = isAdmin ? 'overview' : (hasMod('access') ? 'mine' : 'noaccess');
    let view = name || fallback;
    if (!views[view] || (!isAdmin && view !== 'mine') || (VIEW_MODULE[view] && !hasMod(VIEW_MODULE[view]))) view = fallback;
    state.view = view;
    renderNav();
    closeDrawer();
    const main = $('#main');
    main.replaceChildren(h('p', { class: 'muted' }, t('loading')));
    const frag = h('div');
    try { await views[view](frag, new URLSearchParams(query || '')); }
    catch (e) { frag.append(h('div', { class: 'empty' }, t('error', e.message))); }
    main.replaceChildren(...frag.childNodes);
    main.focus({ preventScroll: true });
    updateMeta();
  }

  async function init() {
    document.documentElement.lang = lang;
    $('#meta').textContent = t('loading');
    try { state.me = await api('me'); }
    catch (e) { $('#main').replaceChildren(h('div', { class: 'empty' }, t('signin.failed', e.message))); return; }
    renderChrome();
    window.addEventListener('hashchange', route);
    window.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });
    await route();
  }
  init();
})();
