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
    'nav.endpoint': ['Endpoint', 'Endpoint'], 'nav.agents': ['AI agents', 'KI-Agents'], 'nav.access': ['Access', 'Zugriffe'], 'nav.everyone': ['For everyone', 'Für alle'], 'nav.history': ['History', 'Verlauf'],
    'v.overview': ['Overview', 'Übersicht'], 'v.findings': ['Findings', 'Befunde'], 'v.exclusions': ['Exclusions', 'Exclusions'], 'v.asr': ['ASR rules', 'ASR-Regeln'],
    'v.devices': ['Devices', 'Geräte'], 'v.baseline': ['Baseline', 'Baseline'], 'v.agents': ['Agents', 'Agents'], 'v.agentca': ['Conditional Access', 'Conditional Access'],
    'v.access': ['Roles and paths', 'Rollen und Wege'], 'v.whocan': ['Who can do what?', 'Wer kann was?'], 'v.mine': ['My permissions', 'Meine Rechte'], 'v.changes': ['Changes', 'Änderungen'],
    'mod.endpoint': ['Endpoint', 'Endpoint'], 'mod.agents': ['Agents', 'Agents'], 'mod.access': ['Access', 'Zugriffe'],
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
    'ov.priv': ['active privileged roles', 'aktive privilegierte Rollen'], 'ov.elig': ['roles activatable via PIM', 'Rollen per PIM aktivierbar'], 'ov.req': ['roles requestable via access packages', 'Rollen über Access Packages beantragbar'],
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
    'd.asrBelow': ['ASR below target', 'ASR unter Soll'], 'd.local': ['Local exclusions', 'Lokale Exclusions'], 'd.os': ['Operating system', 'Betriebssystem'], 'd.lastSeen': ['Last seen', 'Zuletzt gesehen'],
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
    'st.Inconsistent': ['Inconsistent', 'Uneinheitlich'], 'st.DeviceDeviation': ['Deviation on devices', 'Abweichung am Gerät'], 'st.NoData': ['No data', 'Keine Daten'], 'st.NotRelevant': ['Not relevant', 'Nicht relevant'],
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
    'g.title': ['AI agents', 'KI-Agents'],
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
    'src.EntraAgentId': ['Entra Agent ID', 'Entra Agent ID'], 'src.Agent365Registry': ['Agent 365 registry', 'Agent 365 Registry'], 'src.DefenderAgentsInfo': ['Defender (AgentsInfo)', 'Defender (AgentsInfo)'],
    'c.title': ['Conditional Access for agents', 'Conditional Access für Agents'], 'c.lede': ['Policies that target agent identities or agent users – and how many agents they actually cover.', 'Richtlinien, die Agent-Identitäten oder Agent-User adressieren – und wie viele Agents sie tatsächlich erfassen.'],
    'c.policy': ['Policy', 'Richtlinie'], 'c.state': ['State', 'Zustand'], 'c.target': ['Target', 'Ziel'], 'c.excludes': [' (− {0} exclusion(s))', ' (− {0} Ausnahme(n))'], 'c.resources': ['Resources', 'Ressourcen'],
    'c.effect': ['Effect', 'Wirkung'], 'c.covers': ['Covers', 'Erfasst'], 'c.coversN': ['{0} agent(s), {1} agent user(s)', '{0} Agent(s), {1} Agent-User'], 'c.none': ['No Conditional Access policy targets agents.', 'Keine Conditional-Access-Richtlinie adressiert Agents.'],
    'c.weak': ['Not effectively protected', 'Nicht wirksam geschützt'], 'c.weak.lede': ['Agent identities and agent users that are not covered by an enabled policy – report-only counts as unprotected here.', 'Agent-Identitäten und Agent-User, die von keiner aktiven Richtlinie erfasst werden – auch Report-only zählt hier als ungeschützt.'],
    'c.allOk': ['All cloud agents with Entra Agent ID are covered by Conditional Access.', 'Alle Cloud-Agents mit Entra Agent ID sind durch Conditional Access erfasst.'],
    // access (optional module)
    'r.lede': ['Who has which admin role, can activate it via PIM or can request it via an access package – across Entra ID, PIM for groups, access packages and Intune.', 'Wer welche Admin-Rolle hat, sie per PIM aktivieren kann oder über ein Access Package beantragen darf – über Entra ID, PIM für Gruppen, Access Packages und Intune hinweg.'],
    'r.person': ['Person', 'Person'], 'r.role': ['Role', 'Rolle'], 'r.platform': ['Platform', 'Plattform'], 'r.state': ['State', 'Zustand'], 'r.path': ['Path', 'Weg'], 'r.scope': ['Scope', 'Bereich'], 'r.ends': ['Ends', 'Endet'],
    'r.onlyPriv': ['Privileged roles only', 'Nur privilegierte Rollen'], 'r.privileged': ['privileged', 'privilegiert'],
    'r.open': ['Requestable by large groups', 'Für große Gruppen beantragbar'], 'r.open.lede': ['A whole group of users can request these access packages themselves. Check that approvals and roles match.', 'Diese Access Packages kann ein ganzer Benutzerkreis selbst beantragen. Prüfen Sie, ob Genehmigungen und Rollen dazu passen.'],
    'r.package': ['Access package', 'Access Package'], 'r.policy': ['Policy', 'Richtlinie'], 'r.who': ['Who can request', 'Wer darf beantragen'], 'r.grants': ['Grants', 'Vermittelt'],
    'aud.allMemberUsers': ['all members', 'alle Mitglieder'], 'aud.allDirectoryUsers': ['all users incl. guests', 'alle Benutzer inkl. Gäste'], 'aud.allExternalUsers': ['all external users', 'alle externen Benutzer'], 'aud.allConfiguredConnectedOrganizationUsers': ['connected organisations', 'verbundene Organisationen'],
    'rs.Active': ['Active', 'Aktiv'], 'rs.Activated': ['Active (activated via PIM)', 'Aktiv (per PIM aktiviert)'], 'rs.Eligible': ['Eligible', 'Eligible'], 'rs.Requestable': ['Requestable', 'Beantragbar'],
    'w.lede': ['Search for a role or a permission, e.g. “Password”, “microsoft.directory/users/password/update” or “Conditional Access”. Shows everyone who can do it – actively, via PIM or by request.', 'Suchen Sie nach einer Rolle oder einer Berechtigung, zum Beispiel „Password“, „microsoft.directory/users/password/update“ oder „Conditional Access“. Gezeigt werden alle Personen, die das aktiv, per PIM oder per Antrag können.'],
    'w.input': ['Role or permission …', 'Rolle oder Berechtigung …'], 'w.min': ['Enter at least three characters.', 'Mindestens drei Zeichen eingeben.'], 'w.noRole': ['No role matches this search.', 'Keine Rolle passt zu dieser Suche.'],
    'w.roles': ['Matching roles: {0}', 'Passende Rollen: {0}'], 'w.nobody': ['Nobody has any of these roles.', 'Niemand hat eine dieser Rollen.'],
    'm.lede': ['Which admin roles you have now, which you can activate yourself and which you can request.', 'Welche Admin-Rollen Sie jetzt haben, welche Sie selbst aktivieren und welche Sie beantragen können.'],
    'm.active': ['Active', 'Aktiv'], 'm.active.i': ['You have these permissions right now.', 'Diese Rechte haben Sie in diesem Moment.'], 'm.pim': ['Activatable via PIM', 'Per PIM aktivierbar'],
    'm.pim.i': ['You are eligible; the role only takes effect after activation.', 'Sie sind berechtigt; die Rolle wird erst nach Aktivierung wirksam.'], 'm.req': ['Requestable', 'Beantragbar'],
    'm.req.i': ['You can request the role through these access packages.', 'Über diese Access Packages können Sie die Rolle beantragen.'], 'm.none': ['None.', 'Keine.'],
    'm.activate': ['Activate in PIM', 'In PIM aktivieren'], 'm.request': ['Request in My Access', 'In My Access beantragen'], 'm.all': ['Requestable by everyone', 'Für alle beantragbar'],
    'm.all.i': ['These packages are open to all users of your type.', 'Diese Pakete stehen allen Benutzern Ihres Typs offen.'], 'm.until': [' · until {0}', ' · bis {0}'],
    'm.asof': ['Data as of {0}. Changes appear after the next run.', 'Stand der Daten: {0}. Änderungen erscheinen nach dem nächsten Lauf.'],
    // changes
    'ch.lede': ['What changed between two runs. Every run is also kept as a dated snapshot in your company’s storage account.', 'Was sich zwischen zwei Läufen verändert hat. Jeder Lauf wird zusätzlich als datierter Snapshot im Storage Account Ihres Unternehmens aufbewahrt.'],
    'ch.kind': ['Kind', 'Art'], 'ch.area': ['Area', 'Bereich'], 'ch.what': ['What', 'Was'], 'ch.before': ['Before', 'Vorher'], 'ch.after': ['After', 'Nachher'],
    'ch.Added': ['Added', 'Neu'], 'ch.Changed': ['Changed', 'Geändert'], 'ch.Removed': ['Removed', 'Entfernt'],
    'ch.none': ['No changes yet. Deviations are recorded here from the second run on.', 'Noch keine Änderungen. Ab dem zweiten Lauf werden Abweichungen hier festgehalten.'],
    'coll.policyExclusions': ['Exclusion (policy)', 'Exclusion (Richtlinie)'], 'coll.localExclusions': ['Exclusion (local)', 'Exclusion (lokal)'], 'coll.indicators': ['Indicator', 'Indikator'],
    'coll.devices': ['Device', 'Gerät'], 'coll.baseline': ['Baseline', 'Baseline'], 'coll.asrRules': ['ASR rule', 'ASR-Regel'], 'coll.asrGroups': ['ASR device group', 'ASR-Gerätegruppe'],
    'coll.findings': ['Finding', 'Befund'], 'coll.entitlements': ['Permission', 'Recht'], 'coll.audiences': ['Open package', 'Offenes Paket'], 'coll.agents': ['Agent', 'Agent'],
    'coll.blueprints': ['Blueprint', 'Blueprint'], 'coll.policies': ['CA policy', 'CA-Richtlinie'], 'coll.coverage': ['Coverage', 'Abdeckung'],
    // categories, coverage, usage
    'cat.Coverage': ['Coverage', 'Abdeckung'], 'cat.Hygiene': ['Hygiene', 'Hygiene'],
    'cov.NotOnboarded': ['Not onboarded (Intune device)', 'Nicht onboarded (Intune-Gerät)'], 'cov.CanBeOnboarded': ['Discovered, can be onboarded', 'Erkannt, kann onboarded werden'],
    'cov.SensorInactive': ['Sensor inactive', 'Sensor inaktiv'], 'cov.Misconfigured': ['Sensor misconfigured', 'Sensor falsch konfiguriert'],
    'cov.ImpairedCommunications': ['Impaired communications', 'Eingeschränkte Kommunikation'], 'cov.NoSensorData': ['No sensor data', 'Keine Sensordaten'], 'cov.SensorIssue': ['Sensor problem', 'Sensorproblem'],
    'covsrc.Intune': ['Intune', 'Intune'], 'covsrc.Defender': ['Defender', 'Defender'], 'covsrc.DeviceDiscovery': ['Device discovery', 'Geräteerkennung'],
    'use.Used': ['Activity seen', 'Aktivität gesehen'], 'use.Unused': ['No activity (30 days)', 'Keine Aktivität (30 Tage)'], 'use.NotChecked': ['Not checked', 'Nicht geprüft'],
    'x.usage': ['Activity', 'Aktivität'], 'x.onlyUnused': ['No activity only', 'Nur ohne Aktivität'], 'x.usageHits': ['{0} events, last {1}', '{0} Ereignisse, zuletzt {1}'],
    'x.usage.help': ['Process and file events on any device in the last 30 days (Advanced Hunting). Wildcards and variables are not checked.', 'Prozess- und Dateiereignisse auf allen Geräten in den letzten 30 Tagen (Advanced Hunting). Platzhalter und Variablen werden nicht geprüft.'],
    'ov.coverage': ['devices without full Defender coverage', 'Geräte ohne vollständige Defender-Abdeckung'], 'ov.unused': ['exclusions without activity (30 days)', 'Exclusions ohne Aktivität (30 Tage)'],
    // devices
    'd.tab.devices': ['Devices ({0})', 'Geräte ({0})'], 'd.tab.coverage': ['Coverage gaps ({0})', 'Abdeckungslücken ({0})'],
    'd.np': ['Network prot.', 'Netzwerkschutz'], 'd.open': ['Open device page', 'Geräteseite öffnen'],
    'd.cov.lede': ['Devices Defender for Endpoint does not (fully) protect: Intune-managed devices that never showed up in Defender, onboarded devices with sensor problems and devices found by device discovery.', 'Geräte, die Defender for Endpoint nicht (vollständig) schützt: Intune-verwaltete Geräte, die nie in Defender aufgetaucht sind, onboardete Geräte mit Sensorproblemen und Geräte aus der Geräteerkennung.'],
    'd.cov.status': ['Status', 'Status'], 'd.cov.source': ['Source', 'Quelle'], 'd.cov.user': ['User', 'Benutzer'], 'd.cov.none': ['No coverage gaps found.', 'Keine Abdeckungslücken gefunden.'],
    'd.cov.feature': ['The Intune comparison needs the feature Coverage (Install-Wardline.ps1 -Features …,Coverage).', 'Der Intune-Abgleich braucht die Funktion Coverage (Install-Wardline.ps1 -Features …,Coverage).'],
    // device page
    'dv.back': ['← All devices', '← Alle Geräte'], 'dv.notfound': ['Device not found in the latest run.', 'Gerät im letzten Lauf nicht gefunden.'],
    'dv.protection': ['Protection state', 'Schutzzustand'], 'dv.asr': ['ASR rules on this device', 'ASR-Regeln auf diesem Gerät'], 'dv.local': ['Local exclusions', 'Lokale Exclusions'],
    'dv.policies': ['Policies with exclusions and their assignments', 'Richtlinien mit Exclusions und ihre Zuweisungen'], 'dv.policies.note': ['Wardline does not resolve group memberships of devices; check the assignment to see whether a policy targets this device.', 'Wardline löst Gruppenmitgliedschaften von Geräten nicht auf; an der Zuweisung erkennst du, ob eine Richtlinie dieses Gerät trifft.'],
    'dv.findings': ['Findings for this device', 'Befunde zu diesem Gerät'], 'dv.agents': ['Local AI agents', 'Lokale KI-Agents'], 'dv.changes': ['Changes', 'Änderungen'],
    'dv.links': ['Open in', 'Öffnen in'], 'dv.defender': ['Defender portal', 'Defender-Portal'], 'dv.intune': ['Intune', 'Intune'],
    'dv.user': ['Last user', 'Letzter Benutzer'], 'dv.join': ['Join type', 'Join-Typ'], 'dv.sensor': ['Sensor health', 'Sensorzustand'], 'dv.exposure': ['Exposure level', 'Gefährdungsstufe'],
    'dv.sigver': ['Signature version', 'Signaturversion'], 'dv.engver': ['Engine / platform', 'Engine / Plattform'], 'dv.sigtime': ['Signatures published', 'Signaturen veröffentlicht'],
    'dv.target': ['Target', 'Soll'], 'dv.effective': ['On the device', 'Auf dem Gerät'], 'dv.none': ['None.', 'Keine.'],
    'chk.AntivirusEnabled': ['Antivirus enabled', 'Virenschutz aktiv'], 'chk.RealtimeProtection': ['Real-time protection', 'Echtzeitschutz'], 'chk.BehaviorMonitoring': ['Behavior monitoring', 'Verhaltensüberwachung'],
    'chk.CloudProtection': ['Cloud protection', 'Cloudschutz'], 'chk.PUAProtection': ['PUA protection', 'PUA-Schutz'], 'chk.TamperProtection': ['Tamper protection', 'Manipulationsschutz'],
    'chk.NetworkProtection': ['Network protection', 'Netzwerkschutz'], 'chk.ControlledFolderAccess': ['Controlled folder access', 'Überwachter Ordnerzugriff'], 'chk.EdrBlockMode': ['EDR in block mode', 'EDR im Blockmodus'],
    'chk.AntivirusSignatureVersion': ['Signatures current', 'Signaturen aktuell'], 'chk.AntivirusReporting': ['Antivirus reporting', 'Virenschutz-Reporting'], 'chk.SensorEnabled': ['EDR sensor enabled', 'EDR-Sensor aktiv'],
    'chk.SensorDataCollection': ['Sensor data collection', 'Sensor-Datenerfassung'], 'chk.ImpairedCommunications': ['Sensor communication', 'Sensor-Kommunikation'], 'chk.PassiveModeOff': ['Not in passive mode', 'Nicht im Passivmodus'],
    // accepted risks
    'acc.accept': ['Accept risk …', 'Risiko akzeptieren …'], 'acc.save': ['Accept', 'Akzeptieren'], 'acc.cancel': ['Cancel', 'Abbrechen'], 'acc.revoke': ['Revoke', 'Widerrufen'],
    'acc.justification': ['Justification', 'Begründung'], 'acc.owner': ['Owner', 'Verantwortlich'], 'acc.ticket': ['Ticket / change (optional)', 'Ticket / Change (optional)'], 'acc.expires': ['Valid until', 'Gültig bis'],
    'acc.until': ['Accepted until {0}', 'Akzeptiert bis {0}'], 'acc.by': ['by {0}', 'von {0}'], 'acc.saved': ['Risk accepted.', 'Risiko akzeptiert.'], 'acc.revoked': ['Acceptance revoked.', 'Akzeptanz widerrufen.'],
    'acc.hide': ['Hide accepted', 'Akzeptierte ausblenden'], 'acc.tag': ['Accepted', 'Akzeptiert'], 'acc.expired': ['Expired', 'Abgelaufen'], 'acc.revokedTag': ['Revoked', 'Widerrufen'],
    'acc.help': ['Accepted findings and exclusions stay visible but no longer count as open and do not trigger notifications. After the expiry date they are open again.', 'Akzeptierte Befunde und Exclusions bleiben sichtbar, zählen aber nicht mehr als offen und lösen keine Benachrichtigung aus. Nach dem Ablaufdatum sind sie wieder offen.'],
    'acc.title': ['Accepted risks', 'Akzeptierte Risiken'], 'acc.lede': ['Consciously accepted findings and exclusions with justification, owner and expiry date – the record auditors ask for.', 'Bewusst akzeptierte Befunde und Exclusions mit Begründung, Verantwortlichem und Ablaufdatum – der Nachweis, nach dem Prüfer fragen.'],
    'acc.tab.list': ['Acceptances', 'Akzeptanzen'], 'acc.tab.log': ['Audit log', 'Protokoll'], 'acc.what': ['What', 'Was'], 'acc.status': ['Status', 'Status'], 'acc.active': ['Active', 'Aktiv'],
    'acc.at': ['Accepted', 'Akzeptiert am'], 'acc.action': ['Action', 'Aktion'], 'acc.act.accept': ['accepted', 'akzeptiert'], 'acc.act.revoke': ['revoked', 'widerrufen'], 'acc.none': ['No accepted risks yet.', 'Noch keine akzeptierten Risiken.'],
    'acc.err.just': ['Please give a justification (at least 10 characters).', 'Bitte eine Begründung angeben (mindestens 10 Zeichen).'], 'acc.err.owner': ['Please name an owner.', 'Bitte einen Verantwortlichen angeben.'],
    'acc.kind.finding': ['Finding', 'Befund'], 'acc.kind.exclusion': ['Exclusion', 'Exclusion'], 'demo.readonly': ['Demo: changes are not saved.', 'Demo: Änderungen werden nicht gespeichert.'],
    'd.aad': ['Entra device ID', 'Entra-Geräte-ID'], 'v.device': ['Device', 'Gerät'], 'v.accepted': ['Accepted risks', 'Akzeptierte Risiken'],
    'g.registry.na': ['The Agent 365 registry is not available in this tenant (no Agent 365 or already replaced by the Agent 365 APIs). Agents from Entra Agent ID and Defender are still shown.', 'Die Agent-365-Registry ist in diesem Tenant nicht verfügbar (kein Agent 365 oder bereits durch die Agent-365-APIs ersetzt). Agents aus Entra Agent ID und Defender werden weiterhin angezeigt.']
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
  const state = { me: null, endpoint: null, agents: null, access: null, mine: null, changes: {}, runs: null, view: null, acceptances: null };
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

  /** Table with search, optional filters, detail row and CSV export. */
  function dataTable({ name, columns, rows, search, filters = [], detail, empty, sort }) {
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
    wrap.append(toolbar, count, body);

    let current = [];
    function apply() {
      const term = q.value.trim().toLowerCase();
      current = rows.filter(r => {
        if (term && !search(r).toLowerCase().includes(term)) return false;
        for (const { f, input } of filterEls) {
          if (f.type === 'check') { if (input.checked && !f.test(r)) return false; }
          else if (input.value && !f.test(r, input.value)) return false;
        }
        return true;
      });
      if (sort) current.sort(sort);
      tbody.replaceChildren();
      const max = 1500;
      for (const r of current.slice(0, max)) {
        const tr = h('tr', { class: detail ? 'clickable' : null, tabindex: detail ? '0' : null }, columns.map(c => h('td', null, c.cell ? c.cell(r) : c.text(r))));
        if (detail) {
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
      body.replaceChildren(current.length ? h('div', { class: 'table-wrap' }, table) : h('div', { class: 'empty' }, rows.length ? t('no.match') : (empty || t('no.entries'))));
    }
    q.addEventListener('input', apply);
    filterEls.forEach(x => x.input.addEventListener('change', apply));
    exportBtn.addEventListener('click', () => csvExport(name, columns, current));
    apply();
    return wrap;
  }

  function dl(pairs) {
    return h('dl', null, pairs.filter(p => p && p[1] !== undefined && p[1] !== null && p[1] !== '').map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
  }
  function list(items) { return h('ul', null, arr(items).map(i => h('li', null, i))); }
  function tabs(view, items, active) {
    return h('div', { class: 'tabs', role: 'tablist' }, items.map(([id, label]) => h('button', { class: 'tab', role: 'tab', type: 'button', 'aria-selected': String(id === active), onclick: () => { location.hash = `#/${view}?tab=${id}`; } }, label)));
  }

  // ---------- Loading data ----------
  async function loadEndpoint(force) { if (!state.endpoint || force) state.endpoint = await api('endpoint'); return state.endpoint; }
  async function loadAccess(force) { if (!state.access || force) state.access = await api('access'); return state.access; }
  async function loadAgents(force) { if (!state.agents || force) state.agents = await api('agents'); return state.agents; }
  async function loadAcceptances(force) {
    if (!state.acceptances || force) { try { state.acceptances = arr((await api('acceptances')).acceptances); } catch { state.acceptances = []; } }
    return state.acceptances;
  }
  const acceptedMap = () => { const m = {}; for (const a of arr(state.acceptances)) if (a.active) m[a.key] = a; return m; };
  const yesNo = (v) => v === true || /^(true|1)$/i.test(String(v)) ? t('yes') : v === false || /^(false|0)$/i.test(String(v)) ? t('no') : (v || null);
  const deviceLink = (id, name) => id ? h('a', { href: `#/device?id=${encodeURIComponent(id)}`, onclick: (e) => e.stopPropagation() }, name || id) : (name || '–');
  const usageCell = (r) => !r.usage ? h('span', { class: 'muted' }, '–') : h('span', { class: `state ${r.usage === 'Unused' ? 'warn' : r.usage === 'Used' ? 'good' : ''}`, title: r.usageHits ? t('x.usageHits', num(r.usageHits), fmtDay(r.usageLast)) : t('x.usage.help') }, code('use', r.usage));

  /** Accept-risk block for a detail row: shows an active acceptance (with revoke) or a small form. */
  function acceptBox(item, kind, module, title) {
    const box = h('div', { class: 'accept' });
    const a = acceptedMap()[item.key];
    const after = async (msg) => { await loadAcceptances(true); toast(msg); route(); };
    if (a) {
      box.append(h('p', null, h('span', { class: 'tag accepted' }, t('acc.until', fmtDay(a.expires))), ' ', t('acc.by', a.acceptedBy), ' · ', a.owner, a.ticket ? ` · ${a.ticket}` : ''),
        h('p', { class: 'muted small' }, a.justification),
        h('button', { type: 'button', onclick: async (e) => { e.stopPropagation(); try { await api('acceptances/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: item.key }) }); await after(t('acc.revoked')); } catch (err) { toast(t('error', err.message)); } } }, t('acc.revoke')));
      return box;
    }
    const open = h('button', { type: 'button' }, t('acc.accept'));
    const d = new Date(); d.setDate(d.getDate() + 90);
    const max = new Date(); max.setDate(max.getDate() + 365);
    const iso = (x) => x.toISOString().slice(0, 10);
    const just = h('textarea', { rows: '3', maxlength: '1000', 'aria-label': t('acc.justification') });
    const owner = h('input', { type: 'text', maxlength: '200', 'aria-label': t('acc.owner') });
    const ticket = h('input', { type: 'text', maxlength: '100', 'aria-label': t('acc.ticket') });
    const exp = h('input', { type: 'date', value: iso(d), min: iso(new Date(Date.now() + 864e5)), max: iso(max), 'aria-label': t('acc.expires') });
    const form = h('form', { class: 'accept-form', hidden: true },
      h('label', null, t('acc.justification'), just), h('label', null, t('acc.owner'), owner), h('label', null, t('acc.ticket'), ticket), h('label', null, t('acc.expires'), exp),
      h('div', { class: 'accept-actions' }, h('button', { type: 'submit', class: 'primary' }, t('acc.save')), h('button', { type: 'button', onclick: () => { form.hidden = true; open.hidden = false; } }, t('acc.cancel'))));
    open.addEventListener('click', (e) => { e.stopPropagation(); form.hidden = false; open.hidden = true; just.focus(); });
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (just.value.trim().length < 10) { toast(t('acc.err.just')); return; }
      if (!owner.value.trim()) { toast(t('acc.err.owner')); return; }
      try {
        await api('acceptances', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: item.key, kind, module, title, justification: just.value.trim(), owner: owner.value.trim(), ticket: ticket.value.trim(), expires: exp.value }) });
        await after(t('acc.saved'));
      } catch (err) { toast(t('error', err.message)); }
    });
    box.append(h('p', { class: 'muted small' }, t('acc.help')), open, form);
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
      let ep = null, ac = null, ag = null, epErr = null, acErr = null, agErr = null;
      await Promise.all([
        loadEndpoint().then(x => ep = x).catch(e => epErr = e),
        hasMod('agents') ? loadAgents().then(x => ag = x).catch(e => agErr = e) : null,
        hasMod('access') ? loadAccess().then(x => ac = x).catch(e => acErr = e) : null]);
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
          s.coverageGaps !== undefined ? fact(num(s.coverageGaps), t('ov.coverage')) : null, s.unusedExclusions !== undefined ? fact(num(s.unusedExclusions), t('ov.unused')) : null));
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
          fact(num(s.privilegedActive), t('ov.priv')), fact(num(s.eligible), t('ov.elig')), fact(num(s.requestable), t('ov.req')), fact(num(s.openAudiences), t('ov.openPkg'))));
      }

      const runs = await api('runs').catch(() => []);
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
      main.append(warningsBlock([...arr(ep && ep.warnings), ...arr(ag && ag.warnings), ...arr(ac && ac.warnings)]) || '');
    },

    async findings(main, params) {
      main.append(h('h1', null, t('v.findings')), h('p', { class: 'lede' }, t('f.lede')));
      let ep = null, ag = null, err = null;
      await Promise.all([loadEndpoint().then(x => ep = x).catch(e => err = e), hasMod('agents') ? loadAgents().then(x => ag = x).catch(() => null) : null]);
      if (!ep && !ag) { main.append(noData(err, 'endpoint')); return; }
      await loadAcceptances();
      const acc = acceptedMap();
      const rows = [...arr(ep && ep.findings).map(f => ({ ...f, module: 'endpoint' })), ...arr(ag && ag.findings).map(f => ({ ...f, module: 'agents' }))].map(f => ({ ...f, accepted: acc[f.key] || null }));
      const cats = [...new Set(rows.map(r => r.category))].sort();
      const table = dataTable({
        name: 'findings', rows, sort: (a, b) => sevRank(a.severity) - sevRank(b.severity),
        search: r => `${tx(r.title)} ${tx(r.detail)} ${r.deviceName || ''} ${code('cat', r.category)}`,
        filters: [
          { label: t('f.severity'), options: SEV, optionLabel: s => code('sev', s), test: (r, v) => r.severity === v },
          { label: t('f.category'), options: cats, optionLabel: c => code('cat', c), test: (r, v) => r.category === v },
          { label: t('col.module'), options: [...new Set(rows.map(r => r.module))], optionLabel: m => code('mod', m), test: (r, v) => r.module === v },
          { type: 'check', label: t('acc.hide'), checked: true, test: r => !r.accepted }],
        columns: [
          { title: t('f.severity'), cell: r => sevCell(r.severity), text: r => code('sev', r.severity) },
          { title: t('f.finding'), cell: r => h('span', null, tx(r.title), r.accepted ? h('span', { class: 'tag accepted' }, t('acc.tag')) : null), text: r => tx(r.title) + (r.accepted ? ` (${t('acc.tag')})` : '') },
          { title: t('f.category'), text: r => `${code('mod', r.module)} · ${code('cat', r.category)}` },
          { title: t('f.device'), cell: r => deviceLink(r.deviceId, r.deviceName), text: r => r.deviceName || '–' }],
        detail: r => h('div', null, dl([[t('f.description'), tx(r.detail)], [t('f.recommendation'), tx(r.recommendation)], [t('f.device'), r.deviceName]]), acceptBox(r, 'finding', r.module, tx(r.title))),
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
      const active = params.get('tab') || 'devices';
      main.append(tabs('devices', [['devices', t('d.tab.devices', rows.length)], ['coverage', t('d.tab.coverage', cov.length)]], active));
      if (active === 'coverage') {
        main.append(h('p', { class: 'muted small' }, t('d.cov.lede')));
        main.append(dataTable({
          name: 'coverage', rows: cov, sort: (a, b) => String(a.status).localeCompare(String(b.status)) || String(a.deviceName).localeCompare(String(b.deviceName)),
          search: r => `${r.deviceName} ${r.os || ''} ${r.user || ''}`,
          filters: [
            { label: t('d.cov.status'), options: [...new Set(cov.map(r => r.status))].sort(), optionLabel: c => code('cov', c), test: (r, v) => r.status === v },
            { label: t('d.cov.source'), options: [...new Set(cov.map(r => r.source))].sort(), optionLabel: c => code('covsrc', c), test: (r, v) => r.source === v }],
          columns: [
            { title: t('d.device'), cell: r => r.deviceId && rows.some(d => d.deviceId === r.deviceId) ? deviceLink(r.deviceId, r.deviceName) : r.deviceName, text: r => r.deviceName },
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
      main.append(dataTable({
        name: 'devices', rows, sort: (a, b) => (problem(b) - problem(a)) || String(a.deviceName).localeCompare(String(b.deviceName)),
        search: r => `${r.deviceName} ${r.os} ${r.deviceGroup || ''}`,
        filters: [
          { label: t('d.platform'), options: [...new Set(rows.map(r => r.os).filter(Boolean))].sort(), test: (r, v) => r.os === v },
          { label: t('d.group'), options: [...new Set(rows.map(r => r.deviceGroup).filter(Boolean))].sort(), test: (r, v) => r.deviceGroup === v },
          { type: 'check', label: t('d.onlyIssues'), test: problem }],
        columns: [
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
          { title: t('d.local'), cell: r => r.localExclusions ? h('span', { class: `state ${r.localExclusionsHighRisk ? 'bad' : 'warn'}` }, String(r.localExclusions)) : h('span', { class: 'muted' }, '0'), text: r => r.localExclusions }],
        detail: r => dl([[t('d.device'), h('a', { href: `#/device?id=${encodeURIComponent(r.deviceId)}` }, t('d.open'))], [t('d.group'), r.deviceGroup], [t('d.os'), [r.os, r.osVersion].filter(Boolean).join(' ')], [t('d.lastSeen'), fmtDate(r.lastSeen)],
          [t('d.sig'), yesNo(r.signatureUpToDate)], [t('d.plat'), yesNo(r.platformUpToDate)], [t('d.alerts'), r.exclusionAlerts],
          [t('d.checks'), list(Object.entries(r.checks || {}).map(([k, v]) => `${code('chk', k)}: ${v === 'GOOD' ? t('ok') : v === 'BAD' ? t('problem') : t('na')}`))],
          [t('d.asr'), r.asr ? list(Object.entries(r.asr).map(([k, v]) => `${asrName[k] || k}: ${v === 'n/a' ? t('na') : code('asr', v)}`)) : null]]),
        empty: t('d.none')
      }));
    },

    async device(main, params) {
      const id = params.get('id') || '';
      main.append(h('p', null, h('a', { href: '#/devices' }, t('dv.back'))));
      let ep; try { ep = await loadEndpoint(); } catch (e) { main.append(noData(e, 'endpoint')); return; }
      const d = arr(ep.devices).find(x => x.deviceId === id);
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
        [t('d.lastSeen'), fmtDate(d.lastSeen)], [t('dv.sigver'), d.avSignatureVersion || null], [t('dv.engver'), [d.avEngineVersion, d.avPlatformVersion].filter(Boolean).join(' / ') || null],
        [t('dv.sigtime'), d.avSignatureTime ? fmtDate(d.avSignatureTime) : null], [t('d.sig'), yesNo(d.signatureUpToDate)], [t('d.plat'), yesNo(d.platformUpToDate)],
        [t('d.aad'), d.aadDeviceId ? h('span', { class: 'mono small' }, d.aadDeviceId) : null], [t('dv.links'), h('span', null, links)]])));

      const order = ['AntivirusEnabled', 'RealtimeProtection', 'BehaviorMonitoring', 'CloudProtection', 'PUAProtection', 'TamperProtection', 'NetworkProtection', 'ControlledFolderAccess', 'EdrBlockMode', 'AntivirusSignatureVersion', 'SensorEnabled', 'ImpairedCommunications', 'PassiveModeOff'];
      const checks = Object.keys(d.checks || {}).sort((a, b) => (order.indexOf(a) + 1 || 99) - (order.indexOf(b) + 1 || 99));
      main.append(h('h2', null, t('dv.protection')), checks.length ? h('div', { class: 'checks' }, checks.map(k => h('div', { class: 'check-item' }, checkCell(d.checks[k]), ' ', code('chk', k)))) : h('p', { class: 'muted' }, t('dv.none')));

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
      const byPolicy = {}; pols.forEach(p => { (byPolicy[p.policyId] = byPolicy[p.policyId] || { name: p.policyName, platform: p.platform, assignments: p.assignments, assigned: p.assigned, n: 0 }).n++; });
      const plat = String(d.os || '').toLowerCase().slice(0, 3);
      const relevant = Object.values(byPolicy).filter(p => String(p.platform || '').toLowerCase().startsWith(plat));
      main.append(h('h2', null, t('dv.policies')), h('p', { class: 'muted small' }, t('dv.policies.note')), relevant.length ? list(relevant.map(p => `${p.name}: ${p.n} · ${arr(p.assignments).map(assignText).join(', ') || t('x.unassigned')}`)) : h('p', { class: 'muted' }, t('dv.none')));

      let changes = []; try { changes = arr(state.changes.endpoint || (state.changes.endpoint = await api('changes?module=endpoint'))); } catch { changes = []; }
      const mine = changes.filter(c => JSON.stringify(c.label || '').includes(d.deviceName)).slice(0, 50);
      main.append(h('h2', null, t('dv.changes')), mine.length ? dataTable({
        name: `changes-${d.deviceName}`, rows: mine, search: r => tx(r.label),
        columns: [{ title: t('col.time'), text: r => fmtDate(r.at) }, { title: t('ch.kind'), text: r => code('ch', r.change) }, { title: t('ch.what'), text: r => tx(r.label) }, { title: t('ch.after'), text: r => r.after || '–' }]
      }) : h('p', { class: 'muted' }, t('dv.none')));
    },

    async accepted(main, params) {
      main.append(h('h1', null, t('acc.title')), h('p', { class: 'lede' }, t('acc.lede')));
      const active = params.get('tab') || 'list';
      main.append(tabs('accepted', [['list', t('acc.tab.list')], ['log', t('acc.tab.log')]], active));
      if (active === 'log') {
        let log = []; try { log = arr(await api('acceptances/log')); } catch (e) { main.append(noData(e, 'endpoint')); return; }
        main.append(dataTable({
          name: 'acceptance-log', rows: log, search: r => `${r.title} ${r.by} ${r.justification || ''} ${r.ticket || ''}`,
          columns: [
            { title: t('col.time'), text: r => fmtDate(r.at) }, { title: t('acc.action'), text: r => t(`acc.act.${r.action}`) }, { title: t('acc.what'), text: r => r.title || r.key },
            { title: t('acc.by', ''), text: r => r.by }, { title: t('acc.expires'), text: r => r.expires ? fmtDay(r.expires) : '–' }, { title: t('acc.justification'), text: r => r.justification || '–' }],
          empty: t('acc.none')
        }));
        return;
      }
      const rows = await loadAcceptances(true);
      const status = (r) => r.revokedAt ? 'revoked' : r.active ? 'active' : 'expired';
      main.append(dataTable({
        name: 'acceptances', rows, sort: (a, b) => String(a.expires).localeCompare(String(b.expires)),
        search: r => `${r.title} ${r.owner} ${r.ticket || ''} ${r.justification}`,
        filters: [{ label: t('acc.status'), options: ['active', 'expired', 'revoked'], optionLabel: c => c === 'active' ? t('acc.active') : c === 'expired' ? t('acc.expired') : t('acc.revokedTag'), test: (r, v) => status(r) === v }],
        columns: [
          { title: t('acc.what'), text: r => `${t(`acc.kind.${r.kind}`) || r.kind}: ${r.title}` },
          { title: t('acc.status'), cell: r => h('span', { class: `state ${status(r) === 'active' ? 'good' : 'warn'}` }, status(r) === 'active' ? t('acc.active') : status(r) === 'expired' ? t('acc.expired') : t('acc.revokedTag')), text: status },
          { title: t('acc.owner'), text: r => r.owner }, { title: t('acc.expires'), text: r => fmtDay(r.expires) }, { title: t('acc.ticket'), text: r => r.ticket || '–' }],
        detail: r => h('div', null, dl([[t('acc.justification'), r.justification], [t('acc.at'), `${fmtDate(r.acceptedAt)} · ${r.acceptedBy}`], [t('acc.revokedTag'), r.revokedAt ? `${fmtDate(r.revokedAt)} · ${r.revokedBy}` : null]]),
          r.active ? h('button', { type: 'button', onclick: async () => { try { await api('acceptances/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: r.key }) }); await loadAcceptances(true); toast(t('acc.revoked')); route(); } catch (err) { toast(t('error', err.message)); } } }, t('acc.revoke')) : null),
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
      main.append(h('h1', null, t('g.title')), h('p', { class: 'lede' }, t('g.lede')));
      let ag; try { ag = await loadAgents(); } catch (e) { main.append(noData(e, 'agents')); return; }
      if (ag.securityDefaults) main.append(h('div', { class: 'warnings' }, t('g.secdef')));
      if (ag.registryStatus === 'NotAvailable') main.append(h('p', { class: 'muted small' }, t('g.registry.na')));
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
            [t('g.sources'), arr(r.sources).map(s => code('src', s)).join(', ')], [t('g.defStatus'), [r.publishedStatus, r.lifecycle].filter(Boolean).join(' · ') || null], [t('g.created'), fmtDate(r.created)],
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
      const stClass = s => s === 'OK' ? 'good' : (s === 'NotRelevant' || s === 'NoData') ? '' : (s === 'Inconsistent' ? 'warn' : 'bad');
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
      main.append(dataTable({
        name: 'access', rows, sort: (a, b) => String(a.displayName).localeCompare(String(b.displayName)) || String(a.role).localeCompare(String(b.role)),
        search: r => `${r.displayName} ${r.upn} ${r.role} ${r.via}`,
        filters: [
          { label: t('r.state'), options: [...new Set(rows.map(r => r.state))].sort(), optionLabel: s => code('rs', s), test: (r, v) => r.state === v },
          { label: t('r.platform'), options: [...new Set(rows.map(r => r.platform))].sort(), test: (r, v) => r.platform === v },
          { type: 'check', label: t('r.onlyPriv'), test: r => r.privileged === true }],
        columns: [
          { title: t('r.person'), cell: r => h('span', null, r.displayName || r.principalId, h('br'), h('span', { class: 'muted small' }, r.upn || r.principalType)), text: r => r.upn || r.displayName },
          { title: t('r.role'), cell: r => h('span', null, r.role, r.privileged === true ? [' ', h('span', { class: 'tag' }, t('r.privileged'))] : null), text: r => r.role },
          { title: t('r.platform'), text: r => r.platform },
          { title: t('r.state'), text: r => code('rs', r.state) },
          { title: t('r.path'), text: r => assignText(r.via) },
          { title: t('r.scope'), text: r => r.scope },
          { title: t('r.ends'), text: r => r.end ? fmtDay(r.end) : t('unlimited') }]
      }));
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

    async whocan(main, params) {
      main.append(h('h1', null, t('v.whocan')), h('p', { class: 'lede' }, t('w.lede')));
      let ac; try { ac = await loadAccess(); } catch (e) { main.append(noData(e, 'access')); return; }
      const input = h('input', { type: 'search', placeholder: t('w.input'), 'aria-label': t('w.input'), value: params.get('q') || '' });
      const out = h('div');
      main.append(h('div', { class: 'toolbar' }, input), out);
      const covers = (action, q) => {
        const a = action.toLowerCase();
        if (a.includes(q)) return true;
        const base = a.replace(/\/(allproperties\/)?alltasks$/, '/');
        return q.startsWith('microsoft.') && base.endsWith('/') && q.startsWith(base);
      };
      function run() {
        const q = input.value.trim().toLowerCase();
        out.replaceChildren();
        if (q.length < 3) { out.append(h('p', { class: 'muted' }, t('w.min'))); return; }
        const roles = arr(ac.roles).filter(r => String(r.name).toLowerCase().includes(q) || arr(r.actions).some(a => covers(a, q)));
        if (!roles.length) { out.append(h('div', { class: 'empty' }, t('w.noRole'))); return; }
        const ids = new Set(roles.map(r => r.id));
        out.append(h('p', null, t('w.roles', roles.map(r => r.name).join(', '))));
        const rows = arr(ac.entitlements).filter(e => ids.has(e.roleId));
        out.append(dataTable({
          name: 'who-can', rows, sort: (a, b) => String(a.state).localeCompare(String(b.state)),
          search: r => `${r.displayName} ${r.upn} ${r.role} ${r.via}`,
          filters: [{ label: t('r.state'), options: [...new Set(rows.map(r => r.state))].sort(), optionLabel: s => code('rs', s), test: (r, v) => r.state === v }],
          columns: [
            { title: t('r.person'), text: r => r.upn || r.displayName },
            { title: t('r.role'), text: r => r.role },
            { title: t('r.state'), text: r => code('rs', r.state) },
            { title: t('r.path'), text: r => assignText(r.via) }],
          empty: t('w.nobody')
        }));
      }
      input.addEventListener('input', () => { clearTimeout(run._t); run._t = setTimeout(run, 250); });
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
        items.length ? h('div', null, items.map(e => h('div', { class: 'right' }, h('span', { class: 'role' }, e.role, e.privileged === true ? [' ', h('span', { class: 'tag' }, t('r.privileged'))] : null), h('span', { class: 'via' }, `${e.platform} · ${assignText(e.via)}${e.end ? t('m.until', fmtDay(e.end)) : ''}`), action ? action(e) : null)))
          : h('p', { class: 'empty' }, t('m.none')));
      main.append(h('div', { class: 'rights' },
        group(t('m.active'), t('m.active.i'), ents.filter(e => e.state === 'Active' || e.state === 'Activated')),
        group(t('m.pim'), t('m.pim.i'), ents.filter(e => e.state === 'Eligible'), () => h('a', { href: pimUrl, target: '_blank', rel: 'noopener' }, t('m.activate'))),
        group(t('m.req'), t('m.req.i'), ents.filter(e => e.state === 'Requestable'), e => h('a', { href: myAccess(e.accessPackageId), target: '_blank', rel: 'noopener' }, t('m.request'))),
        arr(m.audiences).length ? h('section', null, h('h2', null, t('m.all')), h('p', { class: 'muted' }, t('m.all.i')),
          h('div', null, arr(m.audiences).map(a => h('div', { class: 'right' }, h('span', { class: 'role' }, a.accessPackage), h('span', { class: 'via' }, arr(a.grants).map(g => `${g.role} (${code('rs', g.state)})`).join(', ')), h('a', { href: myAccess(a.accessPackageId), target: '_blank', rel: 'noopener' }, t('m.request')))))) : null));
      main.append(h('p', { class: 'muted small' }, t('m.asof', fmtDate(m.generatedAt))));
    },

    async changes(main, params) {
      main.append(h('h1', null, t('v.changes')), h('p', { class: 'lede' }, t('ch.lede')));
      const mod = modules().includes(params.get('module')) ? params.get('module') : 'endpoint';
      main.append(h('div', { class: 'tabs', role: 'tablist' }, modules().map(id => h('button', { class: 'tab', role: 'tab', type: 'button', 'aria-selected': String(id === mod), onclick: () => { location.hash = `#/changes?module=${id}`; } }, code('mod', id)))));
      let rows; try { rows = state.changes[mod] || (state.changes[mod] = await api(`changes?module=${mod}`)); } catch (e) { main.append(noData(e, mod)); return; }
      rows = arr(rows);
      const area = (r) => code('coll', r.collection);
      main.append(dataTable({
        name: `changes-${mod}`, rows,
        search: r => `${tx(r.label)} ${r.before || ''} ${r.after || ''}`,
        filters: [
          { label: t('ch.kind'), options: ['Added', 'Changed', 'Removed'], optionLabel: c => code('ch', c), test: (r, v) => r.change === v },
          { label: t('ch.area'), options: [...new Set(rows.map(r => r.collection))].sort(), optionLabel: c => code('coll', c), test: (r, v) => r.collection === v }],
        columns: [
          { title: t('col.time'), text: r => fmtDate(r.at) },
          { title: t('ch.kind'), text: r => code('ch', r.change) },
          { title: t('ch.area'), text: area },
          { title: t('ch.what'), text: r => tx(r.label) },
          { title: t('ch.before'), text: r => r.before || '–' },
          { title: t('ch.after'), text: r => r.after || '–' }],
        empty: t('ch.none')
      }));
    }
  };

  const NAV = [
    { group: 'nav.endpoint', admin: true, items: ['overview', 'findings', 'exclusions', 'asr', 'devices', 'baseline'] },
    { group: 'nav.agents', admin: true, module: 'agents', items: ['agents', 'agentca'] },
    { group: 'nav.access', admin: true, module: 'access', items: ['access', 'whocan'] },
    { group: 'nav.everyone', admin: false, module: 'access', items: ['mine'] },
    { group: 'nav.history', admin: true, items: ['changes', 'accepted'] }
  ];
  const VIEW_MODULE = { agents: 'agents', agentca: 'agents', access: 'access', whocan: 'access', mine: 'access' };

  async function runNow(module, btn) {
    if (btn) btn.disabled = true;
    try {
      const r = await api(`run?module=${module}`, { method: 'POST' });
      toast(window.WARDLINE_DEMO ? r.message : t('run.started'));
    } catch (e) {
      toast(e.status === 403 && !/Wardline.Admin/.test(e.message) ? t('run.403') : t('run.failed', e.message));
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
    $('#nav').replaceChildren(...NAV.filter(g => (isAdmin || !g.admin) && (!g.module || hasMod(g.module))).map(g => h('div', { class: 'nav-group' }, h('div', { class: 'nav-group-title' }, t(g.group)), g.items.map(id => h('a', { class: 'nav-link', href: `#/${id}`, 'data-view': id }, t(`v.${id}`))))));
    $('#who').replaceChildren(h('strong', null, state.me.displayName || state.me.upn || t('signed.in')), h('span', null, isAdmin ? t('role.admin') : t('role.user')), h('br'), h('a', { href: '/.auth/logout', style: 'color:#A9D9DE' }, t('signout')));
    const up = state.me.update;
    $('#who').append(h('div', { class: 'version' }, state.me.version ? t('version', state.me.version) : null,
      isAdmin && up && up.available && /^https:\/\/github\.com\//.test(up.url || '') ? h('a', { class: 'update-link', href: up.url, target: '_blank', rel: 'noopener noreferrer' }, t('update.available', up.latest)) : null));
    const langSel = h('select', { 'aria-label': t('language'), onchange: (e) => setLang(e.target.value) }, Object.entries(LANGS).map(([k, v]) => { const o = h('option', { value: k }, v); if (k === lang) o.selected = true; return o; }));
    const actions = $('#actions');
    actions.replaceChildren(h('label', { class: 'lang-switch' }, t('language'), langSel));
    if (isAdmin) {
      actions.append(
        h('button', { type: 'button', onclick: async () => { state.endpoint = state.agents = state.access = state.mine = null; state.changes = {}; await route(); toast(t('reloaded')); } }, t('reload')),
        h('button', { type: 'button', class: 'primary', onclick: (e) => runNow('all', e.currentTarget) }, t('run.now')));
    }
  }

  function updateMeta() {
    const ep = state.endpoint, ac = state.access, mi = state.mine, ag = state.agents;
    const ts = [ep && ep.generatedAt, ag && ag.generatedAt, ac && ac.generatedAt, mi && mi.generatedAt].filter(Boolean).sort().pop();
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
    const navView = view === 'device' ? 'devices' : view;
    document.querySelectorAll('.nav-link').forEach(a => { if (a.dataset.view === navView) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
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
    await route();
  }
  init();
})();
