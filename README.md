# TWIN SIGNAL

Die Website enthält die öffentliche Twin-Signal-Seite, Mitgliederkonten, Kundenliste, Chat, Profile, Beat-Verwaltung und Geräteauswahl für Audio-/Videoanrufe.

## Lokale Vorschau
```powershell
$env:ADMIN_SETUP_KEY="ein-sicherer-einrichtungscode"
$env:SESSION_SECRET="mindestens-32-zufaellige-zeichen"
npm.cmd start
```

Danach `http://localhost:4173` aufrufen.

## Admin-Einrichtung

Unter **CHAT & ANRUFE → ADMIN** kann das erste Administrator-Konto erstellt werden. Der Server erlaubt nur ein Admin-Konto; weitere Admin-Erstellungen werden abgewiesen. Zur Einrichtung sind ein Admin-Passwort und der `ADMIN_SETUP_KEY` aus der Serverumgebung erforderlich. Bei jeder Admin-Anmeldung werden Passwort und Admin-Code abgefragt. Der Code lässt sich nach dem Login unter **Einstellungen** ändern; dazu ist das aktuelle Admin-Passwort erforderlich.

Das Admin-Portal enthält:
- Kundenübersicht
- Chat mit Mitgliedern; Admins können den gesamten Verlauf mit einem Mitglied löschen
- Kontakt- und exklusive Beat-Anfragen einsehen und einzeln löschen
- Beats hinzufügen/löschen und MP3-, WAV-, OGG-, WEBM-, M4A-, AAC- oder FLAC-Audio (max. 12 MB) hochladen
- Profilverwaltung
- Audio-/Video-Gruppenanruf mit bis zu vier Personen; Teilnehmer können weitere einladen, der Host kann entfernen; eigenes Mikrofon stummschaltbar
- Geräteauswahl und Kameraqualität von Auto bis 4K (abhängig von Kamera und Verbindung)

## Chat- und Anrufmenü

Der Hauptmenüpunkt **CHAT & ANRUFE** öffnet den Discord-ähnlichen Kommunikationsbereich. Ohne Anmeldung öffnet sich zuerst das Account-Fenster. Nach Anmeldung sind Kontaktliste, Nachrichtenverlauf, Profil, Audiogeräte und Kamerageräte verfügbar. Auf Mobilgeräten lässt sich der Gesprächspartner über die Auswahl im Chatkopf wechseln. Während eines Anrufs erstellt **LINK PER WHATSAPP** einen teilbaren Beitrittslink. Eingeladene Personen müssen sich anmelden oder ein Mitgliedskonto erstellen. Links funktionieren nur solange der Anruf aktiv ist; der Server prüft die Vierergrenze und widerruft Links, wenn der Host jemanden entfernt. Anrufe verwenden WebRTC, STUN und optional einen TURN-Dienst. STUN allein reicht in manchen Mobilfunk- und Firmennetzwerken nicht; für zuverlässige Verbindungen dort muss ein TURN-Dienst eingerichtet werden.

## Noch benötigte externe Konfiguration

Für produktiven Bot-Schutz die Turnstile-Schlüssel bei Cloudflare anlegen und als Servervariablen setzen:

```text
TURNSTILE_SITE_KEY=...
TURNSTILE_SECRET_KEY=...
```

Kontakt-, Exklusivbeat- und Registrierungsformulare prüfen einen Turnstile-Token serverseitig, wenn beide Turnstile-Schlüssel konfiguriert sind. Ohne Schlüssel funktionieren die Formulare mit IP-Ratenlimits und Honeypot weiter; eine unvollständige Turnstile-Konfiguration wird ausdrücklich abgelehnt. Anmeldungen verwenden kein CAPTCHA und sind durch IP-Ratenlimits geschützt.

Für den Produktivbetrieb außerdem erforderlich:

- `SESSION_SECRET`: zufälliger, geheimer Wert mit mindestens 32 Zeichen
- `ADMIN_SETUP_KEY`: eigener einmaliger Einrichtungscode (mindestens 8 Zeichen); `Dozett808` nur lokal bzw. nach vorherigem Wechsel nutzen
- `PUBLIC_ORIGIN`: exakte öffentliche URL, z. B. `https://twin-signal.example`
- `COOKIE_SECURE=true`, wenn TLS an einem Reverse-Proxy endet
- HTTPS und persistenter Speicher für `DATA_DIR`
- optional für Anrufe in restriktiven Netzwerken: `TURN_URLS` und `TURN_SHARED_SECRET` eines TURN-Dienstes mit Coturn-REST-Authentifizierung; der Server erstellt kurzlebige Zugangsdaten für den Browser

Keine Zugangsdaten oder Secrets in der Frontend-Datei speichern.

## Sicherheitstests

```powershell
npm.cmd test
```

Die Integrationstests starten einen eigenen temporären Server und prüfen HTTP-Security-Header, gesperrte Serverdateien, das einzelne Admin-Konto, Admin-/Mitgliederrechte beim Audio-Upload, Call-Link-Authentifizierung und -Widerruf, Dateisignaturen, Range-Streaming, Cross-Origin-Schutz, Honeypot und Ratenlimits. Die Testdaten liegen außerhalb des Projekts und werden nach den Tests entfernt.

## Stripe und rechtliche Seiten

Die drei Hauptpakete sind mit den hinterlegten Stripe-Payment-Links verbunden. Einzelangebote werden im Buchungsassistenten über den gewählten Link an Stripe weitergeleitet.

Impressum, Datenschutzerklärung, AGB und Widerrufsbelehrung sind als sichtbare Inhaltsbereiche eingebunden. Die Texte enthalten bewusst Prüfhinweise und müssen vor einem Live-Betrieb durch eine fachkundige Person vervollständigt werden.

## Transparente Integrationsgrenzen

Aktuell simuliert die Oberfläche keine reale Zahlung, Buchung oder Nachricht. Die Buchungsdaten werden nicht erfunden oder gespeichert. Eine echte Buchung darf erst nach einem serverseitig verifizierten Stripe-Webhooks persistiert werden.

Der mitgelieferte Server speichert Konten, Rollen, Nachrichten und Beats in `DATA_DIR/store.json`; Audiodateien liegen in `DATA_DIR/audio`. Sitzungen verwenden HttpOnly-/SameSite-Cookies. Der Server setzt Security-Header und stellt ausschließlich die Website-Datei, Studio-Bilder und API-Routen statisch bereit. Audio wird über Beat-IDs mit Range-Unterstützung gestreamt. Browser können abgespielte Audios technisch nicht zuverlässig vor Mitschnitten schützen.

## Onlinebetrieb mit Render

Der gesamte Node-Server muss auf einem Node-Hostingdienst laufen: Er stellt sowohl die Website als auch Anmeldung, Registrierung, Chat und Anruf-Signalisierung bereit. Netlify allein kann diesen Server nicht ausführen. Die `render.yaml`-Vorlage richtet einen einzelnen Render-Webdienst mit dauerhaftem Datenträger ein. Render kann dafür Kosten berechnen; die Vorlage löst selbst noch kein Deployment aus.

1. Das Projekt ohne `.env`, `data/store.json` oder `data/audio` in ein privates GitHub-Repository laden.
2. In Render **New → Blueprint** wählen und das Repository verbinden. Beim Einrichten `ADMIN_SETUP_KEY` durch einen geheimen Wert von mindestens 8 Zeichen ersetzen.
3. Nach dem ersten Start die öffentliche HTTPS-Adresse als `PUBLIC_ORIGIN` eintragen (ohne abschließenden Schrägstrich) und den Dienst neu starten. `SESSION_SECRET` wird von Render erzeugt; `COOKIE_SECURE` ist für HTTPS aktiviert.
4. Die gewünschte Domain in Render als Custom Domain hinzufügen und die dort angezeigten DNS-Einträge bei Netlify setzen. Netlify bleibt dabei DNS-Verwalter; die Website selbst wird von Render ausgeliefert.
5. Für Anrufe, die auch hinter restriktiven Routern funktionieren sollen, einen Coturn-REST-kompatiblen TURN-Dienst einrichten und `TURN_URLS` (kommagetrennte `turn:`/`turns:`-URLs) sowie `TURN_SHARED_SECRET` im Render-Dashboard setzen. Ohne TURN können manche Netze keine Peer-to-Peer-Verbindung herstellen.

Der Dienst ist absichtlich auf eine Instanz mit persistentem Speicher ausgelegt. Mehrere Instanzen benötigen eine gemeinsame Datenbank, gemeinsamen Objektspeicher und verteilte Anruf-Signalisierung. Ein Deployment wurde nicht ausgelöst; dafür ist eine bewusste Bestätigung im Hosting-Konto erforderlich.
