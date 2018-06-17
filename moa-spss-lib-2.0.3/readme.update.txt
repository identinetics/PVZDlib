-------------------------------------------------------------------------------
  Update einer bestehenden MOA-SPSS-Installation auf Version 2.0.3
-------------------------------------------------------------------------------
Es gibt zwei Moeglichkeiten (im Folgenden als "Update Variante A" und 
"Update Variante B" bezeichnet), das Update von MOA-SPSS auf Version
2.0.2 durchzufuehren. Update Variante A geht dabei den Weg ueber eine 
vorangestellte Neuinstallation, waehrend Variante B direkt eine  
bestehende Installation aktualisiert.

Folgende Begriffe werden verwendet:

JAVA_HOME bezeichnet das Wurzelverzeichnis der JDK-Installation

CATALINA_HOME bezeichnet das Wurzelverzeichnis der Tomcat-Installation

MOA_SPSS_INST bezeichnet das Verzeichnis, in das Sie die Datei
moa-spss-2.0.2.zip entpackt haben.

--------------------------
Update Variante A 
--------------------------

1.)	Erstellen Sie eine Sicherungskopie des kompletten Tomcat-Verzeichnisses
	Ihrer MOA-SPSS-Installation.
	
2.)	Fuehren Sie eine Neuinstallation gemaess Handbuch durch.

3.)	Kopieren Sie etwaige Konfigurationsdateien, Trust-Profile und Key-Stores, 
	die Sie aus Ihrer alten Installation beibehalten moechten, aus Ihrer
	Sicherungskopie in die entsprechenden Verzeichnisse der neuen
	Installation.
	Anmerkung: Falls Sie Ihre alten Trustprofile beibehalten wollen, gehen Sie wie unter
	Update Variante B, Punkt 9 beschrieben vor, um Ihre alten Trustprofile
	auf einen aktuellen Stand zu bringen.
	
4.)	Nur wenn alte Installation aelter als Version 1.3.0: 
	Falls Sie Ihre alte MOA-SP Konfigurationsdatei weiterverwenden wollen:
	Seit dem Wechsel auf Version 1.3.1 verwendet MOA SP ein neues Format fuer die 
	XML-Konfigurationsdatei. Sie muessen die Konfigurationsdatei fuer MOA-SP aus 
	Ihrer alten Installation auf das neue Format konvertieren.
	Details dazufinden Sie im MOA-SPSS-Installationshandbuch.
	
	
--------------------------
Update Variante B 
--------------------------

1.)	Erstellen Sie eine Sicherungskopie des kompletten Tomcat-Verzeichnisses
	Ihrer MOA-SPSS-Installation.
	
2.)	Entpacken Sie die Datei "moa-spss-2.0.3.zip" in das Verzeichnis MOA_SPSS_INST.

3.)	Erstellen Sie eine Sicherungskopie aller "*.jar"-Dateien im Verzeichnis
	JAVA_HOME\jre\lib\ext und loeschen Sie diese Dateien danach.
	
4.)	Kopieren Sie alle Dateien aus dem Verzeichnis MOA_SPSS_INST\ext in das 
  	Verzeichnis	JAVA_HOME\jre\lib\ext (Achtung: Java 1.4.x wird nicht mehr 
  	unterstuetzt).
	
5.)	Kopieren Sie die Dateien aus dem Verzeichnis MOA_SPSS_INST\endorsed
	in das Verzeichnis CATALINA_HOME\common\endorsed. Ueberschreiben Sie dabei
	etwaige gleichnamige Dateien. Die dort eventuell vorhandene Datei 
  	xmlParserAPIs.jar ist zu loechen.
	
6.) Loeschen Sie das Verzeichnis CATALINA_HOME\webapps\moa-spss.

7.) Ersetzen Sie die Datei CATALINA_HOME\webapps\moa-spss.war durch die Datei 
	MOA_SPSS_INST\moa-spss.war.
		
8.) Loeschen Sie das Verzeichnis CATALINA_HOME\work.
					
9.)	Nur wenn alte Installation aelter als Version 1.3.0: 
	Mit dem Wechsel auf Version 1.3.0 verwendet MOA SP ein neues Format fuer die 
	XML-Konfigurationsdatei. Sie muessen die Konfigurationsdatei fuer MOA-SP aus 
	Ihrer alten Installation auf das neue Format konvertieren. Details dazu 
	finden Sie im MOA-SPSS-Installationshandbuch.