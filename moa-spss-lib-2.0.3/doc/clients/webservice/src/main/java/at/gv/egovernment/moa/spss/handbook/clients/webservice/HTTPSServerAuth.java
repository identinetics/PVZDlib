/*
 * Copyright 2003 Federal Chancellery Austria
 * MOA-SPSS has been developed in a cooperation between BRZ, the Federal
 * Chancellery Austria - ICT staff unit, and Graz University of Technology.
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 * This product combines work with different licenses. See the "NOTICE" text
 * file for details on the various modules and licenses.
 * The "NOTICE" text file is part of the distribution. Any derivative works
 * that you distribute must include a readable copy of the "NOTICE" text file.
 */


package at.gv.egovernment.moa.spss.handbook.clients.webservice;

import java.security.Security;

import com.sun.net.ssl.internal.ssl.Provider;

/**
 * Diese Klasse implementiert einen einfachen Client f�r das MOA SP/SS Webservice mittels Apache Axis. Die
 * Verbindung erfolgt gesichert ueber SSL, und zwar nur mit Serverauthentisierung.
 */
public class HTTPSServerAuth extends HTTP
{
  // JSSE Konstanten
  public static final String HANDLER = "java.protocol.handler.pkgs";
  public static final String TRUSTSTORE = "javax.net.ssl.trustStore";
  public static final String TRUSTSTOREPASSWORD = "javax.net.ssl.trustStorePassword";
  public static final String TRUSTSTORETYPE = "javax.net.ssl.trustStoreType";

  /**
   * Methode main.
   * 
   * Enthaelt den Beispielcode der noetig ist um von Java aus auf MOA-SPSS zugreifen zu koennen. Der Zugriff
   * passiert ueber das AXIS-Framework. Die Verbindung erfolgt gesichert ueber SSL, und zwar nur mit 
   * Serverauthentisierung.
   * 
   * @param args <ul>
   *             <li>
   *             args[0] enthaelt entweder die Bezeichnung "sign" oder "verify" zur Kennzeichnung,
   *             ob ein Signaturerstellungsrequest, oder ein Signaturpruefrequest gesendet werden soll.
   *             </li>
   *             <li>
   *             args[1] enthaelt einen Verweis auf eine Property-Datei, die die naehere Konfiguration
   *             fuer dieses Beispiel enthaelt. Der Verweis enthaelt entweder eine absolute oder eine
   *             relative Pfadangabe, wobei eine relative Angabe als relativ zum Arbeitsverzeichnis der
   *             Java VM interpretiert wird. Folgende Properties muessen in der Properties-Datei vorhanden
   *             sein: 
   *             <ul>
   *             <li>
   *             <code>signServiceQName</code>: Name des Webservices, fix "SignatureCreation"
   *             </li>
   *             <li>
   *             <code>signServiceEndPoint</code>: Zugangspunkt des Webservices (URL)
   *             </li>
   *             <li>
   *             <code>signRequest</code>: Name des zu sendenden Signaturerstellungsrequests (entweder
   *             absolute oder relative Pfadangabe; eine relative Pfadangabe wird relativ zum
   *             Arbeitsverzeichnis der Java VM interpretiert)
   *             </li>
   *             <li>
   *             <code>verifyServiceQName</code>: Name des Webservices, fix "SignatureVerification"
   *             </li>
   *             <li>
   *             <code>verifyServiceEndPoint</code>: Zugangspunkt des Webservices (URL)
   *             </li>
   *             <li>
   *             <code>verifyRequest</code>: Name des zu sendenden Signaturpruefrequests (entweder
   *             absolute oder relative Pfadangabe; eine relative Pfadangabe wird relativ zum
   *             Arbeitsverzeichnis der Java VM interpretiert)
   *             </li>
   *             <li>
   *             <code>ssl.truststore.type</code>: Typ des JSSE-Truststores (entweder "JKS" fuer einen
   *             Java Key Store oder "PKCS12" fuer eine PKCS#12-Datei).
   *             </li>
   *             <li><code>ssl.truststore.type</code>: Relativer oder absoluter Pfad zum JSSE-Truststore.
   *             Ein relativer Pfad wird relativ zum Arbeitsverzeichnis der Java VM interpretiert).
   *             </li>
   *             <li><code>ssl.truststore.pwd</code>: Passwort fuer den JSSE-Truststore.
   *             </li>
   *             </ul>
   *             </li>
   *             </ul>
   */
  public static void main(String[] args)
  {
    try
    {
      // Pr�fen, ob Beispiel korrekt verwendet wird
      checkArgs(args, "HTTP");
      
      // Initialisieren des Clients
      HTTPSServerAuth httpClient = new HTTPSServerAuth(args);
      
      // Ausf�hren der Serviceabfrage
      httpClient.execute(args[0]);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
  }
  
  /**
   * Erzeugt den MOA Client. Es erfolgt die Auswertung der �bergebenen Aufrufparameter.
   * 
   * @param args Die Aufrufparameter fuer das Beispiel. Siehe {@link HTTPSServerAuth#main(String[])}.
   * 
   * @throws Exception wenn der MOA Client mit den uebergebenen Aufrufparametern nicht korrekt erzeugt
   *         werden konnte. 
   */
  protected HTTPSServerAuth(String[] args) throws Exception
  {
    super(args);
    configureSSL();
  }
  
  /**
   * Konfiguriert JSSE fuer eine SSL-Verbindung mit Serverauthentisierung.
   * 
   * @throws Exception wenn die Konfiguration von JSSE fehlschlaegt.
   */
  protected void configureSSL() throws Exception
  {
    // Aktivieren Sie die n�chste Zeile f�r detailliertes Logging des SSL-Verbindungsaufbaus
    // System.setProperty("javax.net.debug", "all");
    
    // Setzen des korrekten Protokoll-Handlers f�r https
    Security.addProvider(new Provider());
    System.setProperty(HANDLER, "com.sun.net.ssl.internal.www.protocol");

    // Konfiguriere Trust-Store (enth�lt SSL-Zertifikat des MOA Services, dem vertraut wird)
    System.setProperty(TRUSTSTORETYPE, getProperty("ssl.truststore.type"));
    System.setProperty(TRUSTSTORE, getProperty("ssl.truststore.loc"));
    System.setProperty(TRUSTSTOREPASSWORD, getProperty("ssl.truststore.pwd"));
  }
}