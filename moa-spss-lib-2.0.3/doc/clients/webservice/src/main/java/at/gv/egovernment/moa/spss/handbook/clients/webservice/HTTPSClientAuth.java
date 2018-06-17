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


/**
 * Diese Klasse implementiert einen einfachen Client f�r das MOA SP/SS Webservice mittels Apache Axis. Die
 * Verbindung erfolgt gesichert über SSL, und zwar sowohl mit Server- und Clientauthentisierung.
 */
public class HTTPSClientAuth extends HTTPSServerAuth
{
  // JSSE Konstanten
  public static final String KEYSTORE = "javax.net.ssl.keyStore";
  public static final String KEYSTOREPASSWORD = "javax.net.ssl.keyStorePassword";
  public static final String KEYSTORETYPE = "javax.net.ssl.keyStoreType";

  /**
   * Methode main.
   * 
   * Enthaelt den Beispielcode der  noetig ist um von Java aus auf MOA-SPSS zugreifen zu koennen. Der Zugriff
   * passiert ueber das AXIS-Framework. Die Verbindung erfolgt gesichert ueber SSL, und zwar sowohl mit 
   * Server- und Clientauthentisierung.
   * 
   * @param args <ul>
   *             <li>
   *             args[0] enthaelt entweder die Bezeichnung "sign" oder "verify" zur Kennzeichnung,
   *             ob ein Signaturerstellungsrequest, oder ein Signaturprüefrequest gesendet werden soll.
   *             </li>
   *             <li>
   *             args[1] enthaelt einen Verweis auf eine Property-Datei, die die n�here Konfiguration
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
   *             <li><code>ssl.truststore.pwd</code>: Passwort f�r den JSSE-Truststore.
   *             </li>
   *             <li>
   *             <code>ssl.keystore.type</code>: Typ des JSSE-Keystores (entweder "JKS" fuer einen
   *             Java Key Store oder "PKCS12" fuer eine PKCS#12-Datei).
   *             </li>
   *             <li><code>ssl.keystore.type</code>: Relativer oder absoluter Pfad zum JSSE-Keystore.
   *             Ein relativer Pfad wird relativ zum Arbeitsverzeichnis der Java VM interpretiert).
   *             </li>
   *             <li><code>ssl.keystore.pwd</code>: Passwort f�r den JSSE-Keystore.
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
      HTTPSClientAuth httpClient = new HTTPSClientAuth(args);
      
      // Ausf�hren der Serviceabfrage
      httpClient.execute(args[0]);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
  }
  
  /**
   * Erzeugt den MOA Client. Es erfolgt die Auswertung der uebergebenen Aufrufparameter.
   * 
   * @param args Die Aufrufparameter fuer das Beispiel. Siehe {@link HTTPSClientAuth#main(String[])}.
   * 
   * @throws Exception wenn der MOA Client mit den �bergebenen Aufrufparametern nicht korrekt erzeugt
   *         werden konnte. 
   */
  protected HTTPSClientAuth(String[] args) throws Exception
  {
    super(args);
  }
  
  /**
   * Konfiguriert JSSE fuer eine SSL-Verbindung mit Client- und Serverauthentisierung.
   */
  protected void configureSSL() throws Exception
  {
    super.configureSSL();
    
    // Konfiguriere Key-Store (enth�lt privaten Schl�ssel und Zertifikat des Clients)
    System.setProperty(KEYSTORETYPE, getProperty("ssl.keystore.type"));
    System.setProperty(KEYSTORE, getProperty("ssl.keystore.loc"));
    System.setProperty(KEYSTOREPASSWORD, getProperty("ssl.keystore.pwd"));
  }
}