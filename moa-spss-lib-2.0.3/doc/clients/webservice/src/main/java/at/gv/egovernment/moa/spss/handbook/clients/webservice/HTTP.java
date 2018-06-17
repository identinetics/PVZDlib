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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Properties;
import java.util.Vector;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.rpc.Call;
import javax.xml.rpc.Service;
import javax.xml.rpc.ServiceFactory;

import org.apache.axis.message.SOAPBodyElement;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.w3c.dom.Document;

/**
 * Diese Klasse implementiert einen einfachen Client f�r das MOA SP/SS Webservice mittels Apache Axis. Die
 * Verbindung erfolgt ungesichert über HTTP.
 */
public class HTTP
{
  protected Properties props_;

  /**
   * Methode main.
   * 
   * Enthält den Beispielcode der nötig ist um von Java aus auf MOA-SPSS zugreifen zu können. Der Zugriff
   * passiert über das AXIS-Framework. Die Verbindung erfolgt ungesichert über HTTP.
   * 
   * @param args <ul>
   *             <li>
   *             args[0] enthält entweder die Bezeichnung "sign" oder "verify" zur Kennzeichnung,
   *             ob ein Signaturerstellungsrequest, oder ein Signaturprüfrequest gesendet werden soll.
   *             </li>
   *             <li>
   *             args[1] enthält einen Verweis auf eine Property-Datei, die die n�here Konfiguration
   *             f�r dieses Beispiel enthält. Der Verweis enthält entweder eine absolute oder eine
   *             relative Pfadangabe, wobei eine relative Angabe als relativ zum Arbeitsverzeichnis der
   *             Java VM interpretiert wird. Folgende Properties m�ssen in der Property-Datei vorhanden
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
   *             <code>verifyRequest</code>: Name des zu sendenden Signaturprüfrequests (entweder
   *             absolute oder relative Pfadangabe; eine relative Pfadangabe wird relativ zum
   *             Arbeitsverzeichnis der Java VM interpretiert)
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
      HTTP httpClient = new HTTP(args);
      
      // Ausf�hren der Serviceabfrage
      httpClient.execute(args[0]);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
  }
  
  /** 
   * Pr�ft, ob das Beispiel korrekt verwendet wird.
   * 
   * @param args Die Aufrufparameter für das Beispiel. Siehe {@link HTTP#main(String[])}.
   * 
   * @param exampleName Der Name dieses Beispiels, der im Hilfetext gedruckt wird.
   */
  protected static void checkArgs(String[] args, String exampleName)
  {
    if (args == null || args.length != 2 || (!"sign".equals(args[0]) && !"verify".equals(args[0])))
    {
      System.out.println("Verwendung: " + exampleName + " \"sign\"|\"verify\" Properties-Datei");
    }
  }
  
  /**
   * Erzeugt den MOA Client. Es erfolgt die Auswertung der �bergebenen Aufrufparameter.
   * 
   * @param args Die Aufrufparameter für das Beispiel. Siehe {@link HTTP#main(String[])}.
   * 
   * @throws Exception wenn der MOA Client mit den �bergebenen Aufrufparametern nicht korrekt erzeugt
   *         werden konnte. 
   */
  protected HTTP(String[] args) throws Exception
  {
    props_ = new Properties();
    props_.load(new FileInputStream(args[1]));
  }
  
  /**
   * F�hrt die Abfrage beim MOA-Service aus.
   * 
   * @param mode Steuert, ob eine Signatur erstellt ("sign") oder gepr�ft ("verify") werden soll.
   * 
   * @throws Exception wenn dabei etwas schiegeht.
   */
  protected void execute(String mode) throws Exception
  {
    // Datei mit Request einlesen
    FileInputStream inputStream = new FileInputStream(getProperty(mode + "Request"));

    // Parser/DOMBuilder instanzieren
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    DocumentBuilder builder = factory.newDocumentBuilder();

    // XML Datei in einen DOM-Baum umwandeln
    Document xmlRequest = builder.parse(inputStream);

    // AXIS-Server instanzieren
    Service service = ServiceFactory.newInstance().createService(new QName(getProperty(mode + "ServiceQName")));

    // Call �ffnen
    Call call = service.createCall();

    // Neues BodyElement anlegen und mit dem DOM-Baum f�llen
    SOAPBodyElement body = new SOAPBodyElement(xmlRequest.getDocumentElement());
    SOAPBodyElement[] params = new SOAPBodyElement[]
    {
      body
    };

    // Call mit Endpoint verkn�pfen
    call.setTargetEndpointAddress(getProperty(mode + "ServiceEndPoint"));

    // Call ausl�sen und die Antworten speichern
    System.out.println("Calling ...");
    Vector responses = (Vector) call.invoke(params);

    // Erstes Body Element auslesen
    SOAPBodyElement response = (SOAPBodyElement) responses.get(0);

    // Aus der Response den DOM-Baum lesen
    Document root_response = response.getAsDocument();
    System.out.println("Return ...");

    // XML-Formatierung konfiguieren
    OutputFormat format = new OutputFormat((Document) root_response);
    format.setLineSeparator("\n");
    format.setIndenting(false);
    format.setPreserveSpace(true);
    format.setOmitXMLDeclaration(false);
    format.setEncoding("UTF-8");

    // Ausgabe der Webservice-Antwort auf die Konsole
    XMLSerializer conSerializer = new XMLSerializer(System.out, format);
    conSerializer.serialize(root_response);

    // Ausgabe der Webservice-Antwort in Datei
    String responseFile = getProperty(mode + "Request").substring(0, getProperty(mode + "Request").lastIndexOf('.'))
      + ".response.xml";
    XMLSerializer fileSerializer = new XMLSerializer(new FileOutputStream(responseFile), format);
    fileSerializer.serialize(root_response);
  }
  
  /**
   * Pr�ft ob die Property mit dem angegebenen Namen in den Konfigurations-Properties enthalten ist.
   *  
   * @param propName Name der zu untersuchenden Property.
   * 
   * @return den Wert der gesuchten Property.
   * 
   * @throws Exception wenn die gesuchte Property nicht vorhanden ist.
   */
  protected String getProperty(String propName) throws Exception
  {
    String propValue = props_.getProperty(propName);
    if ((propValue == null) || "".equals(propValue.trim()))
    {
      throw new Exception("Property named \"" + propName + "\" does not exist.");
    }
    return propValue;
  }
}