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


package at.gv.egovernment.moa.spss.handbook.clients.api;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;

import at.gv.egovernment.moa.spss.api.SPSSFactory;
import at.gv.egovernment.moa.spss.api.SignatureCreationService;
import at.gv.egovernment.moa.spss.api.common.Content;
import at.gv.egovernment.moa.spss.api.common.MetaInfo;
import at.gv.egovernment.moa.spss.api.xmlsign.CreateTransformsInfo;
import at.gv.egovernment.moa.spss.api.xmlsign.CreateTransformsInfoProfile;
import at.gv.egovernment.moa.spss.api.xmlsign.CreateXMLSignatureRequest;
import at.gv.egovernment.moa.spss.api.xmlsign.CreateXMLSignatureResponse;
import at.gv.egovernment.moa.spss.api.xmlsign.DataObjectInfo;
import at.gv.egovernment.moa.spss.api.xmlsign.SignatureEnvironmentResponse;
import at.gv.egovernment.moa.spss.api.xmlsign.SingleSignatureInfo;
import at.gv.egovernment.moa.util.DOMUtils;

/**
 * Dieses einfache Beispiel demonstriert grundlegend den Gebrauch der API von MOA SP/SS. Es wird damit eine
 * einfach aufgebaute XML-Signatur erzeugt.
 */
public class CreateXMLSignature
{
  /**
   * Methode main.
   * 
   * Enthält beispielhaften Code zum grundlegenden Gebrauch der API von MOA SP/SS. Es wird damit eine
   * einfach aufgebaute XML-Signatur erzeugt.
   * 
   * ACHTUNG: Stellen Sie bei Verwendung von J2SE 1.4.x bzw. 5.x sicher, dass Sie die System-Property 
   * <code>java.endorsed.dirs</code> auf jenes Verzeichnis gesetzt haben, in dem sich die XPath-
   * und XSLT-Bibliothek <em>Xalan-J</em> befindet.
   * 
   * @param args <ul>
   *             <li>
   *             args[0] enthält einen Verweis auf die Konfigurations-Datei von MOA SP/SS Der Verweis 
   *             enthält entweder eine absolute oder eine relative Pfadangabe, wobei eine relative 
   *             Angabe als relativ zum Arbeitsverzeichnis der Java VM interpretiert wird. 
   *             </li>
   *             <li>
   *             args[1] enthält einen Verweis auf die Konfigurations-Datei von Log4J, dem Logging-
   *             Framework, das von MOA SP/SS verwendet wird. Der Verweis enth�lt entweder eine 
   *             absolute oder eine relative Pfadangabe, wobei eine relative Angabe als relativ zum
   *             Arbeitsverzeichnis der Java VM interpretiert wird. 
   *             </li>
   *             </ul>
   * 
   * @throws Exception Sollten Fehler auftreten werden die Fehler an die Java-VM weitergeleitet.
   */
  public static void main(String[] args) throws Exception
  {
    // Setzen der System-Properties
    init(args);

    // Serverfunktionshandler instanzieren
    SPSSFactory spf = SPSSFactory.getInstance();

    // Zu signierende Daten in ein Contentobjekt einbinden (die Daten werden hier explizit angegeben,
    // sollen aber in der Signatur mittels URL "http://uri.data.org" referenziert werden
    byte[] data = "Diese Daten werden signiert.".getBytes("UTF-8");
    ByteArrayInputStream bis = new ByteArrayInputStream(data);
    Content cont = spf.createContent(bis, null);

    // Metainformationen zu den zu signierenden Daten erstellen
    MetaInfo mi = spf.createMetaInfo("text/plain", null, null, null);

    // Transformationen erstellen (hier werden keine Transformationen angewandt)
    CreateTransformsInfo cti = spf.createCreateTransformsInfo(null, mi);
    CreateTransformsInfoProfile ct = spf.createCreateTransformsInfoProfile(cti, null);

    // Datenobjekt aufbauen
    DataObjectInfo doi = spf.createDataObjectInfo(DataObjectInfo.STRUCTURE_ENVELOPING, false, cont, ct);

    // Erstellen eines SingleSignatureInfo-Containers
    // Enth�lt alle Angaben zur Erstellung *einer* Signatur
    List dataobjectinfolist = new ArrayList();
    dataobjectinfolist.add(doi);
    SingleSignatureInfo ssi = spf.createSingleSignatureInfo(dataobjectinfolist, null, false);

    // Erstellen des Request-Objekts (Schl�sselbezeichner, Liste von SingleSignatureInfo-Containern)
    List singlesignatureinfolist = new ArrayList();
    singlesignatureinfolist.add(ssi);
    CreateXMLSignatureRequest cxsreq = spf.createCreateXMLSignatureRequest("KG_allgemein",
      singlesignatureinfolist);

    // Signatureerstellungsservice instanzieren und aufrufen
    SignatureCreationService scs = SignatureCreationService.getInstance();
    CreateXMLSignatureResponse cxsres = scs.createXMLSignature(cxsreq);

    // Response auswerten
    List elements = cxsres.getResponseElements();
    SignatureEnvironmentResponse ser = (SignatureEnvironmentResponse) elements.get(0);

    // Auswertung des ersten (und einzigen) SignatureEnvironmentResponse-Containers
    int response_type = ser.getResponseType();

    if (response_type == SignatureEnvironmentResponse.ERROR_RESPONSE)
    {
      // Fehlerfall
      System.out.println("Bei der Erstellung der Signatur ist ein Fehler aufgetreten.");
    }
    else
    {
      // Signaturerstellung erfolgreich
      System.out.println("Signaturerstellung erfolgreich:");

      Element se = ser.getSignatureEnvironment();
      System.out.println(DOMUtils.serializeNode(se));
    }
  }

  /**
   * Setzt die notwendigen System-Properties f�r die Konfiguration der MOA SP/SS API. 
   * 
   * @param args Siehe @link CreateXMLSignature#main(String[]).
   */
  private static void init(String[] args)
  {
    if (args == null || args.length != 2)
    {
      System.out.println("Verwendung: CreateXMLSignature <MOASPSSConfigFile> <Log4JConfigFile>");
    }
    System.setProperty("moa.spss.server.configuration", args[0]);
    System.setProperty("log4j.configuration", "file:" + args[1]);
  }
}