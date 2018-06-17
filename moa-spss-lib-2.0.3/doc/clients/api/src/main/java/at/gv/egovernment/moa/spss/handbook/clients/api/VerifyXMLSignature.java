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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.HashMap;

import at.gv.egovernment.moa.spss.MOAException;
import at.gv.egovernment.moa.spss.api.SPSSFactory;
import at.gv.egovernment.moa.spss.api.SignatureVerificationService;
import at.gv.egovernment.moa.spss.api.common.Content;
import at.gv.egovernment.moa.spss.api.common.SignerInfo;
import at.gv.egovernment.moa.spss.api.xmlverify.VerifySignatureInfo;
import at.gv.egovernment.moa.spss.api.xmlverify.VerifySignatureLocation;
import at.gv.egovernment.moa.spss.api.xmlverify.VerifyXMLSignatureRequest;
import at.gv.egovernment.moa.spss.api.xmlverify.VerifyXMLSignatureResponse;

/**
 * Dieses einfache Beispiel demonstriert grundlegend den Gebrauch der API von MOA SP/SS. 
 * Es wird damit eine einfach aufgebaute XML-Signatur gepr�ft.
 */

public class VerifyXMLSignature
{
  /**
   * Methode main.
   * 
   * Enthält beispielhaften Code zum grundlegenden Gebrauch der API von MOA SP/SS. 
   * Es wird damit eine einfach aufgebaute XML-Signatur geprüft.
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
   *             <li>
   *             args[2] enth�lt Pfad und Dateiname des XML-Dokuments mit der darin enthaltenen, zu
   *             prüfenden XML-Signatur. Verwenden Sie z.B. das mit diesem Handbuch mitgelieferte
   *             Beispiel <code>clients/api/signatures/SimpleSignature.xml</code>.
   *             </li>
   *             </ul>
   */
  public static void main(String[] args)
  {
    // Setzen der System-Properties
    init(args);

    // Factory und Service instanzieren
    SPSSFactory spssFac = SPSSFactory.getInstance();
    SignatureVerificationService sigVerifyService = SignatureVerificationService.getInstance();
    
    // Content aus Dokument mit zu pr�fender Signatur erstellen
    FileInputStream sigDocFIS = null;
    try
    {
      sigDocFIS = new FileInputStream(args[2]);
    }
    catch (FileNotFoundException e1)
    {
      System.err.println("XML-Dokument mit zu prüfender Signatur nicht gefunden: " + args[2]);
      System.exit(-1);
    }
    Content sigDocContent = spssFac.createContent(sigDocFIS, null);
    
    // Position der zu pr�fenden Signatur im Dokument angeben
    // (Nachdem im XPath-Ausdruck ein NS-Pr�fix verwendet wird, muss in einer Lookup-Tabelle
    // der damit bezeichnete Namenraum mitgegeben werden)
    HashMap nSMap = new HashMap();
    nSMap.put("dsig", "http://www.w3.org/2000/09/xmldsig#");
    VerifySignatureLocation sigLocation = spssFac.createVerifySignatureLocation("//dsig:Signature", nSMap);
    
    // Zu pr�fendes Dokument und Signaturposition zusammenfassen
    VerifySignatureInfo sigInfo = spssFac.createVerifySignatureInfo(sigDocContent, sigLocation);
    
    // Pr�frequest zusammenstellen
    VerifyXMLSignatureRequest verifyRequest = spssFac.createVerifyXMLSignatureRequest(
      null,    // Wird Pr�fzeit nicht angegeben, wird aktuelle Zeit verwendet 
      sigInfo, 
      null,    // Keine Erg�nzungsobjekte notwendig
      null,    // Signaturmanifest-Pr�fung soll nicht durchgef�hrt werden
      false,   // Hash-Inputdaten, d.h. tats�chlich signierte Daten werden nicht zur�ckgeliefert
      "Test-Signaturdienste");  // ID des verwendeten Vertrauensprofils
    
    VerifyXMLSignatureResponse verifyResponse = null;
    try
    {
      // Aufruf der Signaturpr�fung
      verifyResponse = sigVerifyService.verifyXMLSignature(verifyRequest);
    }
    catch (MOAException e)
    {
      // Service liefert Fehler
      System.err.println("Die Signaturprüfung hat folgenden Fehler geliefert:");
      System.err.println("Fehlercode: " + e.getMessageId());
      System.err.println("Fehlernachricht: " + e.getMessage());
      System.exit(-1);
    }
    
    // Auswertung der Response
    System.out.println();
    System.out.println("Ergebnisse der Signaturprüfung:");
    System.out.println();
    
    // Besondere Eigenschaften des Signatorzertifikats
    SignerInfo signerInfo = verifyResponse.getSignerInfo();
    System.out.println("*** Ist Zertifikat des Signators qualifiziert? " + ((signerInfo.isQualifiedCertificate()) ? "ja" : "nein"));
    System.out.println("*** Ist Zertifikat des Signators von einer Behürde? " + ((signerInfo.isPublicAuthority()) ? "ja" : "nein"));
    
    // Ergebnisse von Signatur- und Zertifikatspr�fung
    System.out.println();
    System.out.println("Ergebniscode der Signaturprüfung: " + verifyResponse.getSignatureCheck().getCode());
    System.out.println("Ergebniscode der Zertifikatsprüfung: " + verifyResponse.getCertificateCheck().getCode());
    
    // Signatorzertifikat
    System.out.println();
    System.out.println("*** Zertifikat des Signators:");
    System.out.println("Aussteller: " + signerInfo.getSignerCertificate().getIssuerDN());
    System.out.println("Subject: " + signerInfo.getSignerCertificate().getSubjectDN());
    System.out.println("Seriennummer: " + signerInfo.getSignerCertificate().getSerialNumber());
  }

  /**
   * Setzt die notwendigen System-Properties f�r die Konfiguration der MOA SP/SS API. 
   * 
   * @param args Siehe @link VerifyXMLSignature#main(String[]).
   */
  private static void init(String[] args)
  {
    if (args == null || args.length != 3)
    {
      System.out.println("Verwendung: VerifyXMLSignature <MOASPSSConfigFile> <Log4JConfigFile> <XMLDocWithSignature>");
      System.exit(-1);
    }
    System.setProperty("moa.spss.server.configuration", args[0]);
    System.setProperty("log4j.configuration", "file:" + args[1]);
  }
}