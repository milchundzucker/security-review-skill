# XML — XXE, XSLT, SAML, SOAP

Wird geladen, wenn XML-Verarbeitung erkannt wird: SOAP-Endpoints, SAML-Auth, XML-RPC, XML-Config, Office-Dateien (.docx/.xlsx sind ZIP+XML).

## XML External Entity (XXE)

### Was

XML-Parser kann externe Entitäten auflösen: Dateilesung, SSRF, Billion-Laughs-DoS, in seltenen Fällen RCE.

### Klassische Payloads

```xml
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r>&x;</r>

<!-- SSRF -->
<!DOCTYPE r [<!ENTITY x SYSTEM "http://internal-service/admin">]>

<!-- Billion Laughs DoS -->
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- usw. - exponentielle Expansion -->
]>
<lolz>&lol9;</lolz>

<!-- PHP Wrapper RCE (alt) -->
<!DOCTYPE r [<!ENTITY x SYSTEM "expect://id">]>
```

### Python

```
rg "xml\.etree|xml\.sax|xml\.dom" --type py | rg -v "defusedxml"
rg "lxml\.etree" --type py
rg "xmltodict\.parse" --type py
```

**Anti-Pattern:**
```python
import xml.etree.ElementTree as ET
tree = ET.parse(user_file)  # XXE-anfällig in alten Python-Versionen
```

**Sicher:**
```python
from defusedxml.ElementTree import parse
tree = parse(user_file)
```

`defusedxml` ist die Standardlösung in Python. Alternative: `lxml` mit `XMLParser(resolve_entities=False, no_network=True)`.

### Java

```
rg "DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XMLReader|Unmarshaller" --type java -A 5
rg "setFeature.*disallow-doctype-decl|FEATURE_SECURE_PROCESSING" --type java
```

**Sicher (DocumentBuilder):**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

Best Practice: **OWASP XML External Entity Prevention Cheat Sheet** konsultieren. Java-Defaults variieren je nach Version.

### .NET

```
rg "XmlDocument|XmlReader|XmlTextReader|XmlSerializer" --type cs -A 5
```

**Pre-.NET 4.5.2** war XXE Standard-on. Ab .NET 4.5.2: `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit`.

### PHP

```
rg "libxml_disable_entity_loader|LIBXML_NOENT" --type php
rg "simplexml_load_(file|string)" --type php
rg "DOMDocument" --type php -A 3
```

PHP < 8.0: `libxml_disable_entity_loader(true)` als Workaround. PHP ≥ 8.0: standardmäßig sicher, aber bei explizitem `LIBXML_NOENT` wird XXE wieder aktiv.

### Go

```
rg "encoding/xml" --type go
rg "xml\.NewDecoder|xml\.Unmarshal" --type go
```

Go's `encoding/xml` ist standardmäßig XXE-sicher (keine Entity-Expansion), aber Custom-Parser können das umgehen.

## XInclude

```
rg "XInclude|xi:include" --type py --type java --type xml
```

XInclude erlaubt das Einbinden externer Dateien. Auch wenn klassisches XXE blockiert ist, kann XInclude den gleichen Effekt haben.

**Sicher:** `setXIncludeAware(false)` (Java), `resolve_entities=False` (Python lxml).

## XSLT-Injection

```
rg "TransformerFactory|XSLTProcessor|saxon" --type java --type py
```

XSLT 1.0/2.0 erlaubt:
- Datei-Zugriffe via `document()`-Function
- Code-Execution via Extension-Functions (Java, .NET)
- SSRF via `document()`

**Anti-Pattern:** XSLT-Stylesheet aus User-Input.

**Sicher:** XSLT-Templates serverseitig vorhalten, niemals User-Templates akzeptieren. Wenn doch: gesperrtes Saxon-HE mit deaktivierten Extensions.

## XPath-Injection

```
rg "XPath|selectNodes\(|evaluate\(.*request" --type java --type py --type cs
```

**Anti-Pattern:**
```java
String expr = "//user[name='" + username + "' and pass='" + password + "']";
NodeList n = (NodeList) xpath.evaluate(expr, doc, XPathConstants.NODESET);
```

**Angriff:** `username = "admin' or '1'='1"` → XPath-Injection.

**Sicher:** Variable-Binding über XPath-Variablen (`$user`, `$pass`).

## SAML — XML-Spezifische Risiken

Siehe auch `auth-oauth-saml.md`. Im XML-Kontext zusätzlich:

### XML Signature Wrapping (XSW)

Die SAML-Assertion ist signiert, aber:
- Der Parser liest aus einer anderen Position als die Signatur deckt
- Comment-Knoten (`<!-- ... -->`) splitten Text-Nodes → manche Parser kombinieren, manche nicht
- Zusätzliche `<Assertion>`-Elemente im Document, an Stellen wo das Schema das nicht vorsieht

**Mitigation:**
- Schema-Strict-Validation
- XPath-basiertes Lesen nur aus dem signierten Element (mit absoluter URI-Referenz, nicht Position)
- Library nutzen, die gegen XSW gehärtet ist (Onelogin Python-SAML, etc.)

### SAML-Replay

Ohne `NotBefore`/`NotOnOrAfter`/`OneTimeUse` Conditions ist eine abgefangene Assertion wiederverwendbar.

## SOAP-Spezifika

```
rg "soap|SOAPClient|zeep|suds" -i --type py --type java -A 3
```

- **SOAPAction-Spoofing**: WS-Security-Auth basiert auf SOAPAction-Header, aber Backend führt anders aus
- **WSDL-Public-Exposure**: oft unbeabsichtigt, exponiert komplette Service-Description
- **WS-Security**-Konfigurationen oft fehlerhaft (XSW siehe oben)
- **MTOM/XOP-Attacks**: Anhänge mit unsicheren Mime-Types

## Office-Dateien (DOCX, XLSX, PPTX)

DOCX/XLSX/PPTX sind ZIP-Archive mit XML drin. Wenn User-Upload geparst wird:
- XXE im inneren XML (z. B. `[Content_Types].xml`, `word/document.xml`)
- Zip-Slip beim Entpacken
- Makro-Inhalte als Persistenz-Vektor (DOCM, XLSM)

```
rg "openpyxl|python-docx|python-pptx|olefile" --type py
rg "Apache\s+POI|HSSFWorkbook|XSSFWorkbook" --type java
```

**Sicher:** Libraries auf XXE-Schutz prüfen. `openpyxl` ab 2.5 ist sicher; alte Versionen nicht.

## XML-Bombs (DoS)

Neben Billion Laughs:
- **Quadratic Blowup**: einzelne sehr lange Entity wird mehrfach referenziert (linearer Speicher pro Reference, aber n*m gesamt)
- **External Entity Recursion**: über Netzwerk fetchende Entity blockiert Parser
- **Large XML**: Multi-GB-Dokument, expand-while-parsing

**Mitigation:** Memory-Limits am Parser setzen (`maxOccurs`-Limits in JAXP, `huge_tree=False` in lxml).

## Befund-Beispiel

```
[XML-01] XXE in SAML-Response-Parser
Severity:    Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N = 9.3)
Exploitability: External-Unauth (über manipulierte SAML-Response von Angreifer-IdP)
CWE:         CWE-611 Improper Restriction of XML External Entity Reference

Evidence:
src/auth/saml.py:23:    from xml.etree import ElementTree as ET
                   24:    response = ET.fromstring(b64decode(saml_response))

xml.etree wird ohne XXE-Schutz verwendet. Ein präpariertes SAML-Response
mit DOCTYPE-Declaration kann beliebige Server-Dateien lesen
(z. B. /etc/passwd, /var/log/auth.log, /proc/self/environ → Secrets).

Action:
1. defusedxml.ElementTree statt xml.etree.ElementTree
2. SAML-Library mit gehärtetem XML-Parser (python3-saml von OneLogin)
3. Audit aller XML-Parser im Codebase

References:
- OWASP XML External Entity Prevention Cheat Sheet
- CVE-2022-21703 (vergleichbarer SAML-XXE in einem bekannten Tool)
```

## Mappings

- CWE-611 XML External Entity Reference
- CWE-776 XML Entity Expansion (Billion Laughs)
- CWE-91 XML Injection
- CWE-643 XPath Injection
- A03 Injection (XXE als Sonderfall)
- A05 Security Misconfiguration (Parser-Default-Konfiguration)
- A08 Software and Data Integrity Failures (SAML Signature Wrapping)
