import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;
import java.security.cert.X509Certificate;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Collections;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

public Document generateSignValue(Document xmlDoc, boolean includeKeyInfo) throws Exception {
    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

    // SHA-256 digest method
    Reference ref = fac.newReference(
        "",
        fac.newDigestMethod(DigestMethod.SHA256, null),
        Collections.singletonList(
            fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)
        ),
        null,
        null
    );

    // Canonicalization and SignatureMethod using RSA-SHA256
    SignedInfo sInfo = fac.newSignedInfo(
        fac.newCanonicalizationMethod(
            CanonicalizationMethod.INCLUSIVE,
            (C14NMethodParameterSpec) null
        ),
        fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
        Collections.singletonList(ref)
    );

    if (this.keyEntry == null) {
        throw new RuntimeException("Key could not be read for digital signature. Please check value of signature alias and signature password, and restart the Auth Client");
    }

    X509Certificate x509Cert = (X509Certificate) this.keyEntry.getCertificate();
    KeyInfo kInfo = includeKeyInfo ? this.getKeyInfo(fac, x509Cert.getPublicKey()) : null;

    DOMSignContext dsc = new DOMSignContext(this.keyEntry.getPrivateKey(), xmlDoc.getDocumentElement());

    XMLSignature signature = fac.newXMLSignature(sInfo, kInfo);
    signature.sign(dsc);

    Node node = dsc.getParent();
    return node.getOwnerDocument();
}



































DECLARE matchList CHARACTER '10.177.44.27:5003:PAYMENT_SYS:Payment_S_01','10.177.44.29:5005:PAYMENT_SYS:Payment_S_01','10.177.44.27:5003:PAYMENT_SYS:Payment_S_02';

DECLARE selectQuery CHARACTER 'SELECT name, value FROM your_table WHERE CONCAT(ip,'':'',port,'':'',broker,'':'',eg) IN (' || matchList || ')';

DECLARE refResult REFERENCE TO OutputRoot.XMLNSC.ResultSet;
SET refResult[] = PASSTHRU(selectQuery);







CREATE COMPUTE MODULE ParseCacheESQL
  CREATE FUNCTION Main() RETURNS BOOLEAN
  BEGIN
    DECLARE input CHARACTER '10.177.44.27:5003:PAYMENT SYS: Payment S 01/10.177.44.29:5005:PAYMENT_SYS : Payment S 01/10.177.44.27:5003: PAYMENT SYS: Payment S 02';
    DECLARE entryList REFERENCE TO OutputRoot.JSON.Data.Entries;
    CREATE FIELD OutputRoot.JSON.Data.Entries;

    DECLARE entryListArr REFERENCE TO CreateLastChild(OutputRoot.JSON.Data, 'Entries');
    DECLARE i INT 1;
    DECLARE entry CHARACTER;

    WHILE i <= CARDINALITY(SPLIT(input, '/')) DO
      SET entry = TRIM(SPLIT(input, '/')[i]);

      -- Parse the entry
      DECLARE parts CHARACTER '';
      DECLARE j INT;
      DECLARE ip CHARACTER;
      DECLARE port CHARACTER;
      DECLARE system CHARACTER;
      DECLARE label CHARACTER;
      DECLARE tokens REFERENCE TO Environment.Variables.Tokens;

      CREATE FIELD Environment.Variables.Tokens;
      SET j = 1;

      -- Split by colon manually to preserve system names or labels with colons
      WHILE LENGTH(entry) > 0 DO
        DECLARE pos INT INDEX OF ':' IN entry;
        IF pos > 0 THEN
          SET Environment.Variables.Tokens.Item[j] = TRIM(SUBSTRING(entry FROM 1 FOR pos - 1));
          SET entry = TRIM(SUBSTRING(entry FROM pos + 1));
        ELSE
          SET Environment.Variables.Tokens.Item[j] = TRIM(entry);
          SET entry = '';
        END IF;
        SET j = j + 1;
      END WHILE;

      -- Extract known parts
      SET ip = Environment.Variables.Tokens.Item[1];
      SET port = Environment.Variables.Tokens.Item[2];
      SET system = Environment.Variables.Tokens.Item[3];
      -- Join remaining tokens as label
      SET label = '';
      SET j = 4;
      WHILE Environment.Variables.Tokens.Item[j] IS NOT NULL DO
        SET label = label || ' ' || Environment.Variables.Tokens.Item[j];
        SET j = j + 1;
      END WHILE;

      -- Save result
      CREATE LASTCHILD OF entryListArr TYPE Name NAME 'Entry';
      SET entryListArr.Entry[i].IP = ip;
      SET entryListArr.Entry[i].Port = port;
      SET entryListArr.Entry[i].System = system;
      SET entryListArr.Entry[i].Label = TRIM(label);

      SET i = i + 1;
    END WHILE;

    RETURN TRUE;
  END;
END MODULE;




# Library-Management
Library Management System is a system which maintains the information about the books present in the library, their authors, the members of library to whom books are 
issued and all. This is very difficult to organize manually. Maintenance of all this information manually is a very complex task. Owing to the advancement of technology, 
organization of an Online Library becomes much simple.The maintenance of the records is made efficient, as all the records are stored in the ACCESS database, through 
which data can be retrieved easily. It makes entire process online where student can search books, staff can generate reports and do book transactions.The navigation 
control is provided in all the forms to navigate through the large amount of records. 
The Library Management has been designed to computerize and automate the operations performed over the information about the members, book issues and returns and all 
other operations. This computerization of library helps in many instances of its maintenance. It reduces the workload of management as most of the manual work done is 
reduced.
