import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

public class PidEncryptionUtil {

    public static class EncryptionResult {
        public final String encryptedData;
        public final String hmac;
        public final String skey;

        public EncryptionResult(String encryptedData, String hmac, String skey) {
            this.encryptedData = encryptedData;
            this.hmac = hmac;
            this.skey = skey;
        }
    }

    public static EncryptionResult encryptPidBlock(String pidXml, String uidaiCertPath) throws Exception {
        // 1. Timestamp
        String timestamp = generateTimestamp();

        // 2. Session Key (32 bytes for AES-256)
        byte[] sessionKey = generateSecretKey();

        // 3. IV = last 12 bytes of timestamp
        byte[] iv = getIV(timestamp);

        // 4. AAD = last 16 bytes of timestamp
        byte[] aad = getAAD(timestamp);

        // 5. SHA-256 Hash of PID
        byte[] pidHash = sha256Hash(pidXml);

        // 6. AES/GCM Encrypt PID
        byte[] encryptedPid = encryptAESGCM(pidXml.getBytes(StandardCharsets.UTF_8), sessionKey, iv, aad);

        // 7. AES/GCM Encrypt Hash
        byte[] encryptedHash = encryptAESGCM(pidHash, sessionKey, iv, aad);

        // 8. RSA Encrypt Session Key using UIDAI Public Certificate
        byte[] encryptedSessionKey = encryptRSA(sessionKey, uidaiCertPath);

        // 9. Final API Params
        String encryptedData = Base64.getEncoder().encodeToString((timestamp + new String(encryptedPid, StandardCharsets.ISO_8859_1)).getBytes(StandardCharsets.ISO_8859_1));
        String hmac = Base64.getEncoder().encodeToString(encryptedHash);
        String skey = Base64.getEncoder().encodeToString(encryptedSessionKey);

        return new EncryptionResult(encryptedData, hmac, skey);
    }

    private static String generateTimestamp() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
        return LocalDateTime.now().format(formatter);
    }

    private static byte[] generateSecretKey() {
        byte[] key = new byte[32]; // 256-bit AES
        new SecureRandom().nextBytes(key);
        return key;
    }

    private static byte[] getIV(String timestamp) {
        return timestamp.substring(timestamp.length() - 12).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] getAAD(String timestamp) {
        return timestamp.substring(timestamp.length() - 16).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] sha256Hash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] encryptAESGCM(byte[] data, byte[] key, byte[] iv, byte[] aad) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        cipher.updateAAD(aad);
        return cipher.doFinal(data);
    }

    private static byte[] encryptRSA(byte[] secretKey, String certPath) throws Exception {
        FileInputStream fis = new FileInputStream(certPath);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(fis);
        PublicKey publicKey = cert.getPublicKey();

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return rsaCipher.doFinal(secretKey);
    }
}







String pidXml = "<Pid ts=\"\" ver=\"2.0\"><Pv otp=\"123456\"/></Pid>";
String certPath = "/path/to/uidai-public-cert.cer";

PidEncryptionUtil.EncryptionResult result = PidEncryptionUtil.encryptPidBlock(pidXml, certPath);

System.out.println("EncryptedData: " + result.encryptedData);
System.out.println("Hmac: " + result.hmac);
System.out.println("Skey: " + result.skey);




























-- Serialize Input XML to formatted XML string
DECLARE xmlBlob BLOB;
DECLARE xmlString CHARACTER;

-- Step 1: Re-serialize the parsed XML (which corrects formatting)
SET xmlBlob = ASBITSTREAM(InputRoot.XMLNSC, InputRoot.Properties.Encoding, InputRoot.Properties.CodedCharSetId);

-- Step 2: Convert to CHARACTER string
SET xmlString = CAST(xmlBlob AS CHARACTER CCSID InputRoot.Properties.CodedCharSetId);

-- Step 3: Send it as raw string (optional)
SET OutputRoot.BLOB.BLOB = CAST(xmlString AS BLOB CCSID InputRoot.Properties.CodedCharSetId);
SET OutputRoot.Properties.ContentType = 'text/xml';




-- Copy the parsed XML input to output (forces re-serialization)
SET OutputRoot.XMLNSC = InputRoot.XMLNSC;
SET OutputRoot.Properties.ContentType = 'text/xml';




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
