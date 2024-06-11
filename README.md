import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class WSSecurityExample {

    public static void main(String[] args) throws Exception {
        // Sample UsernameToken XML
        String usernameTokenXML = "<wsse:UsernameToken wsu:Id=\"UsernameToken-1\">"
                + "<wsse:Username>john_doe</wsse:Username>"
                + "<wsse:Password Type=\"http://docs.oasis-open.org/wss/oasis-wss-username-token-profile-1.1#PasswordText\">password</wsse:Password>"
                + "<wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">nonce-value</wsse:Nonce>"
                + "<wsu:Created>2024-06-11T12:34:56Z</wsu:Created>"
                + "</wsse:UsernameToken>";

        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // AES-128
        SecretKey secretKey = keyGen.generateKey();

        // Generate Initialization Vector (IV)
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Encrypt the UsernameToken XML using AES-128-CBC
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedData = cipher.doFinal(usernameTokenXML.getBytes(StandardCharsets.UTF_8));

        // Encode encrypted data and IV to Base64 for readability
        String encryptedDataBase64 = DatatypeConverter.printBase64Binary(encryptedData);
        String ivBase64 = DatatypeConverter.printBase64Binary(iv);

        // Print the encrypted data and IV
        System.out.println("Encrypted Data (Base64): " + encryptedDataBase64);
        System.out.println("Initialization Vector (Base64): " + ivBase64);

        // Hash the encrypted data using SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(encryptedData);
        String hashBase64 = DatatypeConverter.printBase64Binary(hash);

        // Print the hash of the encrypted data
        System.out.println("SHA-256 Hash (Base64): " + hashBase64);
    }
}


<wsse:UsernameToken wsu:Id="UsernameToken-F2AE1262259606AA8F171698646586339">
    <wsse:Username>john_doe</wsse:Username>
    <wsse:Password Type="http://docs.oasis-open.org/wss/oasis-wss-username-token-profile-1.1#PasswordText">password</wsse:Password>
    <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">nonce-value</wsse:Nonce>
    <wsu:Created>2024-06-11T12:34:56Z</wsu:Created>
</wsse:UsernameToken>

<xenc:EncryptedData Id="ED-F2AE1262259606AA8F171698646588147" Type="http://www.w3.org/2001/04/xmlenc#Content" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <wsse:SecurityTokenReference wsse11:TokenType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey" xmlns:wsse11="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd">
            <wsse:Reference URI="#EK-F2AE1262259606AA8F171698646587045"/>
        </wsse:SecurityTokenReference>
    </ds:KeyInfo>
    <xenc:CipherData>ABCD1234</xenc:CipherData>
</xenc:EncryptedData>

# Library-Management
Library Management System is a system which maintains the information about the books present in the library, their authors, the members of library to whom books are 
issued and all. This is very difficult to organize manually. Maintenance of all this information manually is a very complex task. Owing to the advancement of technology, 
organization of an Online Library becomes much simple.The maintenance of the records is made efficient, as all the records are stored in the ACCESS database, through 
which data can be retrieved easily. It makes entire process online where student can search books, staff can generate reports and do book transactions.The navigation 
control is provided in all the forms to navigate through the large amount of records. 
The Library Management has been designed to computerize and automate the operations performed over the information about the members, book issues and returns and all 
other operations. This computerization of library helps in many instances of its maintenance. It reduces the workload of management as most of the manual work done is 
reduced.
