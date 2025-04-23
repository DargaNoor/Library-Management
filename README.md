import java.util.*;

public class CacheEntryParser {

    static class CacheEntry {
        String ip;
        String port;
        String system;
        String label;

        public CacheEntry(String ip, String port, String system, String label) {
            this.ip = ip;
            this.port = port;
            this.system = system;
            this.label = label;
        }

        @Override
        public String toString() {
            return "IP: " + ip + ", Port: " + port + ", System: " + system + ", Label: " + label;
        }
    }

    public static List<CacheEntry> parseInput(String input) {
        List<CacheEntry> result = new ArrayList<>();
        String[] parts = input.split("/");

        for (String part : parts) {
            String[] tokens = part.trim().split(":");
            if (tokens.length < 4) continue;

            String ip = tokens[0].trim();
            String port = tokens[1].trim();
            String system = tokens[2].trim();
            String label = String.join(":", Arrays.copyOfRange(tokens, 3, tokens.length)).trim();

            result.add(new CacheEntry(ip, port, system, label));
        }

        return result;
    }

    public static void main(String[] args) {
        String input1 = "10.177.44.27:5003:PAYMENT SYS: Payment S 01/10.177.44.29:5005:PAYMENT_SYS : Payment S 01/10.177.44.27:5003: PAYMENT SYS: Payment S 02/10.177.44.29:5005: PAYMENT SYS: Payment S 02";
        String input2 = "10.177.44.27:5003: PAYMENT SYS: Payment S 03";

        List<CacheEntry> entries1 = parseInput(input1);
        List<CacheEntry> entries2 = parseInput(input2);

        entries1.forEach(System.out::println);
        System.out.println("---");
        entries2.forEach(System.out::println);
    }
}










data '{

"mobile": {

"countryCode": 91,

"value": "9940173757"

},

"entityld": "531115787360000002100225",

"expiryDate": "12/26",

"kit": "360000002",

"newPin": "1234",

"otpDetails": {

"traceNumber": "57369a32-4882-4ad1-aea0-6561b999add3",

"mobileNumber": "9940173757",

"otp": "123456"

}

}'


<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:dp="http://www.datapower.com/extensions"
  extension-element-prefixes="dp">
    <xsl:output omit-xml-declaration="yes" />
    <xsl:template match="/">
        <xsl:variable name="flag1">
            <xsl:value-of select="dp:variable('var://context/Oauth/flag')"/>
        </xsl:variable>
        <xsl:choose>
            <xsl:when test="$flag1 !='N'">
                <xsl:variable name="flag2">
                    <xsl:value-of select="dp:variable('var://context/Oauth/flag')"/>
                </xsl:variable>
                <dp:set-variable name="'var://context/Oauth/refreshToken1'" value="$flag1" />
                <dp:set-local-variable name="refreshToken" value="$flag1" />
            </xsl:when>
            <xsl:otherwise>
                <xsl:variable name="storedRefreshToken">
                    <xsl:value-of  select="dp:variable('var://context/Oauth/refreshToken1')" />
                </xsl:variable>
                <xsl:variable name="users1" >
                    <xsl:value-of select="dp:local-variable('refreshToken')" />
                </xsl:variable>
                <dp:set-variable name="'var://context/Oauth/users'" value="normalize-space($users1)"/>
                <dp:set-variable name="'var://context/Oauth/users1'" value="normalize-space($storedRefreshToken)"/>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>
</xsl:stylesheet>














// Example GatewayScript before AAA
var headers = request.headers;
session.variables.set("var://context/AAA/username", headers['username']);
session.variables.set("var://context/AAA/password", headers['password']);





var crypto = require('crypto');
var username = session.variables.get('var://context/AA



public static String AESGCMEncrypt(String plaintext, String key) throws Exception {
    byte[] keyBytes = key.getBytes("UTF-8");
    SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

    byte[] iv = new byte[12]; // Random 12-byte IV
    SecureRandom random = new SecureRandom();
    random.nextBytes(iv);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec spec = new GCMParameterSpec(128, iv);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

    byte[] cipherText = cipher.doFinal(plaintext.getBytes("UTF-8"));

    // Combine IV + CipherText+Tag
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    outputStream.write(iv);
    outputStream.write(cipherText);

    return Base64.getEncoder().encodeToString(outputStream.toByteArray());
}

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Properties;

public class KeyFetcher {

    static String propertiesPath = "/path/to/your.properties";
    static String jkspath = "/path/to/yourkeystore.jks";

    public static String getPrivateKey() {
        try {
            Properties prop = new Properties();
            prop.load(new FileInputStream(propertiesPath));
            String enpass = prop.getProperty("enpass");
            String aesk = prop.getProperty("aesk");

            String jkspwd = AESGCMDecrypt(enpass, aesk);
            if (jkspwd.contains("X-JavaError")) return jkspwd;

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(jkspath), jkspwd.toCharArray());

            Enumeration<String> es = keyStore.aliases();
            String alias = null;
            while (es.hasMoreElements()) {
                String currentAlias = es.nextElement();
                if (keyStore.isKeyEntry(currentAlias)) {
                    alias = currentAlias;
                    break;
                }
            }

            if (alias == null) return "Alias with private key not found";

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                    keyStore.getEntry(alias, new KeyStore.PasswordProtection(jkspwd.toCharArray()));
            PrivateKey myPrivateKey = pkEntry.getPrivateKey();

            byte[] privatekey = myPrivateKey.getEncoded();
            return Base64.getEncoder().encodeToString(privatekey);

        } catch (Exception e) {
            return "X-JavaError " + e.toString();
        }
    }

    public static String AESGCMDecrypt(String encryptedData, String key) {
        try {
            byte[] decoded = Base64.getDecoder().decode(encryptedData);

            byte[] iv = new byte[12]; // Standard 12-byte IV
            System.arraycopy(decoded, 0, iv, 0, 12);

            byte[] cipherText = new byte[decoded.length - 12];
            System.arraycopy(decoded, 12, cipherText, 0, cipherText.length);

            byte[] keyBytes = key.getBytes("UTF-8");
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128-bit tag
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            byte[] decrypted = cipher.doFinal(cipherText);
            return new String(decrypted, "UTF-8");

        } catch (Exception e) {
            return "X-JavaError " + e.toString();
        }
    }
}
public static String AESGCMEncrypt(String plaintext, String key) throws Exception {
    byte[] keyBytes = key.getBytes("UTF-8");
    SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

    byte[] iv = new byte[12]; // 12-byte IV for GCM
    SecureRandom random = new SecureRandom();
    random.nextBytes(iv);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

    byte[] cipherText = cipher.doFinal(plaintext.getBytes("UTF-8"));

    // Combine IV + CipherText + Tag
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    outputStream.write(iv);
    outputStream.write(cipherText);

    return Base64.getEncoder().encodeToString(outputStream.toByteArray());
}

# Library-Management
Library Management System is a system which maintains the information about the books present in the library, their authors, the members of library to whom books are 
issued and all. This is very difficult to organize manually. Maintenance of all this information manually is a very complex task. Owing to the advancement of technology, 
organization of an Online Library becomes much simple.The maintenance of the records is made efficient, as all the records are stored in the ACCESS database, through 
which data can be retrieved easily. It makes entire process online where student can search books, staff can generate reports and do book transactions.The navigation 
control is provided in all the forms to navigate through the large amount of records. 
The Library Management has been designed to computerize and automate the operations performed over the information about the members, book issues and returns and all 
other operations. This computerization of library helps in many instances of its maintenance. It reduces the workload of management as most of the manual work done is 
reduced.
