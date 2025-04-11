// Example GatewayScript before AAA
var headers = request.headers;
session.variables.set("var://context/AAA/username", headers['username']);
session.variables.set("var://context/AAA/password", headers['password']);





var crypto = require('crypto');
var username = session.variables.get('var://context/AAA/username');

// Generate tokens and expiry
var accessToken = crypto.randomBytes(16).toString('hex');
var refreshToken = crypto.randomBytes(16).toString('hex');
var sessionKey = crypto.randomBytes(32).toString('base64');
var accessExpiry = Math.floor(Date.now() / 1000) + 3600;
var refreshExpiry = Math.floor(Date.now() / 1000) + 7200;

// Store in var://service/
session.variables.set('var://service/' + username + '/accessToken', accessToken);
session.variables.set('var://service/' + username + '/refreshToken', refreshToken);
session.variables.set('var://service/' + username + '/sessionKey', sessionKey);
session.variables.set('var://service/' + username + '/accessExpiry', accessExpiry.toString());
session.variables.set('var://service/' + username + '/refreshExpiry', refreshExpiry.toString());

// Create token JSON
var tokenJson = {
  accessToken: accessToken,
  accessExpiry: accessExpiry,
  refreshToken: refreshToken,
  refreshExpiry: refreshExpiry,
  sessionKey: sessionKey
};

// Encrypt tokenJson using client public key (done via Crypto Encrypt action in flow)
// You can pass it to the Crypto Binary Encrypt action or encrypt in script (advanced)

// For now, send plain response (for debug)
session.output.write(JSON.stringify(tokenJson));












var crypto = require('crypto');
var username = session.variables.get('var://context/AAA/username');

var accessToken = crypto.randomBytes(16).toString('hex');
var refreshToken = crypto.randomBytes(16).toString('hex');
var sessionKey = crypto.randomBytes(32).toString('base64');
var accessExpiry = Math.floor(Date.now() / 1000) + 3600;
var refreshExpiry = Math.floor(Date.now() / 1000) + 7200;

var tokenJson = {
  accessToken: accessToken,
  accessExpiry: accessExpiry,
  refreshToken: refreshToken,
  refreshExpiry: refreshExpiry,
  sessionKey: sessionKey
};

var plaintext = JSON.stringify(tokenJson);

// Save it to context to be encrypted by Crypto Binary Encrypt action
session.input.setBody(plaintext);





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
