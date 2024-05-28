<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:dp="http://www.datapower.com/extensions"
                extension-element-prefixes="dp"
                xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    
    <xsl:template match="/">
        <!-- Define the key for AES-128-CBC encryption -->
        <xsl:variable name="encryptionKey" select="'YOUR_BASE64_ENCODED_AES_KEY'" />
        
        <!-- Sample XML content to encrypt -->
        <xsl:variable name="xmlContent">
            <![CDATA[
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" 
                               xmlns:ds="http://www.w3.org/2000/09/xmldsig#" 
                               xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" 
                               xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <SOAP-ENV:Header>
                    <wsse:Security mustUnderstand="1">
                        <wsse:UsernameToken>
                            <wsse:Username>B000200206</wsse:Username>
                        </wsse:UsernameToken>
                        <wsu:Timestamp>
                            <wsu:Created>30</wsu:Created>
                            <wsu:Expires>30</wsu:Expires>
                        </wsu:Timestamp>
                        <ds:Signature>
                            <ds:SignedInfo>
                                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                                <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                            </ds:SignedInfo>
                        </ds:Signature>
                    </wsse:Security>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body/>
            </SOAP-ENV:Envelope>
            ]]>
        </xsl:variable>

        <!-- Encrypt the XML content using AES-128-CBC -->
        <xsl:variable name="encryptedXml">
            <xsl:value-of select="dp:encrypt-data($xmlContent, $encryptionKey, 'http://www.w3.org/2001/04/xmlenc#aes128-cbc')" />
        </xsl:variable>

        <!-- Output the encrypted content -->
        <xsl:output method="xml" indent="yes"/>
        <EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">
            <CipherData>
                <CipherValue>
                    <xsl:value-of select="$encryptedXml" />
                </CipherValue>
            </CipherData>
        </EncryptedData>
    </xsl:template>
</xsl:stylesheet>





ï6,ÌþÕ9¾'’«
public class KeyFinder {
    public static void main(String[] args) {
        String encryptedText = "ÓÒ ĐEO | (QhOV×D?";
        
        for (int key = 0; key < 256; key++) {
            String decryptedText = decryptXOR(encryptedText, key);
            if (isPrintable(decryptedText)) {
                System.out.println("Key: " + key + ", Decrypted Text: " + decryptedText);
            }
        }
    }

    public static String decryptXOR(String input, int key) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            result.append((char)(input.charAt(i) ^ key));
        }
        return result.toString();
    }

    public static boolean isPrintable(String text) {
        for (char c : text.toCharArray()) {
            if (c < 32 || c > 126) {
                return false;
            }
        }
        return true;
    }
}







public class Encryptor {
    public static void main(String[] args) {
        String plainText = "Hello World";
        int key = 7; // Key for XOR encryption
        
        String encryptedText = encryptXOR(plainText, key);
        System.out.println("Encrypted Text: " + encryptedText);
    }

    public static String encryptXOR(String input, int key) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            result.append((char)(input.charAt(i) ^ key));
        }
        return result.toString();
    }
}

public class Decryptor {
    public static void main(String[] args) {
        String encryptedText = ""; // Replace with encrypted text from above
        int key = 7; // Key for decryption
        
        String decryptedText = decryptXOR(encryptedText, key);
        System.out.println("Decrypted Text: " + decryptedText);
    }

    public static String decryptXOR(String input, int key) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            result.append((char)(input.charAt(i) ^ key));
        }
        return result.toString();
    }
}









public class Decryptor {
    public static void main(String[] args) {
        String encryptedText = "Jgnnq Yqtnf";
        int shift = 2; // Shift key for Caesar Cipher decryption
        
        String decryptedText = decryptCaesarCipher(encryptedText, shift);
        System.out.println("Decrypted Text: " + decryptedText);
    }

    public static String decryptCaesarCipher(String input, int shift) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (Character.isLetter(c)) {
                char shiftBase = Character.isUpperCase(c) ? 'A' : 'a';
                c = (char) (shiftBase + (c - shiftBase - shift + 26) % 26);
            }
            result.append(c);
        }
        return result.toString();
    }
}





public class Decryptor {
    public static void main(String[] args) {
        String encryptedText = "Jgnnq\"Yqtnf";
        int key = 2; // Key for decryption
        
        String decryptedText = decryptXOR(encryptedText, key);
        System.out.println("Decrypted Text: " + decryptedText);
    }

    public static String decryptXOR(String input, int key) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            result.append((char)(input.charAt(i) ^ key));
        }
        return result.toString();
    }
}




<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:dp="http://www.datapower.com/extensions"
                extension-element-prefixes="dp"
                version="1.0">
  <xsl:output method="xml" encoding="UTF-8" indent="yes"/>
  
  <!-- Replace these with your actual key and IV values -->
  <xsl:variable name="aes-key" select="'your-base64-encoded-key-here'"/>
  <xsl:variable name="aes-iv" select="'your-base64-encoded-iv-here'"/>
  
  <xsl:template match="/">
    <xsl:variable name="plaintext" select="'B00020020612345678123'"/>
    <xsl:variable name="hashed-data">
      <dp:sha1>
        <xsl:value-of select="$plaintext"/>
      </dp:sha1>
    </xsl:variable>
    
    <xsl:variable name="padded-data" select="concat($hashed-data, '0000000000000000000000000000000000000000')"/>
    
    <xsl:variable name="encrypted-data">
      <dp:encrypt type="aes-cbc" key="$aes-key" iv="$aes-iv" form="base64">
        <xsl:value-of select="$padded-data"/>
      </dp:encrypt>
    </xsl:variable>
    
    <xsl:variable name="cipher-value" select="dp:base64-encode(dp:binary-from-hex($encrypted-data))"/>
    
    <output>
      <cipher-value>
        <xsl:value-of select="$cipher-value"/>
      </cipher-value>
      <length>
        <xsl:value-of select="string-length($cipher-value)"/>
      </length>
    </output>
  </xsl:template>
</xsl:stylesheet>



<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:dp="http://www.datapower.com/extensions"
                extension-element-prefixes="dp">
    <!-- The public key and message would typically be passed in as parameters -->
    <xsl:param name="publicKey">MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq6N78zZ0xlD0kJzyqWQC...</xsl:param>
    <xsl:param name="message">This is a secret message</xsl:param>

    <xsl:template match="/">
        <output>
            <xsl:variable name="messageBase64">
                <xsl:value-of select="dp:base64-encode($message)"/>
            </xsl:variable>
            <xsl:variable name="encryptedMessage">
                <xsl:value-of select="dp:encrypt-key('RSA-OAEP', $publicKey, $messageBase64, 'PEM')"/>
            </xsl:variable>
            <encryptedMessage>
                <xsl:value-of select="$encryptedMessage"/>
            </encryptedMessage>
        </output>
    </xsl:template>
</xsl:stylesheet>




<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:js="http://www.mozilla.org/rhino"
                extension-element-prefixes="js">
    <xsl:template match="/">
        <html>
        <head>
            <title>RSA-OAEP Encryption with JavaScript</title>
            <script type="text/javascript">
                <![CDATA[
                async function encryptMessage(publicKeyPem, message) {
                    const encoder = new TextEncoder();
                    const encodedMessage = encoder.encode(message);
                    
                    const publicKey = await window.crypto.subtle.importKey(
                        "spki",
                        base64ToArrayBuffer(publicKeyPem),
                        {
                            name: "RSA-OAEP",
                            hash: "SHA-256"
                        },
                        true,
                        ["encrypt"]
                    );

                    const encryptedMessage = await window.crypto.subtle.encrypt(
                        {
                            name: "RSA-OAEP"
                        },
                        publicKey,
                        encodedMessage
                    );

                    return arrayBufferToBase64(encryptedMessage);
                }

                function base64ToArrayBuffer(base64) {
                    const binaryString = window.atob(base64);
                    const len = binaryString.length;
                    const bytes = new Uint8Array(len);
                    for (let i = 0; i < len; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                    return bytes.buffer;
                }

                function arrayBufferToBase64(buffer) {
                    let binary = '';
                    const bytes = new Uint8Array(buffer);
                    const len = bytes.byteLength;
                    for (let i = 0; i < len; i++) {
                        binary += String.fromCharCode(bytes[i]);
                    }
                    return window.btoa(binary);
                }

                async function performEncryption() {
                    const publicKeyPem = document.getElementById("publicKey").value;
                    const message = document.getElementById("message").value;
                    const encryptedMessage = await encryptMessage(publicKeyPem, message);
                    document.getElementById("encryptedMessage").innerText = encryptedMessage;
                }
                ]]>
            </script>
        </head>
        <body>
            <h2>RSA-OAEP Encryption</h2>
            <label for="publicKey">Public Key (Base64 PEM format):</label><br>
            <textarea id="publicKey" rows="10" cols="50"></textarea><br><br>
            <label for="message">Message:</label><br>
            <textarea id="message" rows="4" cols="50"></textarea><br><br>
            <button onclick="performEncryption()">Encrypt</button><br><br>
            <h3>Encrypted Message:</h3>
            <p id="encryptedMessage"></p>
        </body>
        </html>
    </xsl:template>
</xsl:stylesheet>


# Library-Management
Library Management System is a system which maintains the information about the books present in the library, their authors, the members of library to whom books are 
issued and all. This is very difficult to organize manually. Maintenance of all this information manually is a very complex task. Owing to the advancement of technology, 
organization of an Online Library becomes much simple.The maintenance of the records is made efficient, as all the records are stored in the ACCESS database, through 
which data can be retrieved easily. It makes entire process online where student can search books, staff can generate reports and do book transactions.The navigation 
control is provided in all the forms to navigate through the large amount of records. 
The Library Management has been designed to computerize and automate the operations performed over the information about the members, book issues and returns and all 
other operations. This computerization of library helps in many instances of its maintenance. It reduces the workload of management as most of the manual work done is 
reduced.


package com.sbi.tcs;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;
import java.util.HashMap;
import java.security.Signature;
import com.ibm.misc.BASE64Decoder;
import com.ibm.misc.BASE64Encoder;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import com.ibm.security.bootstrap.BadPaddingException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import jdk.nashorn.internal.parser.JSONParser;



import java.io.ByteArrayInputStream; 
import java.io.InputStream; 
//import java.security.KeyFactory; 
//import java.security.PublicKey; 
//import java.security.cert.CertificateFactory; 
//import java.security.cert.X509Certificate; 
//import java.security.spec.X509EncodedKeySpec; 
//import javax.crypto.Cipher; 
//import javax.crypto.spec.IvParameterSpec; 
//import javax.crypto.spec.SecretKeySpec; 
//import java.util.Base64; 
import org.bouncycastle.util.io.pem.PemObject; 
import org.bouncycastle.util.io.pem.PemReader;


//import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ibm.misc.BASE64Encoder;

import javax.crypto.Cipher; import javax.crypto.KeyGenerator; import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec; import java.nio.charset.StandardCharsets; import java.security.MessageDigest;
import java.security.SecureRandom; import java.security.Security; import java.util.Arrays;



public class YonoEncryption {

	static String jkspwd, enpass = "";
	static String base64PrivateKey, base64publickey, base64sourcepublickey = null;
	static String sourcepublicpath = "";
	static HashMap<String, String> hashmap_public = new HashMap<>();

	
	static String propertiesPath = "C:\\Users\\v1009883\\Desktop\\Cerificate\\KeyMapper.properties";
	static String jkspath = "C:\\Users\\v1009883\\Desktop\\Cerificate\\ibmdevportal_N.jks";
	static String certPath = "D:\\EVC\\uat_EfilingPublicKey.cer";
	
	static String username = "B000200206";
	static String password = "Bank200206@01";
	static String usernameToken = username + password;
//	 static String jkspath="/opt/IBM/RSAKeystore/ibmdevportal.jks";
//	static String certPath = "/opt/IBM/EndPoint_Public/YONO_PublicKey.cer";
//	static String propertiesPath = "/opt/IBM/PropertyFile/KeyMapper.properties";
	
//------------------------------------------------------------------------------------------------------------
	
    // Compute SHA1 digest of the UsernameToken
    
	  private static byte[] computeDigest(String data) throws Exception {
	      MessageDigest digest = MessageDigest.getInstance("SHA-1");
	      return digest.digest(data.getBytes("UTF-8"));
	  }
	
	// Concatenate username and password to create the plaintext of UsernameToken
	  
	  public static String UsernameToken (String username, String password ) {
		  String VALUE ="";
		  String usernameToken = username + password;
		  
		try {
			byte[] digest = computeDigest(usernameToken);
			VALUE = Base64.getEncoder().encodeToString(digest);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return VALUE;  
	  }

//--------------------------------------------------------------------------------------------------------------
	  
	  
	  private static String createXMLStructure(byte[] digest, byte[] signature) throws Exception {
	      DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
	      DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
	      Document doc = docBuilder.newDocument();

	      // Create Signature element
	      Element signatureElement = doc.createElement("Signature");
	      doc.appendChild(signatureElement);

	      // Create SignatureMethod element
	      Element signatureMethod = doc.createElement("SignatureMethod");
	      signatureMethod.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
	      signatureElement.appendChild(signatureMethod);

	      // Create Reference element
	      Element reference = doc.createElement("Reference");
	      reference.setAttribute("URI", "#UsernameToken");
	      signatureElement.appendChild(reference);

	      // Create DigestMethod element
	      Element digestMethod = doc.createElement("DigestMethod");
	      digestMethod.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1");
	      reference.appendChild(digestMethod);

	      // Create DigestValue element
	      Element digestValue = doc.createElement("DigestValue");
	      digestValue.appendChild(doc.createTextNode(Base64.getEncoder().encodeToString(digest)));
	      reference.appendChild(digestValue);

	      // Create SignatureValue element
	      Element signatureValue = doc.createElement("SignatureValue");
	      signatureValue.appendChild(doc.createTextNode(Base64.getEncoder().encodeToString(signature)));
	      signatureElement.appendChild(signatureValue);

	      // Transform document to string
	      TransformerFactory transformerFactory = TransformerFactory.newInstance();
	      Transformer transformer = transformerFactory.newTransformer();
	      DOMSource source = new DOMSource(doc);
	      StringWriter writer = new StringWriter();
	      StreamResult result = new StreamResult(writer);
	      transformer.transform(source, result);

	      return writer.toString();
	  }

	  private static byte[] signDigest(byte[] digest, PrivateKey privateKey) throws Exception {
	      Signature signature = Signature.getInstance("SHA1withRSA");
	      signature.initSign(privateKey);
	      signature.update(digest);
	      return signature.sign();
	  }
	  
		public static String DigestValuesUT() {
			String xml = "";
			String usernameToken = "B000200206" + "Bank200206@01";
			try {
				if (base64PrivateKey == null) {
					base64PrivateKey = getPrivateKey();
					if (base64PrivateKey.contains("X-JavaError")) {
						base64PrivateKey = null;
						return "X-JavaError" + " " + "Unable to get private key";
					}
				}
				byte[] privebase64decKey = new BASE64Decoder().decodeBuffer(base64PrivateKey);
				PKCS8EncodedKeySpec privspec = new PKCS8EncodedKeySpec(privebase64decKey);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PrivateKey privateKey = keyFactory.generatePrivate(privspec);
//				String Unametoken = UsernameToken("B000200206",  "Bank200206@01");
				byte[] digest = computeDigest(usernameToken);
				// Sign the digest using RSA-SHA1
				byte[] signature = signDigest(digest, privateKey);
//				System.out.println("Signature (Base64): " + Base64.getEncoder().encodeToString(signature));

				// Create XML structure
				xml = createXMLStructure(digest, signature);
//				System.out.println("XML Structure: \n" + xml);
				
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return xml;
		}


//----------------------------------------------------------------------------------------------------------------------
			
		  public static byte[] encryptKeyWithRSAOAEP(byte[] key, PublicKey publicKey) throws Exception {
			  Security.addProvider(new BouncyCastleProvider());
		      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
		      
		      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		      return cipher.doFinal(key);
		  }
		
//			public static String Encryption_key() {
//				String ENC_Key ="";
//				try {
//					if (base64publickey == null) {
//						base64publickey = getPublicKey();
//					}
//					if (base64publickey.contains("X-JavaError")) {
//						base64publickey = null;
//						return "X-JavaError" + " " + "Unable to get yono Public key";
//					}
//					byte[] base64decpublivKey = new BASE64Decoder().decodeBuffer(base64publickey);
//					X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64decpublivKey);
//					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//					PublicKey publicKey = keyFactory.generatePublic(keySpec);
//					System.out.println("Key:"+ publicKey);
//					byte [] Pubkey = getPublicKey_byte();
////					ENC_Key = Pubkey.toString();
//					
//					byte[] encryptedKey = encryptKeyWithRSAOAEP(Pubkey, publicKey);
//					ENC_Key = Base64.getEncoder().encodeToString(encryptedKey);
//					
//				} catch (Exception e) {
//					return "X-JavaError" + " " + e.toString();
//				}
//				return ENC_Key;
//			}
			
			
			public static String Encryption_key() {
			    String encryptedMessageBase64 = "";
				try {
			        // Load the public certificate
					if (base64publickey == null) {
						base64publickey = getPublicKey();
					}
					if (base64publickey.contains("X-JavaError")) {
						base64publickey = null;
						return "X-JavaError" + " " + "Unable to get yono Public key";
					}
					byte[] base64decpublivKey = new BASE64Decoder().decodeBuffer(base64publickey);
					X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64decpublivKey);
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					PublicKey publicKey = keyFactory.generatePublic(keySpec);

			        // Generate a random plaintext message
//			        String plaintext = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhfamuA3VA3M+7TrbcAkQgpe2jZZJNjy6QFGy3HfUB9RZUtwb8awvMa5HTrQ/3/U/XRZs8Kg+i9wuhW7aoHnhv7qF2coyz2ZHOqezrcHzWA8ZLuGNB5W71TdqRw6SklPixHtyM5lH7tJhtaI3HTOUQqYbyNI1+Z/NcEXA938iJcRRhzhb8ypLxe3iZcO0280p0sR73RpLq/LhTKDm05zaTzh0oFHqQ3kb9KJZVgWCeKxrTcnb+1RUKtivPmsLXdm4sOsYhJAzbj7NbltC7GdZaE0WfqNfvNH0VMJXHYganyYVnMHB9cgwDdP2B/n6piXNCY8FrLi1A97EXUxBHEP6KQIDAQAB";

			        // Encrypt the plaintext message
			        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			        byte[] encryptedMessage = cipher.doFinal(plaintext.getBytes());

			        // Print the encrypted message
			         encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedMessage);
			        System.out.println("Encrypted message (Base64): " + encryptedMessageBase64);

			    } catch (Exception e) {
			        e.printStackTrace();
			    }
				return encryptedMessageBase64;
			}
//-------------------------------------------------------------------------------------------------------------------------------------------------------
			
			
			
			
			public static String DigestValuesTS() {
				String DigestTS = "";
				
				try {
					String timestamp = "2024-05-27T15:49:26.299Z";
//					System.out.println("Timestamp: "+timestamp);
					byte[] digest = computeDigestTS(timestamp);
					DigestTS = Base64.getEncoder().encodeToString(digest);
				} catch (Exception e) {
					e.printStackTrace();
				}
				return DigestTS;
			}

		       
		       
			   private static String generateTimestamp() {
			       // Generate a simple timestamp
			       return Long.toString(new Date().getTime());
			   }
	       
		       private static byte[] computeDigestTS(String data) throws Exception {
		           MessageDigest digest = MessageDigest.getInstance("SHA-1");
		           return digest.digest(data.getBytes("UTF-8"));
		       }


//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------
		       
		       
				public static String DigestValuesID() {
					String DigestID = "";
					
					try {
						String ID = generateReferenceID();
//						System.out.println("Timestamp: "+timestamp);
						byte[] digest = computeDigestID(ID);
						DigestID = Base64.getEncoder().encodeToString(digest);
					} catch (Exception e) {
						e.printStackTrace();
					}
					return DigestID;
				}
		       

		       private static String generateReferenceID() {
		           return "id-" + java.util.UUID.randomUUID().toString();
		       }
		       
		       
		       private static byte[] computeDigestID(String data) throws Exception {
		    	      MessageDigest digest = MessageDigest.getInstance("SHA-1");
		    	      return digest.digest(data.getBytes("UTF-8"));
		    	  }
		       
		       
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	       
		       
		      
//		       String username = "B000200206";
//		       String password = "Bank200206@01";
//		       String userToken = username + password;
					public static String UsernameToken1() {
						// Step 1: Hash the input data using SHA-1
						String enc = "";
						try {
							MessageDigest sha1;
							sha1 = MessageDigest.getInstance("SHA-1");
							byte[] hashedData = sha1.digest(usernameToken.getBytes(StandardCharsets.UTF_8));

							// Ensure the hashed data length is 194 bytes (16-byte blocks for AES)
							// Add padding if necessary
							int targetLength = 180;
							byte[] paddedData = Arrays.copyOf(hashedData, targetLength);
							if (hashedData.length < targetLength) {
								Arrays.fill(paddedData, hashedData.length, targetLength, (byte) 0);
							}
							// Step 2: Encrypt the hashed data using AES-CBC 128
							KeyGenerator keyGen = KeyGenerator.getInstance("AES");
							keyGen.init(128);
							SecretKey secretKey = keyGen.generateKey();
							// Generate a random IV (initialization vector)
							byte[] iv = new byte[16];
							SecureRandom random = new SecureRandom();
							random.nextBytes(iv);
							IvParameterSpec ivSpec = new IvParameterSpec(iv);

							Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
							aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

							byte[] encryptedData = aesCipher.doFinal(paddedData);
							
//							Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//							aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
//							byte[] encryptedXmlBytes = aesCipher.doFinal(xmlData.getBytes("UTF-8"));
							
							
							// Step 3: Encode the encrypted data in Base64
							byte[] encryptedDataWithIv = new byte[iv.length + encryptedData.length];
							System.arraycopy(iv, 0, encryptedDataWithIv, 0, iv.length);
							System.arraycopy(encryptedData, 0, encryptedDataWithIv, iv.length, encryptedData.length);
//							System.out.println(encryptedDataWithIv.toString());
							enc = new BASE64Encoder().encode(encryptedDataWithIv).replaceAll("\r\n", "");
//							System.out.println(enc);
							
						} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | javax.crypto.BadPaddingException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						return enc;
						
//		       String base64CipherValue =Base64.encodeBase64String(encryptedDataWithIv);

						// Output the cipher value and its length
//		       System.out.println("Cipher Value: " + base64CipherValue);
//		       System.out.println("Cipher Value Length: " + base64CipherValue.length());
					}
		   
		       
		       
		       
		       
		       
		       
		       
		       
		       
		       
		       
		       
		       

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------		       
		       
	public static String AESEncrypt(String xmlData) {
		if (xmlData.trim().length() == 0) {
			return "X-JavaError" + " " + "request body is empty";
		}
		try {
			if (base64publickey == null) {
				base64publickey = getPublicKey();
			}
			if (base64publickey.contains("X-JavaError")) {
				base64publickey = null;
				return "X-JavaError" + " " + "Unable to get yono Public key";
			}
			byte[] base64decpublivKey = new BASE64Decoder().decodeBuffer(base64publickey);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64decpublivKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(keySpec);
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			SecretKey aesKey = keyGen.generateKey();
			byte[] iv = new byte[16]; // AES block size is 16 bytes
			SecureRandom random = new SecureRandom();
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
			byte[] encryptedXmlBytes = aesCipher.doFinal(xmlData.getBytes("UTF-8"));

			// Encrypt AES key using RSA (public key from the certificate)
			Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
			rsaCipher.init(Cipher.WRAP_MODE, publicKey);
			byte[] encryptedAesKeyBytes = rsaCipher.wrap(aesKey);

			// Base64 encode the encrypted data
			String encryptedXml = Base64.getEncoder().encodeToString(encryptedXmlBytes);
			return encryptedXml;
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
	}

	
	public static String AESDecrypt(String message, String key) {
		if (message.trim().length() == 0) {
			return "X-JavaError" + " " + "request body is empty";
		}
		try {
			byte[] keybyte = key.getBytes("UTF-8");
			byte[] ivkey = Arrays.copyOf(keybyte, 16);
			IvParameterSpec iv = new IvParameterSpec(ivkey);
			byte[] encvalue = new BASE64Decoder().decodeBuffer(message);
			SecretKeySpec seckey = new SecretKeySpec(keybyte, "AES");
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			c.init(2, seckey, iv);
			byte[] decvalue = c.doFinal(encvalue);
			String decryptedvalue = new String(decvalue);
			return decryptedvalue;
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
	}

	public static String getPrivateKey() {
		try {
			jkspwd = getProperty("aesk", propertiesPath);
			enpass = getProperty("enpass", propertiesPath);
			boolean isAliasWithPrivateKey = false;
			KeyStore keyStore = KeyStore.getInstance("JKS");
			jkspwd = AESDecrypt(enpass, jkspwd);
			keyStore.load(new FileInputStream(jkspath), jkspwd.toCharArray());
			Enumeration<String> es = keyStore.aliases();
			String alias = "";
			while (es.hasMoreElements()) {
				alias = (String) es.nextElement();
				if (isAliasWithPrivateKey = keyStore.isKeyEntry(alias)) {
					break;
				}
			}
			if (isAliasWithPrivateKey) {
				KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
						new KeyStore.PasswordProtection(jkspwd.toCharArray()));
				PrivateKey myPrivateKey = pkEntry.getPrivateKey();
				byte[] privateKey = (myPrivateKey.getEncoded());
				base64PrivateKey = DatatypeConverter.printBase64Binary(privateKey);
			}
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
		return base64PrivateKey;
	}

	public static String getPublicKey() {
		try {
			FileInputStream fin = new FileInputStream(certPath);
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
			PublicKey publicKey = certificate.getPublicKey();
			byte[] pk = publicKey.getEncoded();
			base64publickey = DatatypeConverter.printBase64Binary(pk);
			fin.close();
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
		return base64publickey;
	}
	
	
	public static byte[] getPublicKey_byte() throws CertificateException, IOException {
		byte[] pk  ;
//		try {
			FileInputStream fin = new FileInputStream(certPath);
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
			PublicKey publicKey = certificate.getPublicKey();
			 pk = publicKey.getEncoded();
//			base64publickey = DatatypeConverter.printBase64Binary(pk);
			fin.close();
//		} catch (Exception e) {
//			return e.p
//		}
		return pk;
	}

	public static String getProperty(String key, String propertiesPath) {
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader(propertiesPath));
			Properties p = new Properties();
			p.load(reader);
			return p.getProperty(key);
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
	}

	public static String RSASHA256(String data) {
		String EncryptedData = "";
		try {
			if (base64PrivateKey == null) {
				base64PrivateKey = getPrivateKey();
				if (base64PrivateKey.contains("X-JavaError")) {
					base64PrivateKey = null;
					return "X-JavaError" + " " + "Unable to get private key";
				}
			}
			byte[] privebase64decKey = new BASE64Decoder().decodeBuffer(base64PrivateKey);
			PKCS8EncodedKeySpec privspec = new PKCS8EncodedKeySpec(privebase64decKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey pk = keyFactory.generatePrivate(privspec);
			Signature rsa = Signature.getInstance("SHA1withRSA");
			rsa.initSign(pk);
			rsa.update(data.getBytes("UTF-8"));
			byte s[] = rsa.sign();
			EncryptedData = Base64.getEncoder().encodeToString(s);
		}
		catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | SignatureException
				| IOException e) {
			e.printStackTrace();
		}
		return EncryptedData;
	}

	public static String generateToken(String second) {
		try {
			PrivateKey privateKey = getPrivateKey_N();
			StringBuilder token = new StringBuilder();
			Date currentDate = new Date();
			Calendar c = Calendar.getInstance();
			long ms = System.currentTimeMillis();
			c.setTime(currentDate);
			Date currrentDatePlusOne = new Date(ms + Integer.parseInt(second) * 1000);
			token.append(Jwts.builder().signWith(SignatureAlgorithm.RS256, privateKey)
					.setIssuedAt(currentDate).setHeaderParam("alg", "RS256").setHeaderParam("typ", "JWT").setIssuer("eis").compact());
			return token.toString();
		} catch (Exception e) {
			// TODO: handle exception
			return "X-JavaError" + " " + e.toString();
		}
	}
	
	public static PrivateKey getPrivateKey_N() {
		// PrivateKey privateKey = null;
		try {
			jkspwd = getProperty("aesk", propertiesPath);
			enpass = getProperty("enpass", propertiesPath);
			jkspwd = AESDecrypt(enpass, jkspwd);
			boolean isAliasWithPrivateKey = false;
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream(jkspath), jkspwd.toCharArray());
			// iterate over all aliases
			Enumeration<String> es = keyStore.aliases();
			String alias = "";
			while (es.hasMoreElements()) {
				alias = (String) es.nextElement();
				// if alias refers to a private key break at that point
				// as we want to use that certificate
				if (isAliasWithPrivateKey = keyStore.isKeyEntry(alias)) {
					break;
				}
			}
			return (PrivateKey) keyStore.getKey(alias, jkspwd.toCharArray());
//			if (isAliasWithPrivateKey) {
//
//				KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
//						new KeyStore.PasswordProtection(jkspwd.toCharArray()));
//
//				PrivateKey myPrivateKey = pkEntry.getPrivateKey();
//				byte[] privateKey = (myPrivateKey.getEncoded());
//				base64PrivateKey = DatatypeConverter.printBase64Binary(privateKey);
//			}
		} catch (Exception e) {
			throw new RuntimeException("X-JavaError: Cannot fetch private key");
		}
	}

	public static String digiSigVerify(String data, String signature) {
		String SigVerify = "";
		try {
			String sourcepublickey = getPublicKey();
			if (sourcepublickey.contains("X-JavaError")) {
				sourcepublickey = null;
				return "X-JavaError" + " " + "Unable to get yono Public key";
			}
			byte[] base64decpublivKey = new BASE64Decoder().decodeBuffer(sourcepublickey);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64decpublivKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey pubKey = keyFactory.generatePublic(keySpec);
			Signature privateSignature = Signature.getInstance("SHA256withRSA");
			privateSignature.initVerify(pubKey);
			privateSignature.update(data.getBytes("UTF-8"));
			byte[] y = Base64.getUrlDecoder().decode(signature);
			boolean bool = privateSignature.verify(y);
			if (bool) {
				SigVerify = "Signature Verified";
			} else {
				SigVerify = "Signature failed";
			}
			return SigVerify;
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}

	}
	
	public static void main(String[] args) {
		
		
		System.out.println("PUB: "+getPublicKey());
		
		System.out.println("DigestUT: "+ UsernameToken("B000200206","Bank200206@01"));
		
		System.out.println("DigestTS: "+ DigestValuesTS());
		
		System.out.println("DigestID: "+ DigestValuesID());
		
//		System.out.println("Encryption_key: "+ Encryption_key());
		
		System.out.println("UsernameToken: "+ UsernameToken1());

		System.out.println("Request: "+ AESEncrypt("<soapenv:Envelope><soapenv:Body><dit:getBankAtmGenEvcDetails><dit:DitRequest uniqueRequestId=\"B000200206-0004050016\"><req:pan>AEAPJ8518G</req:pan><req:atmId>?</req:atmId><req:atmCardNo>12386899</req:atmCardNo><req:bankAccNum>?</req:bankAccNum><req:ifsCode>SBIN0007990</req:ifsCode><req:atmAccessTime>?</req:atmAccessTime><req:accountName>?</req:accountName><req:accountType>?</req:accountType><req:accountStatus>?</req:accountStatus><req:emailId>?</req:emailId><req:mobileNumber>?</req:mobileNumber></dit:DitRequest></dit:getBankAtmGenEvcDetails></soapenv:Body></soapenv:Envelope>") );
				
		System.out.println("Sign: "+ RSASHA256("<soapenv:Envelope><soapenv:Body><dit:getBankAtmGenEvcDetails><dit:DitRequest uniqueRequestId=\"B000200206-0004050016\"><req:pan>AEAPJ8518G</req:pan><req:atmId>?</req:atmId><req:atmCardNo>12386899</req:atmCardNo><req:bankAccNum>?</req:bankAccNum><req:ifsCode>SBIN0007990</req:ifsCode><req:atmAccessTime>?</req:atmAccessTime><req:accountName>?</req:accountName><req:accountType>?</req:accountType><req:accountStatus>?</req:accountStatus><req:emailId>?</req:emailId><req:mobileNumber>?</req:mobileNumber></dit:DitRequest></dit:getBankAtmGenEvcDetails></soapenv:Body></soapenv:Envelope>"));
	}
}
