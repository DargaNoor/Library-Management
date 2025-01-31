{"ReturnCode":200,"ReturnMsg":"Success","Data":{"@odata.context":"https://www.sbimf.com/api/investment-ideas/$metadata#investmentideas(Id,LastModified,PublicationDate,DateCreated,IncludeInSitemap,UrlName,Feature3,Feature1,Feature5,FundIds,ScrollerNote,Feature2,Note,Description,Feature4,Title,ScrollerSubHeading)","value":[{"Id":"6804db79-2048-4882-a67a-782a8d7f8244","LastModified":"2024-06-13T07:04:53Z","PublicationDate":"2022-01-26T10:49:32Z","DateCreated":"2022-01-26T10:49:32Z","IncludeInSitemap":true,"UrlName":"all-weather-investments","Feature3":"Dynamic Asset Allocation","Feature1":"3 Years +","Feature5":null,"FundIds":"41,595","ScrollerNote":null,"Feature2":"Wealth Creation","Note":"<h3>SBI Balanced Advantage Fund</h3>\n<p>SBI Balanced Advantage Fund invests in equity &amp; debt securities based on the market condition. Can act as an ideal choice for those looking for an optimal equity-debt allocation at all times</p>\n<br />\n<br />\n<h3>SBI Multi Asset Allocation Fund&nbsp;</h3>\n<p>SBI Multi Asset Allocation Fund&nbsp; majorly invests in a portfolio of non &ndash; correlated asset classes to lower the volatility through diversification &amp; also to capture the potential upside in equity, debt &amp; gold.</p>","Description":"<p>Let&nbsp; experts do the hard-work, invest in funds that offer dynamic portfolio management solutions. They try to maintain the right mix of&nbsp; asset classes based on macro environments and fund house views.</p>","Feature4":null,"Title":"All Weather Investing","ScrollerSubHeading":"Markets can fluctuate, your peace of mind shouldn't"},{"Id":"f62b92c7-c873-4a66-a4e0-eee9ad56e9e6","LastModified":"2024-10-01T09:53:22Z","PublicationDate":"2021-10-13T15:04:27Z","DateCreated":"2021-10-13T15:04:27Z","IncludeInSitemap":true,"UrlName":"plan-for-your-retirement","Feature3":"Disciplined Investment Approach","Feature1":"5 Years +","Feature5":null,"FundIds":"578,579,580,581","ScrollerNote":"A lock-in period of 5 years","Feature2":"Wealth Creation & Retirement corpus","Note":"Investment amount will be locked in for 5 years or until completion of 65 years of age whichever is earlier. Select a fund of your choice or opt in for Auto-Rebalance and let the experts handle it,","Description":"A one stop solution to meet your retirement planning needs. Choose from 4 different plans based on your life stage and risk preference.","Feature4":null,"Title":"Plan for your retirement","ScrollerSubHeading":"A one stop solution to meet your retirement planning needs"},{"Id":"3ca54123-0ae2-408c-aaab-30f1a816ddde","LastModified":"2024-06-13T07:09:10Z","PublicationDate":"2021-10-13T15:30:30Z","DateCreated":"2021-10-13T15:30:31Z","IncludeInSitemap":true,"UrlName":"Indias-leaders","Feature3":"Stability","Feature1":"5 Years +","Feature5":null,"FundIds":"43,2","ScrollerNote":"","Feature2":"Potential Wealth Creation","Note":"<h3>SBI Bluechip fund </h3>\n<p>SBI Bluechip Fund is a large cap fund, which predominantly invests up to the 100<sup>th</sup>  stock as per market cap. These are well establised companies and relatively less volatile.</p>\n<br />\n<br />\n<h3>SBI Large &amp; Mid Cap Fund</h3>\n<p>SBI Large &amp; Mid Cap fund primarily invests in the 101<sup>st</sup>to the 250<sup>th</sup>&nbsp;stock as per market cap.It is a combination of bluechips &amp; strong emerging companies which have the potential to grow.&nbsp;</p>\n<br />\n<br />\n<br />\n<h6>*1<sup>st</sup> -250<sup>th</sup> company in terms of full market capitalization.</h6>","Description":"Get access to India's most powerful companies in a single go .&nbsp; The curation of funds covers India's top 250* companies! Adding the suggested funds to your portfolio can aid in long term wealth creation.","Feature4":null,"Title":"India's leaders","ScrollerSubHeading":"Invest in India's leading companies"},{"Id":"0229221e-1c4d-4432-932c-afe2d7140f72","LastModified":"2024-06-13T07:05:31Z","PublicationDate":"2021-09-25T11:30:19Z","DateCreated":"2021-09-25T11:30:20Z","IncludeInSitemap":false,"UrlName":"smart-money","Feature3":"Less Volatility","Feature1":"Invest Upto 3 Months","Feature5":null,"FundIds":"19","ScrollerNote":"Instant Redemption Available","Feature2":"Redeem Funds Instantly*","Note":"*SBI Liquid Fund additionally, provides instant redemption upto ?50,000 or 90% of redeemable balance whichever is lower","Description":"An alternative to traditional savings avenues","Feature4":null,"Title":"Smart Save","ScrollerSubHeading":"Potential to earn more than traditional savings instruments"},{"Id":"b24838e2-8f97-44ec-ae36-cf3d4c60a35a","LastModified":"2024-06-13T07:08:46Z","PublicationDate":"2022-01-20T14:20:26Z","DateCreated":"2022-01-20T14:20:30Z","IncludeInSitemap":true,"UrlName":"beginner's-kit","Feature3":"Tax Saving through ELSS","Feature1":"Manage Market Volatility","Feature5":null,"FundIds":"595,3,150","ScrollerNote":"","Feature2":"Potential Wealth Creation","Note":"<h3>SBI Balanced Advantage Fund</h3>\n<p> A balanced fund can help to manage market volatility effectively, it is a dynamic asset allocation fund which invests in equity and debt depending on the current market conditions with the aim  to balance the risk and the reward.</p>\n<br />\n<br />\n<h3>SBI Long Term Equity Fund</h3>\n<p> An ELSS fund, this fund offers the benefit of tax saving with the potential of  wealth creation in a single go.</p>\n<br />\n<br />\n<h3>SBI Savings Fund</h3>\n<p> A money market fund, such funds invest in money market instruments which are perceived to be liquid in nature. This gives your money an opportunity to earn reasonable returns while having the convenience to access it whenever required</p>","Description":"This kit contains funds from 3 categories suitable for majority of first time investors - Balanced Funds, ELSS Funds &amp; Money Market Funds.<br />\n<br />","Feature4":null,"Title":"Beginner's Kit","ScrollerSubHeading":"Funds hand-picked for first time investors"}]}}





import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

public class EncryptionUtility {

    private static final int KeyBitSize = 256;
    private static final int NonceBitSize = 256;
    private static final int MacBitSize = 128;

    // Encryption function with all parameters as strings
    public static String simpleEncrypt(String secretMessage, String keyString, String nonSecretPayloadString) throws Exception {
        if (secretMessage == null || secretMessage.isEmpty())
            throw new IllegalArgumentException("Secret Message Required!");

        byte[] key = keyString.getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretPayload = nonSecretPayloadString != null ? nonSecretPayloadString.getBytes(StandardCharsets.UTF_8) : new byte[0];

        if (key.length != KeyBitSize / 8)
            throw new IllegalArgumentException("Key needs to be " + KeyBitSize + " bit!");

        // Convert secretMessage to bytes
        byte[] plainText = secretMessage.getBytes(StandardCharsets.UTF_8);

        // Generate random nonce
        byte[] nonce = new byte[NonceBitSize / 8];
        new SecureRandom().nextBytes(nonce);

        // Initialize AES-GCM Cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(MacBitSize, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

        // Encrypt the message
        byte[] cipherText = cipher.doFinal(plainText);

        // Assemble the final encrypted message
        ByteArrayOutputStream combinedStream = new ByteArrayOutputStream();
        DataOutputStream binaryWriter = new DataOutputStream(combinedStream);
        binaryWriter.write(nonSecretPayload); // Write non-secret payload
        binaryWriter.write(nonce);           // Write nonce
        binaryWriter.write(cipherText);      // Write cipher text

        // Return Base64 encoded string
        return Base64.getEncoder().encodeToString(combinedStream.toByteArray());
    }

    // Decryption function with all parameters as strings
    public static String simpleDecrypt(String encryptedMessage, String keyString, String nonSecretPayloadLengthString) throws Exception {
        if (encryptedMessage == null || encryptedMessage.isEmpty())
            throw new IllegalArgumentException("Encrypted Message Required!");

        byte[] key = keyString.getBytes(StandardCharsets.UTF_8);
        int nonSecretPayloadLength = Integer.parseInt(nonSecretPayloadLengthString);

        if (key.length != KeyBitSize / 8)
            throw new IllegalArgumentException("Key needs to be " + KeyBitSize + " bit!");

        // Decode Base64 encoded encrypted message
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);

        // Extract non-secret payload, nonce, and cipher text
        byte[] nonSecretPayload = new byte[nonSecretPayloadLength];
        System.arraycopy(encryptedBytes, 0, nonSecretPayload, 0, nonSecretPayloadLength);

        byte[] nonce = new byte[NonceBitSize / 8];
        System.arraycopy(encryptedBytes, nonSecretPayloadLength, nonce, 0, nonce.length);

        byte[] cipherText = new byte[encryptedBytes.length - nonSecretPayloadLength - nonce.length];
        System.arraycopy(encryptedBytes, nonSecretPayloadLength + nonce.length, cipherText, 0, cipherText.length);

        // Initialize AES-GCM Cipher for decryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(MacBitSize, nonce);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

        // Decrypt the cipher text
        byte[] plainText = cipher.doFinal(cipherText);

        // Return decrypted message as a string
        return new String(plainText, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // Example usage with all parameters as strings
            String secretKey = "4B6150645367566B5970337336763979"; // 32-char secret key
            String secretMessage = "Test";
            String nonSecretPayload = ""; // Optional, can be empty

            // Encrypt the message
            String encryptedMessage = simpleEncrypt(secretMessage, secretKey, nonSecretPayload);
            System.out.println("Encrypted Text: " + encryptedMessage);

            // Decrypt the message
            String decryptedMessage = simpleDecrypt(encryptedMessage, secretKey, "0");
            System.out.println("Decrypted Text: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}






//////////////////
package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;




public class EncryptionDec {

    private static final int KeyBitSize = 256;
    private static final int NonceBitSize = 256;
    private static final int MacBitSize = 128;

    public static String simpleEncrypt(String secretMessage, byte[] key, byte[] nonSecretPayload) throws Exception {
        if (secretMessage == null || secretMessage.isEmpty())
            throw new IllegalArgumentException("Secret Message Required!");

        byte[] plainText = secretMessage.getBytes(StandardCharsets.UTF_8);
        byte[] cipherText = simpleEncrypt(plainText, key, nonSecretPayload);

        return Base64.getEncoder().encodeToString(cipherText);
    }
    public static byte[] simpleEncrypt(byte[] secretMessage, byte[] key, byte[] nonSecretPayload) throws Exception {
        //User Error Checks
        if (key == null || key.length != KeyBitSize / 8)
            throw new IllegalArgumentException(String.format("Key needs to be %d bit!", KeyBitSize));

        if (secretMessage == null || secretMessage.length == 0)
            throw new IllegalArgumentException("Secret Message Required!");

        //Non-secret Payload Optional
        nonSecretPayload = nonSecretPayload != null ? nonSecretPayload : new byte[0];

        //Using random nonce large enough not to repeat
        byte[] nonce = new byte[NonceBitSize / 8];
        new SecureRandom().nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(MacBitSize, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

        //Generate Cipher Text With Auth Tag
        byte[] cipherText = cipher.doFinal(secretMessage);

        //Assemble Message
        ByteArrayOutputStream combinedStream = new ByteArrayOutputStream();
        DataOutputStream binaryWriter = new DataOutputStream(combinedStream);
        //Prepend Authenticated Payload
        binaryWriter.write(nonSecretPayload);
        //Prepend Nonce
        binaryWriter.write(nonce);
        //Write Cipher Text
        binaryWriter.write(cipherText);

        return combinedStream.toByteArray();
    }

    public static String  simpleDecrypt(String encryptedMessage, byte[] key, int nonSecretPayloadLength) throws Exception {
        if (encryptedMessage == null || encryptedMessage.isEmpty())
            throw new IllegalArgumentException("Encrypted Message Required!");

        byte[] cipherText = Base64.getDecoder().decode(encryptedMessage);
        byte[] plainText = simpleDecrypt(cipherText, key, nonSecretPayloadLength);
        return plainText == null ? null : new String(plainText, StandardCharsets.UTF_8);
    }


    private static byte[] simpleDecrypt(byte[] encryptedMessage, byte[] key, int nonSecretPayloadLength) throws Exception {
    // User Error Checks
        if (key == null || key.length != KeyBitSize / 8)
            throw new IllegalArgumentException("Key needs to be " + KeyBitSize + " bit!");

        if (encryptedMessage == null || encryptedMessage.length == 0)
            throw new IllegalArgumentException("Encrypted Message Required!");

        try {
        // Grab Payload and Nonce
        byte[] nonSecretPayload = new byte[nonSecretPayloadLength];
        System.arraycopy(encryptedMessage, 0, nonSecretPayload, 0, nonSecretPayloadLength);

        byte[] nonce = new byte[NonceBitSize / 8];
        System.arraycopy(encryptedMessage, nonSecretPayloadLength, nonce, 0, nonce.length);

        byte[] cipherText = new byte[encryptedMessage.length - nonSecretPayloadLength - nonce.length];
        System.arraycopy(encryptedMessage, nonSecretPayloadLength + nonce.length, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(MacBitSize, nonce);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

        // Decrypt Cipher Text
        byte[] plainText = cipher.doFinal(cipherText);

        return plainText;
    } catch (Exception e) {
        // Return null if it doesn't authenticate
        return null;
    }
}


    public static void main(String[] args) {
        // String secretMessage, byte[] key, byte[] nonSecretPayload
        String secretKey = "4B6150645367566B5970337336763979";
        try {

            String EncryptedText = simpleEncrypt("Test", secretKey.getBytes(), null);
			String DecryptedText = simpleDecrypt(value, secretKey.getBytes(), 0);
            System.out.println("\n" + "EncryptedText" + EncryptedText);
            System.out.println("\n" + "DecryptedText" + DecryptedText);
        } catch (Exception e) {
            System.out.println("Error");
        }
    }
}

--------------------------------------
public class Main {
    public static void main(String[] args) throws Exception {
        String clientId = "1000";
        String clientSecret = "your_client_secret";
        String clientKey = "your_client_key";
        String httpMethod = "POST";
        String requestUri = "https://uatdemo.loylty.com/demo";
        String nonce = "ABC123456789";
        long timestamp = 1599378798000L;
        String payload = "{ \"name\":\"Loylty Rewardz\" }";

        // Generate the signature
        String signature = HMACUtility.generateSignature(clientId, httpMethod, requestUri, nonce, timestamp, payload, clientSecret);

        // Prepare Authorization Header
        String authorizationHeader = String.format("sign_auth: %s:%s:%s:%d", clientKey, signature, nonce, timestamp);
        System.out.println("Authorization Header: " + authorizationHeader);

        // Verify the signature
        String httpStatus = "200";
        String responseBody = "{ \"response\":\"Success\" }";
        boolean isValid = HMACVerification.verifySignature(signature, clientId, httpStatus, requestUri, nonce, timestamp, responseBody, clientSecret);
        System.out.println("Is signature valid: " + isValid);
    }
}










import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class HMACUtility {

    public static String generateSignature(String clientId, String httpMethod, String requestUri, String nonce, 
                                           long timestamp, String payload, String clientSecret) throws Exception {
        // Step 1: Hash the request payload
        String hashedPayload = hashSHA256Base64(payload);

        // Step 2: Encode the request URI
        String encodedUri = URLEncoder.encode(requestUri, StandardCharsets.UTF_8.name()).toLowerCase();

        // Step 3: Build the raw HMAC string
        String rawHmacString = String.format("%s|%s|%s|%s|%d|%s",
                clientId, httpMethod, encodedUri, nonce, timestamp, hashedPayload);

        // Step 4: Hash the raw HMAC string with HMAC-SHA256 and client secret
        String signature = hmacSHA256Base64(rawHmacString, clientSecret);

        return signature;
    }

    private static String hashSHA256Base64(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashedBytes);
    }

    private static String hmacSHA256Base64(String data, String secret) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }
}



public class HMACVerification {

    public static boolean verifySignature(String receivedSignature, String clientId, String httpStatus, 
                                          String responseUri, String nonce, long timestamp, 
                                          String responseBody, String clientSecret) throws Exception {
        // Step 1: Hash the response body
        String hashedResponseBody = hashSHA256Base64(responseBody);

        // Step 2: Encode the response URI
        String encodedUri = URLEncoder.encode(responseUri, StandardCharsets.UTF_8.name()).toLowerCase();

        // Step 3: Build the raw HMAC string
        String rawHmacString = String.format("%s|%s|%s|%s|%d|%s",
                clientId, httpStatus, encodedUri, nonce, timestamp, hashedResponseBody);

        // Step 4: Hash the raw HMAC string with HMAC-SHA256 and client secret
        String generatedSignature = hmacSHA256Base64(rawHmacString, clientSecret);

        // Step 5: Compare generated signature with received signature
        return receivedSignature.equals(generatedSignature);
    }

    private static String hashSHA256Base64(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashedBytes);
    }

    private static String hmacSHA256Base64(String data, String secret) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }
}










HMAC Request Signature Generation
The client application needs to follow belowsteps to generate HMAC signature authentication:
1. Client should build a string by combining all the data that will be sent, this string contains the
following parameters (CLIENT ID, HTTP method, encoded request URI, nonce, request time
stamp, SHA256 string representation of the request pay load).
2. Request time stamp is calculated using UNIX time (number of seconds since Jan. 1st, 1970)to
overcome any issues related to a different time zone between client and server.
3. Nonce is an arbitrary string used only once.
4. RequestURI should be encoded using html urlencoder and then lower case.
5. Hash request payload using SHA256 algorithm and encode using base64.
6. Client will hash this large string built in the step 1 using a hash algorithm HMAC-SHA256 and
the CLIENT SECRET assigned to it and then encode using base64, the result for this hash is a
unique signature for this request.
7. The signature needs to be sent in the Authorization header using a custom scheme “sign_auth”.
The data in the Authorization header will contain the CLIENT KEY, Signature, nonce and
Request time stamp separated by colon ‘:’. The format for the Authorization header will be like:
[sign_auth] : [ClientKey:Signature:Nonce:Timestamp].
8. Client send the request as usual along with the data generated in step 7 in the Authorization
header named “sign_auth”.
Sample sudo code steps to generate request hmac signature:
E.g. CLIENT ID: 1000, HTTP Method: POST,Nonce: ABC123456789, Timestamp:1599378798000
Request URI: https://uar.yrl.com/demo
Payload: { “name”:”Loylty Rewardz” }
1. Hash request payload:
hashbody = Base64.Encode(SHA256(“{ “name”:”Loylty Rewardz” }”))
2. Request URI encode:
encodedUri = URLEncoder.encode(https://ua.url.com/demo”).toLower()
3. Build raw hmac string:
rawHmacString = 1000|POST|encodedUri|ABC123456789|1599378798000|hashbody
4. Hash rawHmacString using HMAC-SHA256 algorithm and CLIENT SECRET and then encode using
base64.
signature = Base64.Encode(HMAC-SHA256(rawHmacString, CLIENT_SECRET))
5. Prepare sign_auth value:
sign_auth = CLIENT_KEY:signature:Nonce:Timestamp
Note: In case of GET request or POST request without payload append empty string in place of
hashbody.


HMAC Response Signature Generation
The client application needs to follow below steps to generate HMAC signature authentication:
1. Client should use the same Client Key and Client Secret that was used to generate the request.
2. Client should build a string by combining all the data that is received in response, this string
contains the following parameters (CLIENT ID, HTTP Status, encoded request URI, nonce, request
time stamp, and SHA256 string representation of the response body).
hmac_string = CLIENT ID + “|” + HTTP-Status + "|" + Encoded URL + "|" + Nonce + "|" +
Timestamp + "|" + Base64.encode(SHA256(Response body))
HTTP-Status =200
Request URL = https://ura.col/coldemo
Nonce = ABC123456789(Same nonce value as passed in request)
Timestamp = 1599378798000 (Same timestamp value as passed in request)
SHA256(Response body) =
C6ED656BCA63C0BE27128D54DEC93F9A615D6E06CD1BEDA5574FD33FCD25E90A
hmac_string = 1000|200|
https%3a%2f%2fuatdemo.loylty.com%2fdemo|ABC123456789|1599378798000
|C6ED656BCA63C0BE27128D54DEC93F9A615D6E06CD1BEDA5574FD33FCD25E90A
3. Generate the HMACValue
HMACValue = HMAC-SHA256(hmac_string, Client Secret))
HMACValue = HMAC-SHA256 (1000|200|
https%3a%2f%2fuatdemo.loylty.com%2fdemo|ABC123456789|1599378798000|C6ED656
BCA63C0BE27128D54DEC93F9A615D6E06CD1BEDA5574FD33FCD25E90A)
Signature = Base64.encode(HMACValue)
Signature
=Base64.encode(A79844C1BC90E1E6A615FDFDCE56A3BD8BB344BCE1A75F0C6D1F9A6
9D3252B13)
4. Validate generated Signature with value received in “sign_auth” response Header The
format for the Server Authorization header will be like: [sign_auth:
ClientKey:Signature:Nonce:Timestamp].


public static String generateNonce(int length) {
        // Ensure the minimum length is at least 8
        if (length < 8) {
            throw new IllegalArgumentException("Nonce length must be at least 8");
        }

        // Define the characters to use in the nonce
        String characterSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom random = new SecureRandom();
        StringBuilder nonce = new StringBuilder();

        // Generate random characters
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characterSet.length());
            nonce.append(characterSet.charAt(index));
        }

        return nonce.toString();
    }



private static String bytesToHex(byte[] bytes) {
    StringBuilder hexString = new StringBuilder();
    for (byte b : bytes) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) {
            hexString.append('0');
        }
        hexString.append(hex);
    }
    return hexString.toString();
}




import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.binary.Hex;

public class GenerateSHA256 {

    public static String generateSHA256(String payload) throws NoSuchAlgorithmException {
        // Get the instance of SHA-256 digest
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // Convert payload to bytes and calculate the hash
        byte[] hashBytes = digest.digest(payload.getBytes());

        // Convert the byte array into a hex string
        return Hex.encodeHexString(hashBytes);
    }
}




....
.
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.UUID;

public class HMACSignatureGenerator {

    public static String generateSignature(String clientId, String clientSecret, String method, String uri, String payload) throws Exception {
        // Step 1: Generate current timestamp and nonce
        String timestamp = String.valueOf(System.currentTimeMillis());
        String nonce = UUID.randomUUID().toString();

        // Step 2: Hash the payload (if payload is empty, use an empty string)
        String payloadHash = hashSHA256(payload);

        // Step 3: Create the HMAC string
        String hmacString = String.join("|", clientId, method, uri, timestamp, payloadHash);

        // Step 4: Compute HMAC signature using the client secret
        String signature = computeHMAC(clientSecret, hmacString);

        // Step 5: Build the Authorization header
        return String.format("sign auth:%s:%s:%s:%s", clientId, signature, nonce, timestamp);
    }

    private static String hashSHA256(String data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hashBytes);
    }

    private static String computeHMAC(String secret, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hmacBytes);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String[] args) {
        try {
            String clientId = "1000";
            String clientSecret = "your_client_secret";
            String method = "POST";
            String uri = "https://sso.loylty.com/abc/fffw3242342";
            String payload = "170AE002EFA016D1AB3CC2CF82B4E2B57BE2E7FCE92D4DB1355D25718A039EBC";

            String authorizationHeader = generateSignature(clientId, clientSecret, method, uri, payload);
            System.out.println("Authorization Header: " + authorizationHeader);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}




import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class HmacAuthentication {

    public static void main(String[] args) throws Exception {
        String clientKey = "your-client-key";
        String clientSecret = "your-client-secret";
        String httpMethod = "POST";
        String requestUri = "https://sso.loylty.com/abc/fffw3242342";
        String payloadHash = "170AE002EFA016D1AB3CC2CF82B4E2B57BE2E7FCE92D4DB1355D25718A039EBC";
        long timestamp = System.currentTimeMillis(); // Current time in milliseconds
        String nonce = "randomNonce123"; // Example nonce (ensure it's unique)

        // Step 1: Build the string (hmac_string)
        String hmacString = String.format(
            "%s|%s|%s|%d|%s",
            clientKey, httpMethod, requestUri, timestamp, payloadHash
        );

        // Step 2: Generate the HMAC signature
        String signature = generateHmacSignature(hmacString, clientSecret);

        // Step 3: Build the Authorization header
        String authorizationHeader = String.format(
            "sign auth: %s:%s:%s:%d",
            clientKey, signature, nonce, timestamp
        );

        // Print the Authorization header
        System.out.println("Authorization Header: " + authorizationHeader);
    }

    // Generate HMAC-SHA256 signature
    public static String generateHmacSignature(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmacBytes); // Encode the result in Base64
    }
}









import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HashAndBase64Encode {

    public static String hashAndBase64Encode(String encryptedData) throws NoSuchAlgorithmException {
        // Convert the encrypted data string to bytes
        byte[] dataBytes = encryptedData.getBytes();

        // Create a MessageDigest instance for SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // Perform the hash computation
        byte[] hashedBytes = digest.digest(dataBytes);

        // Encode the hashed bytes using Base64
        String base64EncodedHash = Base64.getEncoder().encodeToString(hashedBytes);

        return base64EncodedHash;
    }

    public static void main(String[] args) {
        try {
            // Example encrypted data
            String encryptedData = "your-encrypted-data";

            // Perform hash and Base64 encoding
            String result = hashAndBase64Encode(encryptedData);

            // Print the result
            System.out.println("Base64 Encoded Hash: " + result);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: SHA-256 algorithm not found.");
            e.printStackTrace();
        }
    }
}









<?xml version="1.0" encoding="UTF-8"?><xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:dfdl="http://www.ogf.org/dfdl/dfdl-1.0/" xmlns:fn="http://www.w3.org/2005/xpath-functions" xmlns:ibmDfdlExtn="http://www.ibm.com/dfdl/extensions" xmlns:ibmSchExtn="http://www.ibm.com/schema/extensions" xmlns:recFixLengthFieldsFmt="http://www.ibm.com/dfdl/RecordFixLengthFieldFormat">

    <xsd:import namespace="http://www.ibm.com/dfdl/RecordFixLengthFieldFormat" schemaLocation="IBMdefined/RecordFixLengthFieldFormat.xsd"/>
    <xsd:annotation>
		<xsd:appinfo source="http://www.ogf.org/dfdl/">
			<dfdl:format encoding="{$dfdl:encoding}" escapeSchemeRef="" occursCountKind="fixed" ref="recFixLengthFieldsFmt:RecordFixLengthFieldsFormat"/>
		</xsd:appinfo>
	</xsd:annotation>

	<xsd:element dfdl:lengthKind="delimited" ibmSchExtn:docRoot="true" name="Response">
		<xsd:complexType>
			<xsd:sequence dfdl:separator="%CR;%LF;%WSP*;" dfdl:separatorSuppressionPolicy="anyEmpty">
				<xsd:element dfdl:initiator="" dfdl:lengthKind="delimited" name="body">
					<xsd:complexType>
						<xsd:sequence>
							<xsd:element dfdl:length="5" ibmDfdlExtn:sampleValue="body_valu1" name="MSGLength" type="xsd:string"/>
                            							<xsd:element dfdl:length="37" name="RESPONSE_META_DATA" type="xsd:string"/>
                            <xsd:element dfdl:length="5" dfdl:textStringJustification="left" dfdl:textStringPadCharacter="%SP;" name="BRANCH_CODE" type="xsd:string"/>
                            <xsd:element dfdl:length="3" name="META_DATA2" type="xsd:string"/>
                            <xsd:element dfdl:length="7" dfdl:textStringJustification="left" dfdl:textStringPadCharacter="%SP;" name="RESPONSE_TELLER_ID" type="xsd:string"/>
                            <xsd:element dfdl:length="6" name="TRAN_CODE" type="xsd:string"/>
                            <xsd:element dfdl:length="9" name="JOURNAL_NUMBER" type="xsd:string"/>
                            <xsd:element dfdl:length="53" name="META_DATA4" type="xsd:string"/>
                            <xsd:element dfdl:length="8" ibmDfdlExtn:sampleValue="" name="FEJNO" type="xsd:string"/>
							<xsd:element dfdl:length="2" ibmDfdlExtn:sampleValue="body_valu3" name="RESPONSE_STATUS" type="xsd:string"/>
                            						<xsd:choice>
                <xsd:sequence>
                  <xsd:annotation>
                    <xsd:appinfo source="http://www.ogf.org/dfdl/">
                      <dfdl:discriminator>{/Response/body/RESPONSE_STATUS eq '03' or /Response/body/RESPONSE_STATUS eq '04' or /Response/body/RESPONSE_STATUS eq '08' or /Response/body/RESPONSE_STATUS eq '55'}</dfdl:discriminator>
                    </xsd:appinfo>
                  </xsd:annotation>
                  <xsd:element dfdl:length="60" dfdl:textStringJustification="center" name="NAME" type="xsd:string"/>
                  <xsd:element dfdl:length="40" dfdl:textStringJustification="center" name="ADDRESS_1" type="xsd:string"/>
                  <xsd:element dfdl:length="40" dfdl:textStringJustification="center" name="ADDRESS_2" type="xsd:string"/>
                  <xsd:element dfdl:length="40" dfdl:textStringJustification="center" name="ADDRESS_3" type="xsd:string"/>
                  <xsd:element dfdl:length="40" dfdl:textStringJustification="center" name="ADDRESS_4" type="xsd:string"/>
                  <xsd:element dfdl:length="17" dfdl:textStringJustification="center" name="ACCOUNT_NUMBER" type="xsd:string"/>
                  <xsd:element dfdl:length="25" dfdl:textStringJustification="center" name="PRODUCT_DESCRIPTION" type="xsd:string"/>
                  <xsd:element dfdl:length="24" dfdl:textStringJustification="center" name="APPROVED_AMOUNT" type="xsd:string"/>
                  <xsd:element dfdl:length="24" dfdl:textStringJustification="center" name="Metadata" type="xsd:string"/>
                  <xsd:element dfdl:length="24" dfdl:textStringJustification="center" name="OUTSTANDING_BALANCE" type="xsd:string"/>
                                                                                                                                                                                                                            <xsd:choice>
                    <xsd:sequence>
                      <xsd:annotation>
                        <xsd:appinfo source="http://www.ogf.org/dfdl/">
                          <dfdl:discriminator>{/Response/body/COLLECTION/HeaderLength eq ' 0185'}</dfdl:discriminator>
                        </xsd:appinfo>
                      </xsd:annotation>
                      <xsd:element dfdl:lengthKind="implicit" dfdl:occursCountKind="implicit" maxOccurs="354" name="COLLECTION">
                        <xsd:complexType>
                          <xsd:sequence>
                            <xsd:element dfdl:length="5" dfdl:textStringJustification="left" name="HeaderLength" type="xsd:string"/>
                            <xsd:element dfdl:length="130" name="Header" type="xsd:string"/>
                            <xsd:element dfdl:length="3" dfdl:textStringJustification="center" dfdl:textStringPadCharacter="%SP;" name="Sl_No" type="xsd:string"/>
                            <xsd:element dfdl:length="8" dfdl:textStringJustification="right" name="DUE_DATE" type="xsd:string"/>
                            <xsd:element dfdl:length="16" dfdl:textStringJustification="center" name="PRINCIPAL_DUE" type="xsd:string"/>
                            <xsd:element dfdl:length="12" dfdl:textStringJustification="center" name="PROJECT_INTEREST" type="xsd:string"/>
                            <xsd:element dfdl:length="16" dfdl:textStringJustification="center" name="TOTAL_REPAYMENT" type="xsd:string"/>
                          </xsd:sequence>
                        </xsd:complexType>
                      </xsd:element>
                      <xsd:choice>
                        <xsd:sequence>
                          <xsd:annotation>
                            <xsd:appinfo source="http://www.ogf.org/dfdl/">
                              <dfdl:discriminator>{/Response/body/HeaderLength eq ' 1113'}</dfdl:discriminator>
                            </xsd:appinfo>
                          </xsd:annotation>
                          <xsd:element dfdl:length="5" name="HeaderLength" type="xsd:string"/>
                          <xsd:element dfdl:length="130" dfdl:textStringJustification="center" name="Header" type="xsd:string"/>
                          <xsd:element dfdl:length="24" dfdl:textStringJustification="center" name="TOTAL_OVERALL_1" type="xsd:string"/>
                          <xsd:element dfdl:length="23" dfdl:textStringJustification="center" name="TOTAL_OVERALL_2" type="xsd:string"/>
                          <xsd:element dfdl:length="24" dfdl:textStringJustification="center" name="TOTAL_OVERALL_3" type="xsd:string"/>
                          <xsd:element dfdl:length="912" dfdl:textStringJustification="center" name="META_DATA" type="xsd:string"/>
                        </xsd:sequence>
                      </xsd:choice>
                    </xsd:sequence>
                  </xsd:choice>
                                </xsd:sequence>
                <xsd:sequence>
                  <xsd:annotation>
                    <xsd:appinfo source="http://www.ogf.org/dfdl/">
                      <dfdl:discriminator>{/Response/body/MSGLength eq ' 0941'}</dfdl:discriminator>
                    </xsd:appinfo>
                  </xsd:annotation>
                  <xsd:element dfdl:length="4" dfdl:textStringJustification="center" name="errorResponseMetadata1" type="xsd:string"/>
                  <xsd:element dfdl:length="4" dfdl:textStringJustification="center" name="responseCode" type="xsd:string"/>
                  <xsd:element dfdl:length="4" dfdl:textStringJustification="center" name="errorResponseMetadata2" type="xsd:string"/>
                  <xsd:element dfdl:length="100" dfdl:textStringJustification="center" name="responseDescription" type="xsd:string"/>
                  <xsd:element dfdl:length="699" dfdl:textStringJustification="center" name="errorResponseMetadata3" type="xsd:string"/>
                </xsd:sequence>
                <xsd:sequence>
                  <xsd:annotation>
                    <xsd:appinfo source="http://www.ogf.org/dfdl/">
                      <dfdl:discriminator>{/Response/body/MSGLength eq ' 0179'}</dfdl:discriminator>
                    </xsd:appinfo>
                  </xsd:annotation>
                  <xsd:element dfdl:length="4" dfdl:textStringJustification="center" name="errorResponseMetadata4" type="xsd:string"/>
                  <xsd:element dfdl:length="4" dfdl:textStringJustification="center" name="responseCode" type="xsd:string"/>
                  <xsd:element dfdl:length="4" dfdl:textStringJustification="center" name="errorResponseMetadata5" type="xsd:string"/>
                  <xsd:element dfdl:length="37" dfdl:textStringJustification="center" name="responseDescription" type="xsd:string"/>
                </xsd:sequence>
                <xsd:sequence>
                  <xsd:annotation>
                    <xsd:appinfo source="http://www.ogf.org/dfdl/">
                      <dfdl:discriminator>{/Response/body/MSGLength eq ' 0165'}</dfdl:discriminator>
                    </xsd:appinfo>
                  </xsd:annotation>
                  <xsd:element dfdl:length="4" dfdl:textStringJustification="center" name="errorResponseMetadata6" type="xsd:string"/>
                  <xsd:element dfdl:length="4" dfdl:textStringJustification="center" name="responseCode" type="xsd:string"/>
                  <xsd:element dfdl:length="4" dfdl:textStringJustification="center" name="errorResponseMetadata7" type="xsd:string"/>
                  <xsd:element dfdl:length="23" dfdl:textStringJustification="center" name="responseDescription" type="xsd:string"/>
                </xsd:sequence>
                <xsd:sequence>
                  <xsd:annotation>
                    <xsd:appinfo source="http://www.ogf.org/dfdl/">
                      <dfdl:discriminator>{/Response/body/MSGLength eq ' 0174'}</dfdl:discriminator>
                    </xsd:appinfo>
                  </xsd:annotation>
                  <xsd:element dfdl:length="4" name="errorResponseMetadata8" type="xsd:string"/>
                  <xsd:element dfdl:length="4" dfdl:textStringJustification="center" name="responseCode" type="xsd:string"/>
                  <xsd:element dfdl:length="4" dfdl:textStringJustification="center" name="errorResponseMetadata9" type="xsd:string"/>
                  <xsd:element dfdl:length="32" dfdl:textStringJustification="center" name="responseDescription" type="xsd:string"/>
                </xsd:sequence>
              </xsd:choice>
                        </xsd:sequence>
					</xsd:complexType>
				</xsd:element>
                			            </xsd:sequence>
		</xsd:complexType>
	</xsd:element>


</xsd:schema>



" 0464    0334            00000000000437003000360021916939007031033102537000045990400E!$00000000        00000000000000000000000647099703Ms. SINGH PARAM JEET                                        AIR INDIA SATS AIRPOT SERVICES SERVICES Bhadarpur border                        DELHI                                   South West - 110047                     00000030095765115EB-RLMS-HL-MAXGAIN                 25,00,000.00  000000000000000000000000                  0.00   0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030010201202600000000015633000000000000000000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030020202202600000000004144000000000197770000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030030203202600000000002412000000000180450000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030040204202600000000004364000000000199970000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030050205202600000000003753000000000193860000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030060206202600000000004429000000000200620000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030070207202600000000003816000000000194490000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030080208202600000000004495000000000201280000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030090209202600000000004531000000000201640000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030100210202600000000003916000000000195490000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030110211202600000000004599000000000202320000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030120212202600000000003982000000000196150000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030130201202700000000004668000000000203010000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030140202202700000000004705000000000203380000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030150203202700000000002772000000000184050000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030160204202700000000004765000000000203980000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030170205202700000000004144000000000197770000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030180206202700000000004837000000000204700000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030190207202700000000004214000000000198470000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030200208202700000000004909000000000205420000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030210209202700000000004949000000000205820000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030220210202700000000004324000000000199570000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030230211202700000000005023000000000206560000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030240212202700000000004396000000000200290000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030250201202800000000005099000000000207320000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030260202202800000000005140000000000207730000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030270203202800000000003839000000000194720000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030280204202800000000005212000000000208450000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030290205202800000000004580000000000202130000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030300206202800000000005290000000000209230000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030310207202800000000004657000000000202900000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030320208202800000000005370000000000210030000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030330209202800000000005413000000000210460000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030340210202800000000004777000000000204100000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030350211202800000000005495000000000211280000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030360212202800000000004856000000000204890000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030370201202900000000005578000000000212110000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030380202202900000000005623000000000212560000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030390203202900000000003607000000000192400000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030400204202900000000005697000000000213300000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030410205202900000000005053000000000206860000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030420206202900000000005783000000000214160000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030430207202900000000005138000000000207710000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030440208202900000000005871000000000215040000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030450209202900000000005918000000000215510000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030460210202900000000005269000000000209020000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030470211202900000000006008000000000216410000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030480212202900000000005357000000000209900000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030490201203000000000006099000000000217320000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030500202203000000000006148000000000217810000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030510203203000000000004085000000000197180000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030520204203000000000006230000000000218630000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030530205203000000000005574000000000212070000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030540206203000000000006325000000000219580000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030550207203000000000005666000000000212990000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030560208203000000000006421000000000220540000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030570209203000000000006473000000000221060000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030580210203000000000005810000000000214430000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030590211203000000000006571000000000222040000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030600212203000000000005906000000000215390000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030610201203100000000006671000000000223040000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030620202203100000000006725000000000223580000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030630203203100000000004611000000000202440000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030640204203100000000006816000000000224490000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030650205203100000000006145000000000217780000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030660206203100000000006920000000000225530000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030670207203100000000006246000000000218790000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030680208203100000000007026000000000226590000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030690209203100000000007082000000000227150000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030700210203100000000006404000000000220370000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030710211203100000000007190000000000228230000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030720212203100000000006510000000000221430000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030730201203200000000007300000000000229330000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030740202203200000000007359000000000229920000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030750203203200000000005931000000000215640000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030760204203200000000007466000000000230990000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030770205203200000000006779000000000224120000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030780206203200000000007580000000000232130000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030790207203200000000006890000000000225230000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030800208203200000000007696000000000233290000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030810209203200000000007758000000000233910000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030820210203200000000007064000000000226970000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030830211203200000000007877000000000235100000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030840212203200000000007180000000000228130000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030850201203300000000007998000000000236310000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030860202203300000000008062000000000236950000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030870203203300000000005828000000000214610000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030880204203300000000008173000000000238060000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030890205203300000000007469000000000231020000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030900206203300000000008299000000000239320000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030910207203300000000007591000000000232240000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030920208203300000000008426000000000240590000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030930209203300000000008494000000000241270000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030940210203300000000007782000000000234150000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030950211203300000000008625000000000242580000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030960212203300000000007909000000000235420000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030970201203400000000008757000000000243900000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030980202203400000000008828000000000244610000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997030990203203400000000006525000000000221580000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031000204203400000000008951000000000245840000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031010205203400000000008227000000000238600000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031020206203400000000009089000000000247220000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031030207203400000000008362000000000239950000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031040208203400000000009229000000000248620000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031050209203400000000009303000000000249360000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031060210203400000000008571000000000242040000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031070211203400000000009446000000000250790000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031080212203400000000008711000000000243440000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031090201203500000000009592000000000252250000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031100202203500000000009669000000000253020000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031110203203500000000007291000000000229240000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031120204203500000000009805000000000254380000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031130205203500000000009061000000000246940000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031140206203500000000009957000000000255900000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031150207203500000000009209000000000248420000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031160208203500000000010110000000000257430000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031170209203500000000010191000000000258240000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031180210203500000000009438000000000250710000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031190211203500000000010349000000000259820000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031200212203500000000009591000000000252240000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031210201203600000000010509000000000261420000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031220202203600000000010593000000000262260000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031230203203600000000008981000000000246140000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031240204203600000000010751000000000263840000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031250205203600000000009983000000000256160000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031260206203600000000010917000000000265500000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031270207203600000000010145000000000257780000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031280208203600000000011086000000000267190000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031290209203600000000011175000000000268080000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031300210203600000000010397000000000260300000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031310211203600000000011348000000000269810000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031320212203600000000010566000000000261990000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031330201203700000000011524000000000271570000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031340202203700000000011616000000000272490000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031350203203700000000009064000000000246970000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031360204203700000000011782000000000274150000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031370205203700000000010990000000000266230000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031380206203700000000011965000000000275980000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031390207203700000000011168000000000268010000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031400208203700000000012151000000000277840000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031410209203700000000012248000000000278810000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031420210203700000000011444000000000270770000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031430211203700000000012439000000000280720000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031440212203700000000011630000000000272630000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031450201203800000000012632000000000282650000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031460202203800000000012733000000000283660000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031470203203800000000010081000000000257140000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031480204203800000000012916000000000285490000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031490205203800000000012096000000000277290000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031500206203800000000013117000000000287500000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031510207203800000000012292000000000279250000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031520208203800000000013321000000000289540000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031530209203800000000013428000000000290610000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031540210203800000000012595000000000282280000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031550211203800000000013637000000000292700000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031560212203800000000012799000000000284320000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031570201203900000000013849000000000294820000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031580202203900000000013960000000000295930000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031590203203900000000011198000000000268310000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031600204203900000000014162000000000297950000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031610205203900000000013311000000000289440000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031620206203900000000014382000000000300150000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031630207203900000000013526000000000291590000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031640208203900000000014606000000000302390000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031650209203900000000014724000000000303570000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031660210203900000000013859000000000294920000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031670211203900000000014953000000000305860000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031680212203900000000014083000000000297160000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031690201204000000000015186000000000308190000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031700202204000000000015308000000000309410000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031710203204000000000013427000000000290600000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031720204204000000000015539000000000311720000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031730205204000000000014654000000000302870000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031740206204000000000015781000000000314140000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031750207204000000000014890000000000305230000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031760208204000000000016027000000000316600000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031770209204000000000016156000000000317890000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031780210204000000000015256000000000308890000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031790211204000000000016408000000000320410000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031800212204000000000015502000000000311350000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031810201204100000000016664000000000322970000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031820202204100000000016798000000000324310000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031830203204100000000013781000000000294140000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031840204204100000000017043000000000326760000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031850205204100000000016122000000000317550000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031860206204100000000017309000000000329420000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031870207204100000000016381000000000320140000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031880208204100000000017580000000000332130000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031890209204100000000017721000000000333540000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031900210204100000000016783000000000324160000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031910211204100000000017998000000000336310000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031920212204100000000017053000000000326860000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031930201204200000000018279000000000339120000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031940202204200000000018426000000000340590000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031950203204200000000015264000000000308970000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031960204204200000000018696000000000343290000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031970205204200000000017734000000000333670000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031980206204200000000018989000000000346220000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997031990207204200000000018019000000000336520000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032000208204200000000019286000000000349190000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032010209204200000000019440000000000350730000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032020210204200000000018460000000000340930000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032030211204200000000019745000000000353780000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032040212204200000000018757000000000343900000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032050201204300000000020054000000000356870000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032060202204300000000020215000000000358480000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032070203204300000000016892000000000325250000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032080204204300000000020512000000000361450000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032090205204300000000019506000000000351390000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032100206204300000000020834000000000364670000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032110207204300000000019819000000000354520000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032120208204300000000021160000000000367930000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032130209204300000000021330000000000369630000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032140210204300000000020303000000000359360000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032150211204300000000021664000000000372970000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032160212204300000000020629000000000362620000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032170201204400000000022003000000000376360000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032180202204400000000022180000000000378130000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032190203204400000000019907000000000355400000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032200204204400000000022518000000000381510000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032210205204400000000021462000000000370950000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032220206204400000000022871000000000385040000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032230207204400000000021806000000000374390000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032240208204400000000023229000000000388620000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032250209204400000000023416000000000390490000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032260210204400000000022338000000000379710000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032270211204400000000023783000000000394160000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032280212204400000000022696000000000383290000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032290201204500000000024156000000000397890000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032300202204500000000024350000000000399830000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032310203204500000000020657000000000362900000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032320204204500000000024711000000000403440000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032330205204500000000023602000000000392350000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032340206204500000000025099000000000407320000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032350207204500000000023980000000000396130000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032360208204500000000025493000000000411260000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032370209204500000000025697000000000413300000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032380210204500000000024564000000000401970000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032390211204500000000026101000000000417340000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032400212204500000000024957000000000405900000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032410201204600000000026510000000000421430000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032420202204600000000026723000000000423560000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032430203204600000000022818000000000384510000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032440204204600000000027121000000000427540000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032450205204600000000025952000000000415850000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032460206204600000000027547000000000431800000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032470207204600000000026368000000000420010000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032480208204600000000027980000000000436130000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032490209204600000000028204000000000438370000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032500210204600000000027009000000000426420000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032510211204600000000028647000000000442800000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032520212204600000000027442000000000430750000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032530201204700000000029097000000000447300000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032540202204700000000029331000000000449640000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032550203204700000000025193000000000408260000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032560204204700000000029769000000000454020000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032570205204700000000028535000000000441680000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032580206204700000000030237000000000458700000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032590207204700000000028992000000000446250000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032600208204700000000030712000000000463450000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032610209204700000000030958000000000465910000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032620210204700000000029696000000000453290000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032630211204700000000031445000000000470780000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032640212204700000000030171000000000458040000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032650201204800000000031940000000000475730000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032660202204800000000032196000000000478290000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032670203204800000000029352000000000449850000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032680204204800000000032690000000000483230000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032690205204800000000031385000000000470180000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032700206204800000000033204000000000488370000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032710207204800000000031887000000000475200000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032720208204800000000033727000000000493600000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032730209204800000000033997000000000496300000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032740210204800000000032661000000000482940000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032750211204800000000034532000000000501650000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032760212204800000000033183000000000488160000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032770201204900000000035076000000000507090000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032780202204900000000035357000000000509900000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032790203204900000000030680000000000463130000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032800204204900000000035887000000000515200000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032810205204900000000034504000000000501370000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032820206204900000000036452000000000520850000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032830207204900000000035056000000000506890000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032840208204900000000037026000000000526590000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032850209204900000000037324000000000529570000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032860210204900000000035905000000000515380000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032870211204900000000037911000000000535440000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032880212204900000000036479000000000521120000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032890201205000000000038508000000000541410000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032900202205000000000038817000000000544500000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032910203205000000000033830000000000494630000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032920204205000000000039400000000000550330000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032930205205000000000037931000000000535640000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032940206205000000000040021000000000556540000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032950207205000000000038537000000000541700000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032960208205000000000040652000000000562850000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032970209205000000000040978000000000566110000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032980210205000000000039470000000000551030000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997032990211205000000000041624000000000572570000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033000212205000000000040100000000000557330000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033010201205100000000042279000000000579120000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033020202205100000000042619000000000582520000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033030203205100000000037291000000000529240000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033040204205100000000043260000000000588930000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033050205205100000000041697000000000573300000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033060206205100000000043942000000000595750000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033070207205100000000042362000000000579950000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033080208205100000000044635000000000602680000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033090209205100000000044993000000000606260000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033100210205100000000043387000000000590200000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033110211205100000000045702000000000613350000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033120212205100000000044079000000000597120000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033130201205200000000046423000000000620560000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033140202205200000000046795000000000624280000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033150203205200000000043119000000000587520000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033160204205200000000047517000000000631500000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033170205205200000000045849000000000614820000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033180206205200000000048267000000000639000000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033190207205200000000046580000000000622130000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033200208205200000000049028000000000646610000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033210209205200000000049421000000000650540000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033220210205200000000047707000000000633400000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033230211205200000000050201000000000658340000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033240212205200000000048467000000000641000000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033250201205300000000050993000000000666260000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033260202205300000000051402000000000670350000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033270203205300000000045288000000000609210000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033280204205300000000052178000000000678110000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033290205205300000000050396000000000660290000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033300206205300000000053001000000000686340000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033310207205300000000051199000000000668320000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033320208205300000000053838000000000694710000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033330209205300000000054270000000000699030000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033340210205300000000052436000000000680690000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033350211205300000000055126000000000707590000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033360212205300000000053272000000000689050000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033370201205400000000055996000000000716290000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033380202205400000000056446000000000720790000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033390203205400000000049880000000000655130000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033400204205400000000057299000000000729320000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033410205205400000000055391000000000710240000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033420206205400000000058203000000000738360000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033430207205400000000056274000000000719070000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033440208205400000000059122000000000747550000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033450209205400000000059597000000000752300000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033460210205400000000057633000000000732660000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033470211205400000000060538000000000761710000000000015633 0185    0055            00000000000437003000360021916939007031033102537000045990000E!$00000000        000000000000000000000006470997033482312205400000009550418000000001314960000000009681914 1113    0983            00000000000437003000360021916939007031033102537000045990600E!$00000000        00000000000000000000000647099703        1,66,32,102.00         1,26,06,565.00          1,51,06,565.00                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  "


import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AesGcmDecryption {

    public static String AESDecrypt_GCM(String message, String key) {
        try {
            // Validate input
            if (message == null || message.trim().isEmpty()) {
                return "JavaDecryptionError: Request body is empty";
            }

            // Convert key to byte array
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);

            // Ensure key length is valid for AES (16 bytes for AES-128)
            if (keyBytes.length != 16) {
                throw new IllegalArgumentException("Key must be 16 bytes (128 bits)");
            }

            // Decode the Base64 input message
            byte[] combined = Base64.getDecoder().decode(message);

            // Extract IV (12 bytes), Ciphertext, and Tag (last 16 bytes)
            byte[] iv = new byte[12];
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[combined.length - iv.length - tag.length];

            System.arraycopy(combined, 0, iv, 0, iv.length);
            System.arraycopy(combined, combined.length - tag.length, tag, 0, tag.length);
            System.arraycopy(combined, iv.length, ciphertext, 0, ciphertext.length);

            // Initialize Cipher for AES-GCM
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv); // 128-bit authentication tag
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

            // Combine ciphertext and tag for decryption
            byte[] decryptedBytes = cipher.doFinal(ciphertext);

            // Convert decrypted bytes to string
            return new String(decryptedBytes, StandardCharsets.UTF_8);

        } catch (Exception e) {
            return "JavaDecryptionError: " + e.toString();
        }
    }

    public static void main(String[] args) {
        String encryptedMessage = "YourBase64EncryptedMessageHere";
        String key = "1234567890123456"; // 16-byte key

        String decryptedMessage = AESDecrypt_GCM(encryptedMessage, key);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}







..

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AesGcmEncryption {

    public static String AESEncrypt_GCM(String message, String key) {
        try {
            // Convert key to byte array
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
            
            // Ensure key length is valid for AES (16 bytes for AES-128)
            if (keyBytes.length != 16) {
                throw new IllegalArgumentException("Key must be 16 bytes (128 bits)");
            }

            // Generate Initialization Vector (IV) - 12 bytes for AES-GCM
            byte[] iv = new byte[12];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);

            // Create AES SecretKeySpec
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

            // Initialize Cipher for AES-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv); // 128-bit authentication tag
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

            // Encrypt the message
            byte[] plaintextBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertextBytes = cipher.doFinal(plaintextBytes);

            // Combine IV, Ciphertext, and Authentication Tag
            byte[] combined = new byte[iv.length + ciphertextBytes.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertextBytes, 0, combined, iv.length, ciphertextBytes.length);

            // Encode result to Base64 for easy transport/storage
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            return "JavaEncryptionError: " + e.toString();
        }
    }

    public static void main(String[] args) {
        String message = "YourMessageHere";
        String key = "1234567890123456"; // 16-byte key

        String encryptedMessage = AESEncrypt_GCM(message, key);
        System.out.println("Encrypted Message: " + encryptedMessage);
    }
}


import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AesGcmDecryption {

    public static String AESDecrypt_GCM(String message, String key) {
        try {
            // Validate input
            if (message == null || message.trim().isEmpty()) {
                return "JavaDecryptionError: Request body is empty";
            }

            // Convert key to byte array
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);

            // Ensure key length is valid for AES (16 bytes for AES-128)
            if (keyBytes.length != 16) {
                throw new IllegalArgumentException("Key must be 16 bytes (128 bits)");
            }

            // Decode the Base64 input message
            byte[] combined = Base64.getDecoder().decode(message);

            // Extract IV (12 bytes), Ciphertext, and Tag (last 16 bytes)
            byte[] iv = new byte[12];
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[combined.length - iv.length - tag.length];

            System.arraycopy(combined, 0, iv, 0, iv.length);
            System.arraycopy(combined, combined.length - tag.length, tag, 0, tag.length);
            System.arraycopy(combined, iv.length, ciphertext, 0, ciphertext.length);

            // Initialize Cipher for AES-GCM
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv); // 128-bit authentication tag
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

            // Combine ciphertext and tag for decryption
            byte[] decryptedBytes = cipher.doFinal(ciphertext);

            // Convert decrypted bytes to string
            return new String(decryptedBytes, StandardCharsets.UTF_8);

        } catch (Exception e) {
            return "JavaDecryptionError: " + e.toString();
        }
    }

    public static void main(String[] args) {
        String encryptedMessage = "YourBase64EncryptedMessageHere";
        String key = "1234567890123456"; // 16-byte key

        String decryptedMessage = AESDecrypt_GCM(encryptedMessage, key);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}





,.........

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AesGcmEncryption {

    public static String AESEncrypt_GCM(String message, String key) {
        try {
            // Convert key to byte array
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
            
            // Ensure key length is valid for AES (16 bytes for AES-128)
            if (keyBytes.length != 16) {
                throw new IllegalArgumentException("Key must be 16 bytes (128 bits)");
            }

            // Generate Initialization Vector (IV) - 12 bytes for AES-GCM
            byte[] iv = new byte[12];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);

            // Create AES SecretKeySpec
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

            // Initialize Cipher for AES-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv); // 128-bit authentication tag
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

            // Encrypt the message
            byte[] plaintextBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertextBytes = cipher.doFinal(plaintextBytes);

            // Combine IV, Ciphertext, and Authentication Tag
            byte[] combined = new byte[iv.length + ciphertextBytes.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertextBytes, 0, combined, iv.length, ciphertextBytes.length);

            // Encode result to Base64 for easy transport/storage
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            return "JavaEncryptionError: " + e.toString();
        }
    }

    public static void main(String[] args) {
        String message = "YourMessageHere";
        String key = "1234567890123456"; // 16-byte key

        String encryptedMessage = AESEncrypt_GCM(message, key);
        System.out.println("Encrypted Message: " + encryptedMessage);
    }
}






import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AesGcmEncryption {

    public static String AESEncrypt_GCM(String message, String key) {
        try {
            // Convert key to bytes
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
            // Use first 12 bytes of the key as IV
            byte[] iv = new byte[12];
            System.arraycopy(keyBytes, 0, iv, 0, 12);

            // Generate SecretKeySpec
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

            // Initialize cipher in AES/GCM/NoPadding mode
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

            // Encrypt the message
            byte[] plaintextBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertextBytes = cipher.doFinal(plaintextBytes);

            // Combine IV, Ciphertext, and Tag
            byte[] combined = new byte[iv.length + ciphertextBytes.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertextBytes, 0, combined, iv.length, ciphertextBytes.length);

            // Convert to Base64 string
            return Base64.getEncoder().encodeToString(combined);

        } catch (Exception e) {
            // Handle exception and return error message
            return "X-JavaError: " + e.toString();
        }
    }

    public static void main(String[] args) {
        // Test the function
        String key = "123456789012345678901234"; // 24-byte key
        String message = "Hello, IBM ACE!";
        String encryptedMessage = AESEncrypt_GCM(message, key);
        System.out.println("Encrypted Message: " + encryptedMessage);
    }
}






import json

def generate_update_statement(req1_file, req2_file, output_file):
    with open(req1_file, 'r') as f1, open(req2_file, 'r') as f2, open(output_file, 'w') as out_file:
        # Load JSON data from the files
        req1 = json.load(f1)
        req2 = json.load(f2)
        
        # Find fields in req1 that are missing in req2
        missing_fields = {key: value for key, value in req1.items() if key not in req2}
        
        # Base query components
        table_name = "details"
        column_name = "request_data"
        
        # Generate WHERE clause using all fields from req1
        where_clause = " AND ".join([f"{column_name}->>'{key}' = '{value}'" for key, value in req1.items()])
        
        # Generate SET clause for missing fields from req1, setting their values in req2
        set_clause = ", ".join([f"{column_name}->>'{key}' = '{value}'" for key, value in missing_fields.items()])

        # Construct the final UPDATE query if there are missing fields
        if missing_fields:
            update_query = f"UPDATE {table_name} SET {set_clause} WHERE {where_clause};\n"
            out_file.write(update_query)
            print("Update statement written to output file.")
        else:
            print("No missing fields. No update needed.")

# File paths
req1_file = 'req1.json'
req2_file = 'req2.json'
output_file = 'update.sql'

# Execute function
generate_update_statement(req1_file, req2_file, output_file)







import json
from datetime import datetime

# Function to format SQL insert statements
def generate_insert_statement(api_code, field_name, field_value, action, service_name):
    return (f"INSERT INTO EISAPP.IHUB_CACHE_DETAILS "
            f"(API_CODE, FIELD_NAME, FIELD_VALUE, CREATION_TIME, ACTION, SERVICE_NAME) "
            f"VALUES ('{api_code}', '{field_name}', '{json.dumps(field_value)}', TRUNC(SYSDATE), '{action}', '{service_name}');\n")

# Function to process JSON files and generate SQL statements
def create_sql_insert_statements(request_file, response_file, output_file):
    api_code = '000022'
    service_name = 'Account Flag Enquiry'

    with open(request_file, 'r') as req_file, open(response_file, 'r') as resp_file, open(output_file, 'w') as outfile:
        # Read request and response from their respective files
        request_json = json.loads(req_file.readline().strip())
        response_json = json.loads(resp_file.readline().strip())

        # 1. Insert statement for request map
        request_map_field_name = f"{api_code}_REQUEST_MAP"
        request_insert = generate_insert_statement(api_code, request_map_field_name, request_json, 'REQUEST_MAP', service_name)
        outfile.write(request_insert)

        # 2. Insert statement for response map
        response_map_field_name = f"{api_code}_RESPONSE_MAP"
        response_insert = generate_insert_statement(api_code, response_map_field_name, response_json, 'RESPONSE_MAP', service_name)
        outfile.write(response_insert)

        # 3. Insert statement for endpoint URL
        endpoint_url = 'http://eissiuat.sbi.co.in:3001/AccountFlag_bth/enquiry/accounts'
        endpoint_url_field_name = f"{api_code}_ENDPOINT_URL"
        endpoint_url_insert = generate_insert_statement(api_code, endpoint_url_field_name, endpoint_url, 'ENDPOINT_URL', service_name)
        outfile.write(endpoint_url_insert)

        # 4. Insert statement for timeout
        timeout_value = '15'
        timeout_field_name = f"{api_code}_TIME_OUT"
        timeout_insert = generate_insert_statement(api_code, timeout_field_name, timeout_value, 'TIME_OUT', service_name)
        outfile.write(timeout_insert)

# File paths for request and response JSON, and SQL output
request_file = 'request.jsonl'
response_file = 'response.jsonl'
output_file = 'output.sql'

# Generate the SQL insert statements
create_sql_insert_statements(request_file, response_file, output_file)














import javax.crimport json
import re

# Function to convert snake_case or space separated words to CamelCase
def to_camel_case(field):
    parts = re.split(r'[_ ]+', field)
    return parts[0].capitalize() + ''.join(part.capitalize() for part in parts[1:])

# Function to process each line and generate the output dictionary
def process_request(request_data):
    output = {}
    for key in request_data:
        # Convert the field name to camel case for the output dictionary's key
        camel_key = to_camel_case(key)
        # Map the camel case key to its original field name
        output[camel_key] = key
    return output

# Function to process the input file and generate the output for each request
def process_requests_from_file(input_file):
    with open(input_file, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                try:
                    # Parse each line as JSON
                    request_data = json.loads(line)
                    # Process the request and generate the output
                    output = process_request(request_data)
                    print(json.dumps(output, indent=4))
                except json.JSONDecodeError:
                    print("Invalid JSON format in line:", line)

# Input file path
input_file = 'requests.txt'

# Process the requests from file
process_requests_from_file(input_file)
ypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class EncryptionExample {

    // Method to encrypt a plain text
    public static String encrypt(String plainText) throws Exception {
        // Base64 encoded key (32 bytes for AES-256)
        String base64Key = "abcdefghijklmnopqrstuvwxyz123456";  // Replace with your key
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);

        // Generate random IV (16 bytes for AES/CBC)
        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        // Perform encryption
        byte[] encryptedBytes = encryptWithAesCbcPkcs5(plainText, keyBytes, iv);

        // Concatenate IV + Encrypted data
        byte[] encryptedWithIv = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, encryptedWithIv, iv.length, encryptedBytes.length);

        // Return Base64 encoded result (IV + Encrypted data)
        return Base64.getEncoder().encodeToString(encryptedWithIv);
    }

    // Encrypt method using AES/CBC/PKCS5Padding
    private static byte[] encryptWithAesCbcPkcs5(String plainText, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);

        return cipher.doFinal(plainText.getBytes("UTF-8"));
    }

    public static void main(String[] args) {
        try {
            // Example text to encrypt
            String plainText = "This is a secret message.";

            // Perform encryption
            String encryptedData = encrypt(plainText);
            System.out.println("Encrypted Data (Base64): " + encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}














import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;

public class DecryptionExample {

    // Decrypt base64-encoded string
    public static String decrypt(String base64EncryptedText) throws Exception {
        // Trim the input and remove any unexpected characters
        base64EncryptedText = base64EncryptedText.trim().replace("\r", "").replace("\n", "").replace(" ", "");

        // Validate the input characters
        for (char c : base64EncryptedText.toCharArray()) {
            if (!Character.isLetterOrDigit(c)) {
                throw new IllegalArgumentException("Unexpected character: " + c + " (Unicode: " + (int) c + ")");
            }
        }

        // Decode the base64 string into a byte array
        byte[] encryptedBytes = Base64.getDecoder().decode(base64EncryptedText);

        // Call method to decrypt the byte array (cipherTextWithIv)
        return decryptFromBase64(encryptedBytes);
    }

    // Decrypt from byte array which contains IV + cipher text
    public static String decryptFromBase64(byte[] cipherTextWithIv) {
        try {
            // Define AES encryption parameters
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] key = Base64.getDecoder().decode("abcdefghijklmnopqrstuvwxyz123456");  // Base64-encoded key (32 bytes for AES-256)

            if (cipherTextWithIv.length < cipher.getBlockSize()) {
                throw new IllegalArgumentException("The cipherTextWithIv array is too short to contain the IV.");
            }

            // Extract the IV (first 16 bytes)
            byte[] iv = new byte[cipher.getBlockSize()];
            System.arraycopy(cipherTextWithIv, 0, iv, 0, iv.length);

            // Extract the cipher text (remaining bytes)
            byte[] cipherText = new byte[cipherTextWithIv.length - iv.length];
            System.arraycopy(cipherTextWithIv, iv.length, cipherText, 0, cipherText.length);

            // Initialize decryption
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);

            // Decrypt the cipher text
            byte[] decryptedBytes = cipher.doFinal(cipherText);

            // Return decrypted text as string
            return new String(decryptedBytes, "UTF-8");

        } catch (Exception ex) {
            return ex.toString();  // In case of exception, return error message
        }
    }

    public static void main(String[] args) throws Exception {
        // Example of an encrypted text (IV + Cipher Text, base64 encoded)
        String base64EncryptedText = "Base64_Encrypted_Data";

        // Perform decryption
        String decryptedText = decrypt(base64EncryptedText);
        System.out.println("Decrypted Data: " + decryptedText);
    }
}









import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Base64;
import java.security.SecureRandom;

public class EncryptionExample {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Generate random IV of 16 bytes
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Symmetric key base64 encoded (32 bytes key)
        String base64Key = "abcdefghijklmnopqrstuvwxyz123456"; // Example 32 bytes
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);

        String plainText = "This is the text to encrypt";

        // Perform encryption
        String encryptedData = encrypt(plainText, keyBytes, iv);
        System.out.println("Encrypted Data: " + encryptedData);
    }

    public static String encrypt(String data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);

        byte[] encryptedData = cipher.doFinal(data.getBytes());

        // Concatenate IV with encrypted data
        byte[] encryptedWithIv = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encryptedData, 0, encryptedWithIv, iv.length, encryptedData.length);

        // Encode the final result to Base64
        return Base64.getEncoder().encodeToString(encryptedWithIv);
    }
}
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Base64;

public class DecryptionExample {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Symmetric key base64 encoded (32 bytes key)
        String base64Key = "abcdefghijklmnopqrstuvwxyz123456"; // Example 32 bytes
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);

        // Encrypted data (IV + Encrypted Data Base64 encoded)
        String encryptedData = "Base64_Encrypted_Data";  // Use the output from the encryption method

        // Perform decryption
        String decryptedData = decrypt(encryptedData, keyBytes);
        System.out.println("Decrypted Data: " + decryptedData);
    }

    public static String decrypt(String encryptedData, byte[] key) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

        // Extract IV (first 16 bytes)
        byte[] iv = new byte[16];
        System.arraycopy(encryptedBytes, 0, iv, 0, iv.length);

        // Extract encrypted data (remaining bytes)
        byte[] actualEncryptedData = new byte[encryptedBytes.length - iv.length];
        System.arraycopy(encryptedBytes, iv.length, actualEncryptedData, 0, actualEncryptedData.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);

        byte[] decryptedData = cipher.doFinal(actualEncryptedData);

        return new String(decryptedData);
    }
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
