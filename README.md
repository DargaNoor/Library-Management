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
