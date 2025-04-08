'{

"mobileNumber": "9940173757",

"otpType": "S",

"template": "Change PIN OTP",

"entityld": "531115787360000002100225",

"productid": "6jmuBHZ8Gr",

"card": "0024"





package com.sbi.Martech;

import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Properties;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class INC_ENC_DNC {
    
    static String base64PublicKey;
    static HashMap<String, String> hashmap_public = new HashMap<>();

    public static String getAlphaNumericString() {
        int n = 32;
        SecureRandom rnd = new SecureRandom();
        int n1 = 10000000 + rnd.nextInt(9999999);
        String ranNum = String.valueOf(n1);
        String secKey = ranNum + ranNum + ranNum + ranNum;
        return secKey.substring(0, n);
    }

    public static String getPublicKey() {
        try {
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) f.generateCertificate(INC_ENC_DNC.class.getResourceAsStream("/certs/INS_PCMS.cer"));
            PublicKey publicKey = certificate.getPublicKey();
            base64PublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            return base64PublicKey;
        } catch (Exception e) {
            return "X-JavaError " + e.getMessage();
        }
    }

    public static String AESEncrypt_GCM(String message, String keyStr) {
        try {
            String algorithm = "AES/GCM/NoPadding";
            byte[] keyByte = keyStr.getBytes("UTF-8");
            byte[] iv = Arrays.copyOf(keyByte, 16);
            SecretKeySpec key = new SecretKeySpec(keyByte, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            return "X-JavaError " + e.toString();
        }
    }

    public static String AESDecrypt_GCM(String message, String key) {
        if (message.trim().isEmpty()) {
            return "X-JavaError request body is empty";
        }
        try {
            byte[] keyByte = key.getBytes("UTF-8");
            byte[] ivKey = Arrays.copyOf(keyByte, 16);
            byte[] encValue = Base64.getDecoder().decode(message);
            SecretKeySpec secKey = new SecretKeySpec(keyByte, "AES");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivKey);
            c.init(Cipher.DECRYPT_MODE, secKey, gcmParameterSpec);
            byte[] decValue = c.doFinal(encValue);
            return new String(decValue);
        } catch (Exception e) {
            return "X-JavaError " + e.toString();
        }
    }

    public static String RSAEncrypt(String data) {
        try {
            if (base64PublicKey == null) {
                base64PublicKey = getPublicKey();
            }
            byte[] decodedPublicKey = Base64.getDecoder().decode(base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedPublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] encryptedData = cipher.doFinal(data.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            return "X-JavaError " + e.getMessage();
        }
    }

    public static PublicKey getPublicKey_RBI() {
        try {
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) f.generateCertificate(INC_ENC_DNC.class.getResourceAsStream("/certs/INS_PCMS.cer"));
            return certificate.getPublicKey();
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String[] args) {
        try {
            String key = getAlphaNumericString();
            System.out.println("AES Key: " + key);
            
            String rsaEncryptedKey = RSAEncrypt(key);
            System.out.println("RSA Encrypted Key: " + rsaEncryptedKey);
            
            String requestPayload = "{\"ATM_TXN_AMOUNT\":\"100\",\"PROXY_NUMBER\":\"100000074837\",\"POS_TXN_FLAG\":\"1\"}";
            String encryptedRequest = AESEncrypt_GCM(requestPayload, key);
            System.out.println("Encrypted Request: " + encryptedRequest);
            
            String decryptedRequest = AESDecrypt_GCM(encryptedRequest, key);
            System.out.println("Decrypted Request: " + decryptedRequest);
            
        } catch (Exception e) {
            System.out.println("X-JavaError " + e.getMessage());
        }
    }
}








package com.sbi.Martech;

import java.io.FileInputStream;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

public class EncryptionUtils {

    private static final String CERT_PATH = "/home/aceuser/certs/INS_PCMS.cer";  // Change as per ACE environment

    // Generate AES Key (32 characters)
    public static String generateAESKey() {
        SecureRandom rnd = new SecureRandom();
        int n1 = 10000000 + rnd.nextInt(9999999);
        String ranNum = String.valueOf(n1);
        return ranNum + ranNum + ranNum + ranNum;
    }

    // Load Public Key from Certificate
    public static String getPublicKey() {
        try {
            FileInputStream fin = new FileInputStream(CERT_PATH);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(fin);
            PublicKey publicKey = certificate.getPublicKey();
            byte[] encodedKey = publicKey.getEncoded();
            return Base64.encodeBase64String(encodedKey);
        } catch (Exception e) {
            return "X-JavaError " + e.getMessage();
        }
    }

    // RSA Encryption
    public static String encryptRSA(String data) {
        try {
            String base64PublicKey = getPublicKey();
            byte[] decodedKey = Base64.decodeBase64(base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));

            return Base64.encodeBase64String(encryptedBytes);
        } catch (Exception e) {
            return "X-JavaError " + e.getMessage();
        }
    }

    // AES-GCM Encryption
    public static String encryptAESGCM(String message, String keyStr) {
        try {
            String algorithm = "AES/GCM/NoPadding";
            byte[] keyBytes = keyStr.getBytes("UTF-8");
            byte[] iv = Arrays.copyOf(keyBytes, 16);

            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

            byte[] encryptedBytes = cipher.doFinal(message.getBytes("UTF-8"));
            return Base64.encodeBase64String(encryptedBytes);
        } catch (Exception e) {
            return "X-JavaError " + e.getMessage();
        }
    }

    // AES-GCM Decryption
    public static String decryptAESGCM(String encryptedMessage, String keyStr) {
        try {
            byte[] keyBytes = keyStr.getBytes("UTF-8");
            byte[] iv = Arrays.copyOf(keyBytes, 16);
            byte[] encValue = Base64.decodeBase64(encryptedMessage);

            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

            byte[] decValue = cipher.doFinal(encValue);
            return new String(decValue);
        } catch (Exception e) {
            return "X-JavaError " + e.getMessage();
        }
    }
}















//////


package com.sbi.Martech;


import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Properties;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;





public class INC_ENC_DNC {

	static String jkspwd,enpass= "";
	   static String base64PrivateKey,base64publickey,base64sourcepublickey = null;
	   static String sourcepublicpath = "";
	   static HashMap<String, String> hashmap_public = new HashMap<>();
	   static String jkspath="D:/ibmdevportall.jks";
	   static String certPath="E:/INS_PCMS.cer";
	   static String propertiesPath="D:/KeyMapper.properties";
	   

	   
	   public  static String getAlphaNumericString() 
	    { 		

	    	int n =32;	
	    	SecureRandom rnd = new SecureRandom();	    	
	    	int n1 = 10000000 + rnd.nextInt(9999999);
	    	String ranNum = String.valueOf(n1);
	    	String secKey = ranNum + ranNum + ranNum + ranNum;
	    	StringBuilder sb = new StringBuilder(n);
	        sb.append(secKey);
	    	return sb.toString();
		   
	    }
	   
	   
 
 public static String getPublicKey()
		{
	 		try {
	 			FileInputStream fin = new FileInputStream(certPath);
				CertificateFactory f = CertificateFactory.getInstance("X.509");
				X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
				PublicKey publicKey= certificate.getPublicKey();
				byte[] pk=publicKey.getEncoded();
			    base64publickey = DatatypeConverter.printBase64Binary(pk);
			   fin.close();	 
	 		}
				
			catch (Exception e)
			{			
	      		return "X-JavaError" +" " +e.getMessage();			
			    }
		     return base64publickey;	
	   	}

	  
	   


	   public static String AESEncrypt_GCM(String message,String keyStr) 
	   {
	 	  try {  
	 		  
	 		 String encryptedStr = null;
	            String algorithm = "AES/GCM/NoPadding";

	            byte[] keybyte = keyStr.getBytes("UTF-8");
	            byte[] iv = Arrays.copyOf(keybyte, 16);

	            SecretKeySpec key = new SecretKeySpec(keybyte, "AES");
	            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
	      	            Cipher cipher = Cipher.getInstance(algorithm);
	            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

	            byte[] encryptedBytes = cipher.doFinal(message.getBytes("UTF-8"));	           
	            encryptedStr = Base64.encodeBase64String(encryptedBytes);
	            return encryptedStr;
	 		  
	 		
	 	} catch (IOException e) {	  	  		
  			return "X-JavaError" +" " +e.toString();	  	  			
		} 
		catch (NoSuchAlgorithmException e) {	  	  		
  			return "X-JavaError" +" " +e.toString();	  	  			
		} 
		catch (NoSuchPaddingException e) {	  	  		
  			return "X-JavaError" +" " +e.toString();	  	  			
		} 
		catch (InvalidKeyException e) {	  	  		
  			return "X-JavaError" +" " +e.toString();	  	  			
		} 
		catch (InvalidAlgorithmParameterException e) {	  	  		
  			return "X-JavaError" +" " +e.toString();	  	  			
		} 
		catch (IllegalBlockSizeException e) {	  	  		
  			return "X-JavaError" +" " +e.toString();	  	  			
		}	 
		 catch (Exception e) {
	 		return "X-JavaError" +" " +e.toString();
	 	}
	   }
	   
	   public static String AESDecrypt_GCM(String message, String key) 
	   {
		  if (message.trim().length() == 0) {
			 return "X-JavaError" +" " +"request body is empty";
		}
	 	  try {
	 		  byte [] keybyte = key.getBytes("UTF-8"); 
	 		  byte [] ivkey = Arrays.copyOf(keybyte,16); 
	 		  byte [] encvalue = Base64.decodeBase64(message);  
	 		SecretKeySpec seckey= new SecretKeySpec(keybyte, "AES");
	 		Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
	 		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivkey);
	 		
	 		//IvParameterSpec iv = new IvParameterSpec(ivkey);
	 		c.init(Cipher.DECRYPT_MODE,seckey,gcmParameterSpec);
	 		byte[] decvalue=c.doFinal(encvalue);
	 		String decryptedvalue = new String(decvalue);
	 		return decryptedvalue;
	 	} catch (IOException e) {	  	  		
  			return "X-JavaError" +" " +e.toString();	  	  			
		} 
		catch (NoSuchAlgorithmException e) {	  	  		
  			return "X-JavaError" +" " +e.toString();	  	  			
		} 
		catch (NoSuchPaddingException e) {	  	  		
  			return "X-JavaError" +" " +e.toString();	  	  			
		} 
		catch (InvalidKeyException e) {	  	  		
  			return "X-JavaError" +" " +e.toString();	  	  			
		} 
		catch (InvalidAlgorithmParameterException e) {	  	  		
  			return "X-JavaError" +" " +e.toString();	  	  			
		} 
		catch (IllegalBlockSizeException e) {	  	  		
  			return "X-JavaError" +" " +e.toString();	  	  			
		}	 
		 catch (Exception e) {
	 		return "X-JavaError" +" " +e.toString();
	 	}
	   }
	   
	   

	
	public static String getProperty(String key,String propertiesPath)
		{
	
			BufferedReader reader;
			try {
				reader = new BufferedReader(new FileReader(propertiesPath));
				Properties p = new Properties();
				p.load(reader);
				return p.getProperty(key);
	      		} 
			
			catch (Exception e){
				
	      		return "X-JavaError" +" " +e.getMessage();
				
			    }
		     	
	   	}
	
	public static String RSAEncrypt(String data)
	   {     String encData= "";
	         String base64EncodedData= "";
		   try {
			   if (base64publickey  == null)
	           {	
				   base64publickey = getPublicKey();	
	           }
				
				byte[] base64decpublivKey = Base64.decodeBase64(base64publickey);
	            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64decpublivKey);
	            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	            PublicKey pubKey = keyFactory.generatePublic(keySpec);
	            
		        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithMD5AndMGF1Padding");
		        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		        byte[] data_bytes = data.getBytes("UTF-8");
		    
		        System.out.println(data_bytes);
		        byte[] encdatabyte = cipher.doFinal(data_bytes); 
		   
		        base64EncodedData =  Base64.encodeBase64String(data_bytes);
		        System.out.println(base64EncodedData);
		        encData =  Base64.encodeBase64String(encdatabyte);
		    
			
			} catch (Exception e) {
				return "X-JavaError" +" " +e.getMessage();
			}
		   
		   return encData;
				   
	   }
	
	public static PublicKey getPublicKey_RBI() {
		PublicKey publicKey = null;
		try {
			FileInputStream fin = new FileInputStream(certPath);
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
			fin.close();
			return certificate.getPublicKey();
		} catch (Exception e) {
			return publicKey;
		}
	}
	

	
	public static void main(String[] args) throws Exception {
		
		
		String key = "11111111111111111111111111111111";
	      System.out.println("AESkey : " + key);
	    
	      String acc = RSAEncrypt(key);
	      System.out.println("RSA ENC : " + acc);
	      
	      String R = "{\"ATM_TXN_AMOUNT\":\"100\",\"PROXY_NUMBER\":\"100000074837\",\"POS_TXN_FLAG\":\"1\",\"REMARKS\":\"API  INSERTION  UPDATION \",\"REQUEST_ID\":\"YON2301251237544127\",\"CARD_NUMBER\":\"4216872500089960\",\"POS_TXN_COUNT\":\"1\",\"ECOM_TXN_AMOUNT\":\"100\",\"CL_TXN_COUNT\":\"1\",\"REQUEST_CODE\":\"LMTUPDT\",\"POS_TXN_AMOUNT\":\"100\",\"ECOM_TXN_COUNT\":\"1\",\"ATM_TXN_FLAG\":\"1\",\"ATM_TXN_COUNT\":\"1\",\"CL_TXN_FLAG\":\"1\",\"CL_TXN_AMOUNT\":\"100\",\"ECOM_TXN_FLAG\":\"1\"}";
	      String Request = AESEncrypt_GCM(R, key);
	      System.out.println("Request : " + Request);
	      
	      String ciurl = "curl -k -X POST https://10.176.6.135:8510/SBICMS/cmsServices/limitEnquiry -H 'Content-type:application/json' -H 'AccessToken: " 
	    			+ acc +  "' -d '{\"REQUEST_REFERENCE_NUMBER\": \"YON2301251236485570\",\"REQUEST\":"
	    			+ "\"" + Request + "\"}'";
	      System.out.println("ciurl: " + ciurl);
			
	      
	      Request =   AESDecrypt_GCM("fAk3sG4UedIzC9DaNUJFZ3xPAP3QYTkQn43lck+LCcnrH1O5kDPo2HbkCGr449mY4DRVDhCb12NCyn9mZnVVVQPo6Mr6Z3FYeCgA7YqnU64CH8wHZDyS3aWirJ5Yfnka1wA54DXXD7Z/ZuO5wGgNLzq+hn0f/sqxdDeHZpn/OlxIM900ni6qETyqzJkcTqjQH0e9rzjl5dUwRo0Nstr4HlWxakn0FHSiQg==",key);
	    		  
	    		  System.out.println("Request : " + Request);
	      
	    	
		
		
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
