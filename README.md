Sr. No

Initiative

3

4

1

DFG Payload Inhound logging in DB

2

DPG Payload outbound logging in DB

Toggling of DPG Audit, DPG Payload based on insert selector

Multiple Timeout

In case any failure at DPG end we are unable to monitor and view the problem.

Currently we capture only request and response time at SYS layer but not at DPG level, so it will be captured as well

In case any failure at DPG end we are unable to monitor and view the problem. It is not possible to view exact dara send to end system it can be captured as well.

DPG Audit, DPG Payload can be toggled to be logged or not to save DB space for enquiry txn.

Open

Change Description

Current Status

Remarks

Target Closure

Currently we capture only DPG req and Resp time in DB

Done

Open

30-04-2025

UAT Finished, PROD in Progress

Done

Open

31-05-2025

Completed in UAT and NESL Done remaining Pending for Prod

Under UAT, PROD in Progress Depended on Point 1

31-05-2025

Multiple Timeout based on channel

Open

Changes Done need to be promted in UAT

10-04-2025

CBS identifier for Bancs APIs

EIS to generate CBS identifier the TXN with RRN sent by channel. and send the identifier to the CBS at end of string will help in corelating

Open

Changes in Progress

30-04-2025

New Error will be shown in response as difference between DPG and EXP Timeout is more than the set threshold limit, configured in cache

6

Check for Tumeout between DPG and EXP

Open

Deployed in CUSTOMER EXP, and will be deployed in remaining servers later post confirmation

01-05-2025

7

DPGMQ

Sending SMS from DPG to MQ Server

Open

POC in Progress. FAR in progress

31-05-2025

IMPS Beneficiary Name Lookup

Beneficiary Name Lookup for Inward NEFT/RTGS

Clased

Prod Promoted

NA

IMPS outward Process flow

Beneficiary Name Lookup for Inward NEFT/RTGS

Closed

Prod Promoted

NA

Revert




















import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public byte[] decryptMessage(byte[] encryptedMessage, byte[] vector, byte[] aesKey) throws Exception {
    // Extract 16-byte IV from vector starting at index 8
    byte[] m_IV = new byte[16];
    System.arraycopy(vector, 8, m_IV, 0, 16);

    // Create AES key and IV spec
    SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(m_IV);

    // Initialize cipher in AES/CFB/NoPadding mode
    Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

    // Decrypt
    return cipher.doFinal(encryptedMessage);
}

























import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;

public byte[] getkey(byte[] encryptedKey, byte[] pad, PrivateKey privateKey) throws Exception {
    // If pad is custom, pass it; if not, use DEFAULT
    PSource.PSpecified pSource = (pad != null && pad.length > 0)
        ? new PSource.PSpecified(pad)
        : PSource.PSpecified.DEFAULT;

    OAEPParameterSpec oaepParams = new OAEPParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, pSource
    );

    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
    return cipher.doFinal(encryptedKey);
}












import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.MGF1ParameterSpec;
import javax.crypto.spec.PSource;
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.MessageDigest;

public byte[] getKey(byte[] encryptedKey, byte[] pad, PrivateKey privateKey) throws Exception {
    // Define OAEP parameters with SHA-256 and the label
    OAEPParameterSpec oaepParams = new OAEPParameterSpec(
        "SHA-256",                               // Digest algorithm
        "MGF1",                                  // Mask generation function
        MGF1ParameterSpec.SHA256,                // MGF1 Digest algorithm
        new PSource.PSpecified(pad)              // Label (padding)
    );

    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);

    return cipher.doFinal(encryptedKey);
}





















import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.digests.SHA256Digest;

public byte[] getKey(byte[] encryptedKey, byte[] pad, PrivateKey javaPrivateKey) throws Exception {
    // Convert Java PrivateKey to Bouncy Castle format
    AsymmetricKeyParameter privateKeyParam = PrivateKeyFactory.createKey(javaPrivateKey.getEncoded());

    // Create OAEP encoding with SHA-256 digest and custom label (pad)
    OAEPEncoding oaep = new OAEPEncoding(new RSAEngine(), new SHA256Digest(), pad);
    oaep.init(false, privateKeyParam); // false for decryption

    // Decrypt the data
    return oaep.processBlock(encryptedKey, 0, encryptedKey.length);
}

















private byte[] getkey(byte[] encryptkey, byte[] pad)
{
    //ECDecryptor.CSPDecryption csp = new CSPDecryption();
    //csp.Decrypt(encryptkey, pad);

    IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest(), pad);
    AsymmetricKeyParameter privateKey = this.GetPrivateKey(this.m_Location, m_Password);
    cipher.Init(false, privateKey);
    return cipher.ProcessBlock(encryptkey, 0, encryptkey.Length);
    //return null;



}










public static byte[][] split(byte[] source, int lengthOfFirst)
{
    byte[] first = new byte[lengthOfFirst];
    byte[] second = new byte[source.Length - lengthOfFirst];
    Array.Copy(source, 0, first, 0, lengthOfFirst);
    Array.Copy(source, lengthOfFirst, second, 0, source.Length - lengthOfFirst);

    byte[][] finalByte = { first, second };


    return finalByte;
}









private List<byte[]> splitToChunks(byte[] source, int chunkSize) {
    List<byte[]> result = new ArrayList<>();
    int index = 0;
    while (index < source.length) {
        int end = Math.min(index + chunkSize, source.length);
        result.add(Arrays.copyOfRange(source, index, end));
        index = end;
    }
    return result;
}






private byte[][] extractFixedChunks(byte[] source, int... lengths) throws Exception {
    byte[][] result = new byte[lengths.length][];
    int offset = 0;

    for (int i = 0; i < lengths.length; i++) {
        if (offset + lengths[i] > source.length) {
            throw new Exception("Invalid input: expected length " + lengths[i] + " at chunk " + i);
        }
        result[i] = Arrays.copyOfRange(source, offset, offset + lengths[i]);
        offset += lengths[i];
    }

    return result;
}


























package com.example.crypto;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class Main {

    public static void main(String[] args) {
        try {
            // Provide path to your .pfx certificate file and password
            String pfxPath = "/path/to/your/certificate.pfx";
            String pfxPassword = "yourPfxPassword";

            // Initialize CryptoUtil with the certificate
            CryptoUtil cryptoUtil = new CryptoUtil(pfxPath, pfxPassword);

            // Example: load the encrypted data (Base64 encoded) from a file or string
            // Here we assume you have Base64 encoded encrypted data in a file or string
            String base64EncryptedData = Files.readString(Paths.get("/path/to/encryptedData.b64")).trim();

            // Decode Base64 to get the encrypted byte array
            byte[] encryptedData = Base64.getDecoder().decode(base64EncryptedData);

            // Call RSADecrypt method to decrypt
            String decryptedText = cryptoUtil.RSADecrypt(encryptedData);

            System.out.println("Decrypted text: " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Error occurred: " + e.getMessage());
        }
    }
}












package com.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class CryptoUtil {

    private PrivateKey privateKey;

    public CryptoUtil(String pfxPath, String password) throws Exception {
        FileInputStream fis = new FileInputStream(pfxPath);
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(fis, password.toCharArray());
        String alias = keystore.aliases().nextElement();
        Key key = keystore.getKey(alias, password.toCharArray());
        if (key instanceof PrivateKey) {
            privateKey = (PrivateKey) key;
        }
    }

    public String RSADecrypt(byte[] encryptedAndEncodedData) throws Exception {
        byte[] plainBytes = decrypt(encryptedAndEncodedData, false);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    public byte[] decrypt(byte[] datatosegregate, boolean fromUSBToken) throws Exception {
        byte[][] verdata = split(datatosegregate, 11);
        String verNumber = new String(verdata[0], StandardCharsets.US_ASCII);
        byte[] verData = verNumber.equals("VERSION_1.0") ? verdata[1] : datatosegregate;

        byte[][] data = split(verData, 294);
        byte[] publicKeyBlock = data[0];
        byte[] mergedata = data[1];

        byte[][] datafrompad = split(mergedata, 32);
        byte[] padding = datafrompad[0];
        byte[] mergedatafromkey = datafrompad[1];

        byte[][] datafromkey = split(mergedatafromkey, 256);
        byte[] encryptedsecret = datafromkey[0];
        byte[] encryptedmessage = datafromkey[1];

        byte[] secretkey;
        if (fromUSBToken) {
            throw new UnsupportedOperationException("USB Token decryption not supported in this version.");
        } else {
            secretkey = getkey(encryptedsecret, padding);
        }

        byte[] plaintext = decryptmessage(encryptedmessage, padding, secretkey);
        byte[][] result = split(plaintext, 32);

        byte[] hash = generateHash(result[1]);
        if (!Arrays.equals(hash, result[0])) {
            throw new Exception("File is Corrupt or invalid !");
        }

        return result[1];
    }

    private byte[] getkey(byte[] encryptedsecret, byte[] padding) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedsecret);
    }

    private byte[] decryptmessage(byte[] encryptedmessage, byte[] iv, byte[] key) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
        return cipher.doFinal(encryptedmessage);
    }

    private byte[] generateHash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    private byte[][] split(byte[] source, int splitLength) {
        int numberOfChunks = (int) Math.ceil((double) source.length / splitLength);
        byte[][] result = new byte[numberOfChunks][];
        for (int i = 0; i < numberOfChunks; i++) {
            int start = i * splitLength;
            int length = Math.min(source.length - start, splitLength);
            result[i] = Arrays.copyOfRange(source, start, start + length);
        }
        return result;
    }
}
































public string RSADecrypt(Byte[] encryptedAndEncodedData)
{
    string plain_text = string.Empty;
    try
    {
        Decryptor.Decryptor rsaDecryptor = new Decryptor.Decryptor();
        rsaDecryptor.KeyStoreLocation = HttpContext.Current.ApplicationInstance.Server.MapPath("~/App_Data/Cert/") + ConfigurationManager.AppSettings["BankPPKFilePath"];
        rsaDecryptor.Password = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(System.Configuration.ConfigurationManager.AppSettings.Get("BankPPKPwd")));
        plain_text = Encoding.UTF8.GetString(rsaDecryptor.decrypt(encryptedAndEncodedData, false));
    }
    catch (Exception Ex)
    {
        FileLogger.LogException("Exception Message : " + Ex.Message + " . Stack Trace : " + Ex.StackTrace, "Nikhil Cert", null);
        throw Ex;
    }
    return plain_text;
}


public byte[] decrypt(byte[] datatosegregate, bool fromUSBToken)
{
    byte[][] verdata = Utilities.split(datatosegregate, 11);
    byte[] versionNumber = verdata[0];
    string verNumber = System.Text.Encoding.ASCII.GetString(versionNumber);
    byte[] verData = null;
    if (verNumber.Equals("VERSION_1.0"))
    {
        verData = verdata[1];
    }
    else
    {
        verData = datatosegregate;
    }
    byte[][] data = Utilities.split(verData, 294);
    byte[] publickey = data[0];
    byte[] publicKeyModulus = GetPublicKeyInfo(publickey);
    byte[] mergedata = data[1];
    byte[][] datafrompad = Utilities.split(mergedata, 32);
    byte[] padding = datafrompad[0];
    byte[] mergedatafromkey = datafrompad[1];
    byte[][] datafromkey = Utilities.split(mergedatafromkey, 256);
    byte[] encryptedsecret = datafromkey[0];
    Console.WriteLine(encryptedsecret.Length);
    byte[] encryptedmessage = datafromkey[1];
    byte[] secreatkey = null;
    if (fromUSBToken)
    {
        // Get AES key from USB Token
        //CSPDec dec = new CSPDec();
        //secreatkey = dec.Decrypt(encryptedsecret, padding, publicKeyModulus);
        //ECDecryptor.CSPDecryption csp = new ECDecryptor.CSPDecryption();
        //secreatkey = csp.Decrypt(encryptedsecret, padding, publicKeyModulus);
    }
    else
    {
        // Get AES key from private key file
        secreatkey = this.getkey(encryptedsecret, padding);
    }
    byte[] plaintext = this.decryptmessage(encryptedmessage, padding, secreatkey);
    byte[][] result = Utilities.split(plaintext, 32);

    // Console.WriteLine(Encoding.UTF8.GetString(result[1]));

    byte[] hashBytes = GenerateHash(result[1]);

    if (Utilities.ParseByteArraytoHexString(hashBytes) != Utilities.ParseByteArraytoHexString(result[0]))
        throw new System.Exception("File is Corrupt or invalid !");

    // Console.WriteLine(Encoding.UTF8.GetString(result[1]));
    return result[1];
}

<add key="BankPPKFilePath" value="SUDEEP_PHILIPS.pfx" />
<add key="BankPPKPwd" value="U2JpQDEyMzQ=" />

<add key="UIDTYPE_AadharNumber" value="0"/>
<add key="UIDTYPE_VID" value="2"/>
<add key="UIDTYPE_UIDTOKEN" value="3"/>
<add key="UIDTYPE_ReferenceKey" value="9"/>


select ERROR_DESCRIPTION from ERROR_CODE_MAPPER WHERE ERROR_CODE=:ERROR_CODE



Fingerprint

private string processNPCIGetDetailsResponse(ref EkycXMLData ekycXMLData, string ReferenceNumber, ref string ReferenceKey, string TokenFromVault, string UIDReferenceKey, string _ControllerName)
{
    string response = string.Empty;
    try
    {
      
        //Desialize the NPCI encrypted response
        NPCIKycEncryptedResponse Response_Kyc = SICommonHelper.Deserialize<NPCIKycEncryptedResponse>(ekycXMLData.ResponseXMLEncrypted.ToString());
        FileLogger.LogData("UID: XXXXXXXX" + ekycXMLData.AadhaarNumber.Substring(8, 4) + " UID Token : " + ekycXMLData.UIDToken + " :UIDReferenceKey: " + UIDReferenceKey, " : ProcessNPCIGetDetailsResponse _ControllerName", ReferenceNumber);
        //Check NPCI response is valid
        if (Response_Kyc != null && Response_Kyc.TransactionInfo != null)
        {
            string Uref = "SBI" + Response_Kyc.TransactionInfo.RRN;
            String ResponseCode = Response_Kyc.TransactionInfo.ResponseCode;
            String ResponseMsg = Response_Kyc.TransactionInfo.ResponseMsg;

            // if NPCI response is success(when Response_Kyc.Resp.status  == "0")
            if (Response_Kyc.Resp != null && Response_Kyc.Resp.status == "0")
            {
                //Decrypt Using RSA/AES using certificate from BankPPKFilePath 
                Encryptor aes256Encrypter = new Encryptor();
                Byte[] respBytes = Convert.FromBase64String(Response_Kyc.Resp.kycRes);
                //TextReader Uidata = new StringReader(aes256Encrypter.RSADecrypt(respBytes));

                KycRes KycRes = SICommonHelper.Deserialize<KycRes>(aes256Encrypter.RSADecrypt(respBytes));

                ekycXMLData.AadhaarNumber = KycRes.UidData.uid;
                ekycXMLData.UIDToken = KycRes.UidData.tkn;
                //Maindatory Storedata Vault call
                //if (this._IsVaultEnabled == "Y")
                //{
                    FileLogger.LogData("UID: XXXXXXXX" + ekycXMLData.AadhaarNumber.Substring(8, 4) + " UID Token : " 
                        + ekycXMLData.UIDToken + " :UIDReferenceKey: " + UIDReferenceKey, 
                        " : ProcessNPCIGetDetailsResponse StoreAadhaarDataInVaultAfterNPCI", ReferenceNumber);
                    var storeAadhaarDataResponse = StoreAadhaarDataInVaultAfterNPCI(ref ekycXMLData, ref ReferenceKey, ekycXMLData.UIDToken, AppConstants.NPCISuccessFlag, UIDReferenceKey, _ControllerName);
                    //ToBeRemoved 4
                   // FileLogger.LogData(JsonConvert.SerializeObject(storeAadhaarDataResponse).ToString(), "StoreAadhaarDataInVaultAfterNPCI", _NPCIRequest.ReferenceNumber);
                    if (storeAadhaarDataResponse.HasErrors)
                    {
                        if (storeAadhaarDataResponse.Errors[0].ErrorCode != "SI465")
                        {
                            vaultData = GetReferencekeyOnNPCIUp(ref ekycXMLData, AppConstants.NPCISuccessFlag, _ControllerName);
                            FileLogger.LogData(ReferenceKey, "GetReferencekeyOnNPCIUp", _NPCIRequest.ReferenceNumber);
                            return response = ekycXMLData.ResponseXMLPlain;
                        }
                        else
                            return response = ekycXMLData.ResponseXMLPlain;
                    }
                    //SBI SI: Convert UID into VRN for all channels except Front end portal
                    string[] portalIDs = AppConstants.PortalIDs.Split(',');
                    if (!portalIDs.Contains(_NPCIRequest.biometricType))
                        KycRes.UidData.uid = vaultData.ReferenceKey;
                //}

               //Finally convert  response in xml format
                KycResponse result1 = new KycResponse("0", Uref, null, KycRes.UidData, null);
                response = result1.TOXML();

            }
            else
            {
                ekycXMLData.ErrorCode = ResponseCode;
                ekycXMLData.ErrorDescription = ResponseMsg;

                if (Response_Kyc.Resp != null)
                {
                    //Check error from Resp element response from UIDAI
                    string err = !string.IsNullOrWhiteSpace(Response_Kyc.Resp.err) ? Response_Kyc.Resp.err.Trim() : string.Empty;
                    //string errMsg = _ICommonRepository.GetErrorDescription(err);

                    if (!string.IsNullOrWhiteSpace(Response_Kyc.Resp.kycRes))
                    {
                        //Deserialize kycRes
                        KycRes KycRes = SICommonHelper.Deserialize<KycRes>(Encoding.UTF8.GetString(Convert.FromBase64String(Response_Kyc.Resp.kycRes)));

                        if (KycRes != null)
                        {
                            FileLogger.LogData(Encoding.UTF8.GetString(Convert.FromBase64String(Response_Kyc.Resp.kycRes)), "KYC Response", ReferenceNumber);
                            //Check error from KycRes element response from UIDAI
                            err = !string.IsNullOrWhiteSpace(KycRes.err) ? KycRes.err.Trim() : err;
                            //errMsg = _ICommonRepository.GetErrorDescription(err);

                            if (!string.IsNullOrWhiteSpace(KycRes.Rar))
                            {
                                //Deserialize AuthRes
                                AuthResponse AuthRes = SICommonHelper.Deserialize<AuthResponse>(Encoding.UTF8.GetString(Convert.FromBase64String(KycRes.Rar)));
                                if (AuthRes != null)
                                {
                                    FileLogger.LogData(Encoding.UTF8.GetString(Convert.FromBase64String(KycRes.Rar)), "AuthResponse", ReferenceNumber);
                                    //Check error from KycRes element response from UIDAI
                                    err = !string.IsNullOrWhiteSpace(AuthRes.err) ? AuthRes.err.Trim() : err;

                                    if (!string.IsNullOrWhiteSpace(AuthRes.info) && AuthRes.info.Length <= int.MaxValue)
                                    {

                                        int startIndex = AuthRes.info.IndexOf('{') + 1;
                                        int EndIndex = AuthRes.info.IndexOf('}', startIndex);
                                        var AuthResInfo = AuthRes.info.Substring(startIndex, EndIndex - startIndex).Split(new char[] { ',' }, StringSplitOptions.None);
                                        ekycXMLData.UIDToken = AuthResInfo.Length > 0 && AuthResInfo[0].Trim().ToUpper() != "NA" ? AuthResInfo[0] : string.Empty;


                                        //if (this._IsVaultEnabled == "Y" || this._IsVaultEnabled == "N")
                                        //{

                                            var storeAadhaarDataResponse = StoreAadhaarDataInVaultAfterNPCI(ref ekycXMLData, ref ReferenceKey, TokenFromVault, AppConstants.NPCIFailFlag, UIDReferenceKey, _ControllerName);
                                            if (storeAadhaarDataResponse.HasErrors)
                                            {
                                                if (storeAadhaarDataResponse.Errors[0].ErrorCode != "SI465")
                                                {
                                                    vaultData = GetReferencekeyOnNPCIUp(ref ekycXMLData, AppConstants.NPCIFailFlag, _ControllerName);
                                                    return response = ekycXMLData.ResponseXMLPlain;
                                                }
                                                else
                                                    return response = ekycXMLData.ResponseXMLPlain;
                                            }

                                        //}
                                    }
                                }
                            }
                        }
                    }

                    //if Udai Error is null then assign npci response to uidai error
                    ekycXMLData.UIDAIErrorCode = !string.IsNullOrWhiteSpace(err) ? err : ekycXMLData.ErrorCode;

                    string errorDescription = string.Empty;
                    if (!string.IsNullOrWhiteSpace(err))
                        errorDescription = _ICommonRepository.GetErrorDescription(err);

                    ekycXMLData.UIDAIErrorDescription = !string.IsNullOrWhiteSpace(errorDescription) ? errorDescription : ekycXMLData.ErrorDescription;

                    KycResponse result = new KycResponse("-1", Uref, ekycXMLData.UIDAIErrorCode, null, ekycXMLData.UIDAIErrorDescription);
                    response = result.TOXML();

                    //This case occurs only when NPCI gives UIDAI TIMEOUT response or when UIDType is UID token or VID as we unable to call vault store method 
                    //when using mentioned uidtype values
                    //if ((this._IsVaultEnabled == "Y" || this._IsVaultEnabled == "N") && string.IsNullOrWhiteSpace(ReferenceKey))
                    //{
                        if (_NPCIRequest.UIDType == AppConstants.UIDType.UIDTOKEN)
                        {
                            ekycXMLData.UIDToken = !string.IsNullOrWhiteSpace(ekycXMLData.UIDToken) ? ekycXMLData.UIDToken : _NPCIRequest.UID;
                            vaultData = GetReferencekeyOnNPCIUp(ref ekycXMLData, AppConstants.NPCIFailFlag, _ControllerName);
                        }
                        else if (_NPCIRequest.UIDType == AppConstants.UIDType.VID)
                        {
                            vaultData = GetReferencekeyOnNPCIUp(ref ekycXMLData, AppConstants.NPCIFailFlag, _ControllerName);
                        }

                    //}

                }
                else
                {
                    ekycXMLData.UIDAIErrorCode = ekycXMLData.ErrorCode;
                    ekycXMLData.UIDAIErrorDescription = ekycXMLData.ErrorDescription;

                    KycResponse result = new KycResponse("-1", Uref, ekycXMLData.UIDAIErrorCode, null, ekycXMLData.UIDAIErrorDescription);
                    response = result.TOXML();

                    vaultData = GetReferenceKeyonNPCIDown(ReferenceKey, _ControllerName);
                }
            }
        }
        else
        {
            ekycXMLData.ErrorCode = "SI438";
            ekycXMLData.ErrorDescription = "INVALID RESPONSE FROM NPCI";

            ekycXMLData.UIDAIErrorCode = ekycXMLData.ErrorCode;
            ekycXMLData.UIDAIErrorDescription = ekycXMLData.ErrorDescription;

            KycResponse result = new KycResponse("-1", "", ekycXMLData.UIDAIErrorCode, null, ekycXMLData.UIDAIErrorDescription);
            response = result.TOXML();

            vaultData = GetReferenceKeyonNPCIDown(ReferenceKey, _ControllerName);
        }
    }
    catch (Exception ex)
    {
        FileLogger.LogException(ex.Message, "ProcessNPCIGetDetailsResponse Exception", ReferenceNumber);

        ekycXMLData.ErrorCode = "SI001";
        ekycXMLData.ErrorDescription = "EXCEPTION WHILE PROCESSING THE RESPONSE";

        ekycXMLData.UIDAIErrorCode = ekycXMLData.ErrorCode;
        ekycXMLData.UIDAIErrorDescription = ekycXMLData.ErrorDescription;

        KycResponse result = new KycResponse("-1", "", ekycXMLData.UIDAIErrorCode, null, ekycXMLData.UIDAIErrorDescription);
        response = result.TOXML();

        vaultData = GetReferenceKeyonNPCIDown(ReferenceKey, _ControllerName);
    }
    return response;
}


private VaultData GetReferencekeyOnNPCIUp(ref EkycXMLData EkycXMLData, string NPCISuccessFlag, string _ControllerName)
{
    string VaultResponse = "";
    EKYCVaultProvider EVP = new EKYCVaultProvider();
    //ALWAYS GENERATE NEW VAULT REFENCE NUMBER
    string NewVaultReferenceNumber = "";
    NewVaultReferenceNumber = _ICommonRepository.GenerateReferenceNumber("SBISI");

    if (NPCISuccessFlag == AppConstants.NPCISuccessFlag)
    {
        if (!string.IsNullOrWhiteSpace(EkycXMLData.AadhaarNumber))
            vaultData = EVP.GetReferencekey(_sourceID, _NPCIRequest.ReferenceNumber, _NPCIRequest.UID, AppConstants.Vault.AadhaarDataType, _ControllerName, NewVaultReferenceNumber);
    }
    else if (NPCISuccessFlag == AppConstants.NPCIFailFlag)
    {
        if (_NPCIRequest.UIDType == AppConstants.UIDType.AadharNumber)
            vaultData = EVP.GetReferencekey(_sourceID, _NPCIRequest.ReferenceNumber, _NPCIRequest.UID, AppConstants.Vault.AadhaarDataType, _ControllerName, NewVaultReferenceNumber);
        if (_NPCIRequest.UIDType == AppConstants.UIDType.VID || (_NPCIRequest.UIDType == AppConstants.UIDType.UIDTOKEN && !string.IsNullOrWhiteSpace(EkycXMLData.UIDToken)))
            vaultData = EVP.GetReferencekey(_sourceID, _NPCIRequest.ReferenceNumber, _NPCIRequest.UID, AppConstants.Vault.UIDTokenDataType, _ControllerName, NewVaultReferenceNumber); 
    }

    return vaultData;
}


private VaultData GetReferenceKeyonNPCIDown(string Referencekey, string _ControllerName)
{   
    EKYCVaultProvider EVP = new EKYCVaultProvider();
    //ALWAYS GENERATE NEW VAULT REFENCE NUMBER
    string NewVaultReferenceNumber = "";
    NewVaultReferenceNumber = _ICommonRepository.GenerateReferenceNumber("SBISI");
    //if (this._IsVaultEnabled == "Y" || this._IsVaultEnabled == "N")
    //{
        if (string.IsNullOrWhiteSpace(Referencekey))
        {
            if (_NPCIRequest.UIDType == AppConstants.UIDType.UIDTOKEN)
                vaultData = EVP.GetReferencekey(_sourceID, _NPCIRequest.ReferenceNumber, _NPCIRequest.UID, AppConstants.Vault.UIDTokenDataType, _ControllerName,NewVaultReferenceNumber);
            if (_NPCIRequest.UIDType == AppConstants.UIDType.AadharNumber)
                vaultData = EVP.GetReferencekey(_sourceID, _NPCIRequest.ReferenceNumber,  _NPCIRequest.UID, AppConstants.Vault.AadhaarDataType, _ControllerName,NewVaultReferenceNumber);
        }
    //}

    return vaultData;
}

OTP


private string processGenerateOTPResponse(ref OtpXMLData OtpXMLData, string rrn, string ReferenceNumber)
{
    string response = string.Empty;

    try
    {
        OTPNpciResponse OTPNpciResponse = SICommonHelper.Deserialize<OTPNpciResponse>(OtpXMLData.NPCIResponseXML);

        if (OTPNpciResponse != null && OTPNpciResponse.TransactionInfoResponseOTPNPCI != null)
        {
            string Uref = "SBI" + OTPNpciResponse.TransactionInfoResponseOTPNPCI.RRN;
            String ResponseCode = OTPNpciResponse.TransactionInfoResponseOTPNPCI.ResponseCode;
            String ResponseMsg = OTPNpciResponse.TransactionInfoResponseOTPNPCI.ResponseMsg;

            ////if ResponseCode == 00 means No Error from NPCI
            //if (ResponseCode == "00")
            //{
            if (OTPNpciResponse.OtpRes != null)
            {
                // If ret is Y means match successful if N means match fail
                string ret = string.IsNullOrWhiteSpace(OTPNpciResponse.OtpRes.ret) ? string.Empty : OTPNpciResponse.OtpRes.ret.Trim().ToUpper();
                if (ret == "Y")
                {
                    OtpResponse result = new OtpResponse("0", Uref, null, OTPNpciResponse.OtpRes.txn, null);
                    response = result.TOXML();
                    OtpXMLData.ResponseXMLPlain = response;
                }
                else if (ret == "N")
                {
                    string err = !string.IsNullOrWhiteSpace(OTPNpciResponse.OtpRes.err) ? OTPNpciResponse.OtpRes.err.Trim() : string.Empty;
                    string errMsg = _ICommonRepository.GetErrorDescription(err);

                    OtpXMLData.ErrorCode = ResponseCode;
                    OtpXMLData.ErrorDescription = ResponseMsg;

                    OtpXMLData.UIDAIErrorCode = !string.IsNullOrWhiteSpace(err) ? err : ResponseCode;
                    OtpXMLData.UIDAIErrorDescription = !string.IsNullOrWhiteSpace(errMsg) ? errMsg : ResponseMsg;

                    OtpResponse result = new OtpResponse("-1", Uref, OtpXMLData.UIDAIErrorCode, null, OtpXMLData.UIDAIErrorDescription);
                    response = result.TOXML();

                    OtpXMLData.ResponseXMLPlain = response;
                }
                else
                {
                    OtpXMLData.ErrorCode = ResponseCode;
                    OtpXMLData.ErrorDescription = ResponseMsg;

                    OtpXMLData.UIDAIErrorCode = OtpXMLData.ErrorCode;
                    OtpXMLData.UIDAIErrorDescription = OtpXMLData.ErrorDescription;

                    OtpResponse result = new OtpResponse("-1", Uref, OtpXMLData.UIDAIErrorCode, null, OtpXMLData.UIDAIErrorDescription);
                    response = result.TOXML();
                    OtpXMLData.ResponseXMLPlain = response;
                }
            }
            else
            {
                OtpXMLData.ErrorCode = ResponseCode;
                OtpXMLData.ErrorDescription = ResponseMsg;

                OtpXMLData.UIDAIErrorCode = OtpXMLData.ErrorCode;
                OtpXMLData.UIDAIErrorDescription = OtpXMLData.ErrorDescription;

                OtpResponse result = new OtpResponse("-1", Uref, OtpXMLData.UIDAIErrorCode, null, OtpXMLData.UIDAIErrorDescription);
                response = result.TOXML();
                OtpXMLData.ResponseXMLPlain = response;
            }
        }
        else
        {
            OtpXMLData.ErrorCode = "SI438";
            OtpXMLData.ErrorDescription = "INVALID RESPONSE FROM NPCI";

            OtpXMLData.UIDAIErrorCode = OtpXMLData.ErrorCode;
            OtpXMLData.UIDAIErrorDescription = OtpXMLData.ErrorDescription;

            OtpResponse result = new OtpResponse("-1", "SBI" + rrn, OtpXMLData.UIDAIErrorCode, null, OtpXMLData.UIDAIErrorDescription);
            response = result.TOXML();
            OtpXMLData.ResponseXMLPlain = response;
        }
    }
    catch (Exception ex)
    {
        FileLogger.LogException(ex.Message, "processGenerateOTPResponse Exception", ReferenceNumber);

        OtpXMLData.ErrorCode = "SI001";
        OtpXMLData.ErrorDescription = "EXCEPTION WHILE PROCESSING THE RESPONSE";

        OtpXMLData.UIDAIErrorCode = OtpXMLData.ErrorCode;
        OtpXMLData.UIDAIErrorDescription = OtpXMLData.ErrorDescription;
        OtpResponse result = new OtpResponse("-1", "SBI" + rrn, "SI001", null, "EXCEPTION WHILE PROCESSING THE RESPONSE");
        response = result.TOXML();
    }
    return response;
}

AuthenticateAadhaar 

private string processNPCIAuthenticationResponse(ref DemoAuthXMLData xmlDataModel, string ReferenceNumber, ref string ReferenceKey, string TokenFromVault)
{
    string response = string.Empty;
    try
    {
        NPCIDemoResponse Response_demo = SICommonHelper.Deserialize<NPCIDemoResponse>(xmlDataModel.ResponseXMLEncrypted);

        if (Response_demo != null && Response_demo.TransactionInfoResponseDemoAuth != null)
        {
            String ResponseCode = Response_demo.TransactionInfoResponseDemoAuth.ResponseCode;
            String ResponseMsg = Response_demo.TransactionInfoResponseDemoAuth.ResponseMsg;

            ////if ResponseCode == 00 means No Error from NPCI
            //if (ResponseCode == "00")
            //{
            if (Response_demo.AuthResponse != null)
            {
                // If ret is Y means match successful if N means match fail
                string ret = string.IsNullOrWhiteSpace(Response_demo.AuthResponse.ret) ? string.Empty : Response_demo.AuthResponse.ret.Trim().ToUpper();
                string code = string.IsNullOrWhiteSpace(Response_demo.AuthResponse.code) ? string.Empty : Response_demo.AuthResponse.code.Trim().ToUpper();
                string tkn = string.Empty;
                if (!string.IsNullOrWhiteSpace(Response_demo.AuthResponse.info) && Response_demo.AuthResponse.info.Length <= int.MaxValue)
                {
                    int startIndex = Response_demo.AuthResponse.info.IndexOf('{') + 1;
                    int EndIndex = Response_demo.AuthResponse.info.IndexOf('}', startIndex);
                    var AuthResInfo = Response_demo.AuthResponse.info.Substring(startIndex, EndIndex - startIndex).Split(new char[] { ',' }, StringSplitOptions.None);
                    tkn = AuthResInfo.Length > 0 && AuthResInfo[0].Trim().ToUpper() != "NA" ? AuthResInfo[0] : string.Empty;
                    xmlDataModel.UIDToken = tkn;

                    //#region Store Aadhaar Data in Vault
                    //if (AppConstants.IsVaultEnabled == "Y" || AppConstants.IsVaultEnabled == "N")
                    //{
                    //    var storeAadhaarDataResponse = StoreAadhaarDataInVaultAfterNPCI(ref xmlDataModel, ref ReferenceKey, TokenFromVault);

                    //    if (storeAadhaarDataResponse.HasErrors) return response = xmlDataModel.ResponseXMLPlain;


                    //}
                    //#endregion
                }
                if (ret == "Y")
                {
                    AuthenticateAadhaarResponse result = new AuthenticateAadhaarResponse("00", "SUCCESS", tkn);
                    response = result.TOXML();
                    xmlDataModel.ResponseXMLPlain = response;

                }
                else if (ret == "N")
                {
                    string err = !string.IsNullOrWhiteSpace(Response_demo.AuthResponse.err) ? Response_demo.AuthResponse.err.Trim() : string.Empty;
                    string errMsg = _ICommonRepository.GetErrorDescription(err);


                    xmlDataModel.ErrorCode = ResponseCode;
                    xmlDataModel.ErrorDescription = ResponseMsg;

                    xmlDataModel.UIDAIErrorCode = !string.IsNullOrWhiteSpace(err) ? err : ResponseCode;
                    xmlDataModel.UIDAIErrorDescription = !string.IsNullOrWhiteSpace(errMsg) ? errMsg : ResponseMsg;

                    AuthenticateAadhaarResponse result = new AuthenticateAadhaarResponse(xmlDataModel.UIDAIErrorCode, xmlDataModel.UIDAIErrorDescription, tkn);
                    response = result.TOXML();

                    xmlDataModel.ResponseXMLPlain = response;
                }
                else
                {
                    xmlDataModel.ErrorCode = ResponseCode;
                    xmlDataModel.ErrorDescription = ResponseMsg;

                    xmlDataModel.UIDAIErrorCode = xmlDataModel.ErrorCode;
                    xmlDataModel.UIDAIErrorDescription = xmlDataModel.ErrorDescription;

                    AuthenticateAadhaarResponse result = new AuthenticateAadhaarResponse(xmlDataModel.UIDAIErrorCode, xmlDataModel.UIDAIErrorDescription, tkn);
                    response = result.TOXML();
                    xmlDataModel.ResponseXMLPlain = response;
                }

            }
            else
            {
                xmlDataModel.ErrorCode = ResponseCode;
                xmlDataModel.ErrorDescription = ResponseMsg;

                xmlDataModel.UIDAIErrorCode = xmlDataModel.ErrorCode;
                xmlDataModel.UIDAIErrorDescription = xmlDataModel.ErrorDescription;

                AuthenticateAadhaarResponse result = new AuthenticateAadhaarResponse(xmlDataModel.UIDAIErrorCode, xmlDataModel.UIDAIErrorDescription);
                response = result.TOXML();
                xmlDataModel.ResponseXMLPlain = response;
            }
        }
        else
        {
            xmlDataModel.ErrorCode = "SI438";
            xmlDataModel.ErrorDescription = "INVALID RESPONSE FROM NPCI";

            xmlDataModel.UIDAIErrorCode = xmlDataModel.ErrorCode;
            xmlDataModel.UIDAIErrorDescription = xmlDataModel.ErrorDescription;

            AuthenticateAadhaarResponse result = new AuthenticateAadhaarResponse(xmlDataModel.UIDAIErrorCode, xmlDataModel.UIDAIErrorDescription);
            response = result.TOXML();
            xmlDataModel.ResponseXMLPlain = response;
        }
    }
    catch (Exception ex)
    {
        FileLogger.LogException(ex.Message, "processNPCIAuthenticationResponse", ReferenceNumber);
        xmlDataModel.ErrorCode = "SI001";
        xmlDataModel.ErrorDescription = "EXCEPTION WHILE PROCESSING THE RESPONSE";
        xmlDataModel.UIDAIErrorCode = xmlDataModel.ErrorCode;
        xmlDataModel.UIDAIErrorDescription = xmlDataModel.ErrorDescription;

        AuthenticateAadhaarResponse result = new AuthenticateAadhaarResponse(xmlDataModel.UIDAIErrorCode, xmlDataModel.UIDAIErrorDescription);

        xmlDataModel.ResponseXMLPlain = result.TOXML();
        response = result.TOXML();
    }
    return response;
}





































import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class TimestampGenerator {

    public static String generateUIDAITimestamp() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
        return LocalDateTime.now().format(formatter);
    }

    // Example usage
    public static void main(String[] args) {
        String ts = generateUIDAITimestamp();
        System.out.println("Generated ts: " + ts);
    }
}









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
