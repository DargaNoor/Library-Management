// ================= STATIC CACHES (CLASS LEVEL) =================

private static final XMLSignatureFactory SIG_FACTORY =
        XMLSignatureFactory.getInstance("DOM");

private static final ThreadLocal<DocumentBuilderFactory> DBF =
        ThreadLocal.withInitial(() -> {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(true);
            return f;
        });

private static volatile KeyStore.PrivateKeyEntry PRIVATE_KEY_ENTRY;

// Load keystore ONCE only
private static KeyStore.PrivateKeyEntry loadKeyOnce(String propertiesPath) throws Exception {
    if (PRIVATE_KEY_ENTRY == null) {
        synchronized (CkycRequest.class) {
            if (PRIVATE_KEY_ENTRY == null) {
                PRIVATE_KEY_ENTRY = getKeyEntryFromKeystore(propertiesPath);
            }
        }
    }
    return PRIVATE_KEY_ENTRY;
}

// ================= SAFE SIGN FUNCTION =================

public static Document signUsingPrivateKey(
        String xmlDoc,
        boolean includeKeyInfo,
        String propertiesPath
) throws Exception {

    // 1️⃣ Parse XML (unavoidable, but optimized)
    DocumentBuilderFactory dbf = DBF.get();
    Document xmlDocument = dbf.newDocumentBuilder()
            .parse(new InputSource(new StringReader(xmlDoc)));

    // 2️⃣ Reference (SHA-256 OK)
    Reference ref = SIG_FACTORY.newReference(
            "",
            SIG_FACTORY.newDigestMethod(DigestMethod.SHA256, null),
            Collections.singletonList(
                    SIG_FACTORY.newTransform(
                            Transform.ENVELOPED,
                            (TransformParameterSpec) null)),
            null,
            null
    );

    // 3️⃣ SignedInfo (RSA-SHA1 kept as-is for compatibility)
    SignedInfo signedInfo = SIG_FACTORY.newSignedInfo(
            SIG_FACTORY.newCanonicalizationMethod(
                    CanonicalizationMethod.INCLUSIVE,
                    (C14NMethodParameterSpec) null),
            SIG_FACTORY.newSignatureMethod(
                    SignatureMethod.RSA_SHA1,   // keep as-is if system requires
                    null),
            Collections.singletonList(ref)
    );

    // 4️⃣ Load key ONLY ONCE
    KeyStore.PrivateKeyEntry keyEntry = loadKeyOnce(propertiesPath);
    if (keyEntry == null) {
        throw new MbUserException(
                "CkycRequest",
                "signUsingPrivateKey",
                "",
                "",
                "Private key entry not available",
                null
        );
    }

    X509Certificate cert =
            (X509Certificate) keyEntry.getCertificate();

    KeyInfo keyInfo = includeKeyInfo
            ? getKeyInfo(cert, SIG_FACTORY)
            : null;

    // 5️⃣ Sign (CPU-heavy but controlled)
    DOMSignContext signContext =
            new DOMSignContext(
                    keyEntry.getPrivateKey(),
                    xmlDocument.getDocumentElement()
            );

    XMLSignature signature =
            SIG_FACTORY.newXMLSignature(signedInfo, keyInfo);

    signature.sign(signContext);

    // 6️⃣ Return DOM (no extra copies)
    return xmlDocument;
}


































SignedInfo si = SIG_FACTORY.newSignedInfo(
    SIG_FACTORY.newCanonicalizationMethod(
        CanonicalizationMethod.INCLUSIVE,
        (C14NMethodParameterSpec) null
    ),
    SIG_FACTORY.newSignatureMethod(
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        null
    ),
    Collections.singletonList(ref)
);





import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.*;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.concurrent.Semaphore;
import java.util.Base64;

public class CKYCDownload_sys_JavaCompute extends MbJavaComputeNode {

    /* ---------- THREAD & LOAD CONTROL ---------- */
    private static final Semaphore CRYPTO_LIMIT = new Semaphore(40);

    /* ---------- CACHED FACTORIES ---------- */
    private static final XMLSignatureFactory SIG_FACTORY =
            XMLSignatureFactory.getInstance("DOM");

    private static final ThreadLocal<DocumentBuilderFactory> DBF =
            ThreadLocal.withInitial(() -> {
                DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
                f.setNamespaceAware(true);
                return f;
            });

    private static final ThreadLocal<TransformerFactory> TF =
            ThreadLocal.withInitial(TransformerFactory::newInstance);

    /* ---------- PRIVATE KEY CACHE ---------- */
    private static volatile PrivateKey PRIVATE_KEY;

    private static PrivateKey loadPrivateKeyOnce() throws Exception {
        if (PRIVATE_KEY == null) {
            synchronized (CKYCDownload_sys_JavaCompute.class) {
                if (PRIVATE_KEY == null) {

                    // 🔴 MOVE THIS TO PROPERTY FILE LATER
                    String base64PrivateKey =
                            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...";

                    byte[] decoded = Base64.getDecoder().decode(base64PrivateKey);
                    PKCS8EncodedKeySpec keySpec =
                            new PKCS8EncodedKeySpec(decoded);

                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    PRIVATE_KEY = kf.generatePrivate(keySpec);
                }
            }
        }
        return PRIVATE_KEY;
    }

    /* ---------- MAIN EXECUTION ---------- */
    @Override
    public void evaluate(MbMessageAssembly inAssembly) throws MbException {

        MbOutputTerminal out = getOutputTerminal("out");
        MbMessage outMessage = new MbMessage();
        MbMessageAssembly outAssembly =
                new MbMessageAssembly(inAssembly, outMessage);

        try {
            // 🔐 Prevent CPU & thread starvation
            CRYPTO_LIMIT.acquire();

            MbElement xmlElem =
                    inAssembly.getMessage().getRootElement().getLastChild();

            byte[] xmlBytes =
                    xmlElem.toBitstream(null, null, null, 0, 0, 0);

            String signedXml =
                    createDigitalSignature(new String(xmlBytes));

            MbElement outRoot = outMessage.getRootElement();
            MbElement parser =
                    outRoot.createElementAsLastChild("XMLNSC");

            parser.createElementAsLastChild(
                    MbElement.TYPE_NAME_VALUE,
                    "DigiSign",
                    signedXml
            );

            out.propagate(outAssembly);

        } catch (Exception e) {
            throw new MbUserException(
                    this, "evaluate", "", "", e.toString(), null);
        } finally {
            // ✅ THREAD IS ALWAYS RELEASED HERE
            CRYPTO_LIMIT.release();
        }
    }

    /* ---------- DIGITAL SIGNATURE ---------- */
    public String createDigitalSignature(String xml) throws Exception {

        DocumentBuilderFactory dbf = DBF.get();
        TransformerFactory tf = TF.get();

        Document doc =
                dbf.newDocumentBuilder()
                   .parse(new InputSource(new StringReader(xml)));

        Reference ref = SIG_FACTORY.newReference(
                "",
                SIG_FACTORY.newDigestMethod(DigestMethod.SHA256, null),
                Collections.singletonList(
                        SIG_FACTORY.newTransform(
                                Transform.ENVELOPED,
                                (TransformParameterSpec) null)),
                null,
                null
        );

        SignedInfo si = SIG_FACTORY.newSignedInfo(
                SIG_FACTORY.newCanonicalizationMethod(
                        CanonicalizationMethod.INCLUSIVE,
                        (C14NMethodParameterSpec) null),
                SIG_FACTORY.newSignatureMethod(
                        SignatureMethod.RSA_SHA256, null),
                Collections.singletonList(ref)
        );

        DOMSignContext signContext =
                new DOMSignContext(
                        loadPrivateKeyOnce(),
                        doc.getDocumentElement());

        XMLSignature signature =
                SIG_FACTORY.newXMLSignature(si, null);

        signature.sign(signContext);

        StringWriter sw = new StringWriter();
        Transformer t = tf.newTransformer();
        t.transform(new DOMSource(doc), new StreamResult(sw));

        return sw.toString();
    }
}




































var fs = require('fs');
var crypto = require('crypto');

var publicKey = fs.readFileSync('local:///publickey.pem');

var verify = crypto.createVerify('RSA-SHA256');
verify.update(PlainReq);

var ok = verify.verify(publicKey, Signature, 'base64');

session.output.write({valid: ok});


































<?xml version="1.0" encoding="UTF-8"?> 
<Configuration status="WARN">
    <Appenders>
        <RollingFile name="RollingFile" fileName="/tmp/ace_java.log"
                     filePattern="/tmp/ace_java-%d{yyyy-MM-dd}-%i.log.gz">
            <PatternLayout>
                <Pattern>%d{yyyy-MM-dd HH:mm:ss} %-5p [%t] %c - %m%n</Pattern>
            </PatternLayout>
            <Policies>
                <SizeBasedTriggeringPolicy size="10MB" />
                <TimeBasedTriggeringPolicy interval="1" />
            </Policies>
        </RollingFile>

        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="%d %-5p %c - %m%n" />
        </Console>
    </Appenders>

    <Loggers>
        <Root level="DEBUG">
            <AppenderRef ref="Console"/>
            <AppenderRef ref="RollingFile"/>
        </Root>
    </Loggers>
</Configuration>
















<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
    <Appenders>
        <RollingFile name="RollingFile" fileName="/tmp/ace_java.log"
                     filePattern="/tmp/ace_java-%d{yyyy-MM-dd}-%i.log.gz">
            <PatternLayout>
                <Pattern>%d{yyyy-MM-dd HH:mm:ss} %-5p [%t] %c - %m%n</Pattern>
            </PatternLayout>
            <Policies>
                <SizeBasedTriggeringPolicy size="10MB" />
                <TimeBasedTriggeringPolicy interval="1" />
            </Policies>
        </RollingFile>

        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="%d %-5p %c - %m%n" />
        </Console>
    </Appenders>

    <Loggers>
        <Root level="DEBUG">
            <AppenderRef ref="Console"/>
            <AppenderRef ref="RollingFile"/>
        </Root>
    </Loggers>
</Configuration>






























private String mapToJson(Map map) {

    StringBuilder sb = new StringBuilder();
    sb.append("{");

    boolean firstKey = true;

    for (Object objEntry : map.entrySet()) {

        Map.Entry entry = (Map.Entry) objEntry;

        String key = (entry.getKey() == null) ? "StatusLine" : entry.getKey().toString();

        if (!firstKey) sb.append(",");
        firstKey = false;

        sb.append("\"").append(escape(key)).append("\":");

        // value is List<String> BUT ACE treats it as raw List
        List values = (List) entry.getValue();

        sb.append("[");
        boolean firstVal = true;

        for (Object v : values) {
            if (!firstVal) sb.append(",");
            firstVal = false;

            sb.append("\"").append(escape(v.toString())).append("\"");
        }
        sb.append("]");
    }

    sb.append("}");
    return sb.toString();
}

private String escape(String s) {
    return s.replace("\\", "\\\\")
            .replace("\"", "\\\"");
}













private String mapToJson(Map<String, List<String>> map) {
    StringBuilder sb = new StringBuilder();
    sb.append("{");

    boolean firstKey = true;

    for (Map.Entry<String, List<String>> entry : map.entrySet()) {

        String key = entry.getKey();
        if (key == null) key = "StatusLine";

        if (!firstKey) sb.append(",");
        firstKey = false;

        sb.append("\"").append(escape(key)).append("\":");

        // Write array
        sb.append("[");
        boolean firstVal = true;
        for (String v : entry.getValue()) {
            if (!firstVal) sb.append(",");
            firstVal = false;

            sb.append("\"").append(escape(v)).append("\"");
        }
        sb.append("]");
    }

    sb.append("}");
    return sb.toString();
}

private String escape(String s) {
    return s.replace("\\", "\\\\")
            .replace("\"", "\\\"");
}import com.ibm.json.java.JSONObject;
import com.ibm.json.java.JSONArray;

Map<String, List<String>> headerMap = CONN.getHeaderFields();

JSONObject jsonHeaders = new JSONObject();

for (Map.Entry<String, List<String>> entry : headerMap.entrySet()) {

    String key = entry.getKey();
    List<String> values = entry.getValue();

    if (key == null) {
        key = "StatusLine";     // since null key not allowed in JSON
    }

    JSONArray arr = new JSONArray();
    arr.addAll(values);

    jsonHeaders.put(key, arr);
}

// Serialize to string
String headerJsonString = jsonHeaders.serialize();








}


















cREATE COMPUTE MODULE EmailBuild
    CREATE FUNCTION Main() RETURNS BOOLEAN
    BEGIN

        -- Create email body as text
        DECLARE bodyTxt CHARACTER 'This is a test email from IBM ACE.';

        CREATE LASTCHILD OF OutputRoot DOMAIN('BLOB')
            NAME 'BLOB' VALUE CAST(bodyTxt AS BLOB CCSID 1208);

        -- Email Subject
        SET OutputLocalEnvironment.Destination.Email.Subject = 'ACE Email Test';

        -- Recipient
        SET OutputLocalEnvironment.Destination.Email.To = 'someone@example.com';

        -- From address (OPTIONAL because EmailOutput node also has this)
        -- SET OutputLocalEnvironment.Destination.Email.From = 'dnoorali2015@gmail.com';

        RETURN TRUE;
    END;
END MODULE;

























import com.ibm.broker.config.proxy.PolicyManager;
import com.ibm.broker.config.proxy.UserDefinedPolicy;
import com.ibm.broker.config.proxy.MbService;

public void evaluate(MbMessageAssembly inAssembly) throws MbException {

    String policyProject = "MyRetryPolicies";   // MUST match project name
    String policyName = "RetryQueue";           // MUST match policy file name

    UserDefinedPolicy udp = (UserDefinedPolicy)
            PolicyManager.getPolicy(policyProject, "UserDefined", policyName);

    if (udp == null) {
        MbService.logWarning("RetryPolicy", "evaluate",
                "Policy not found: " + policyProject + "/" + policyName, null);
        throw new MbUserException(this, "evaluate", "", "", 
                "POLICY NULL", null);
    }

    String maxAttempts = udp.getPropertyValueAsString("maxAttempts");
    String interval = udp.getPropertyValueAsString("backoffInterval");

    MbService.logInfo("RetryPolicy", "evaluate",
            "maxAttempts=" + maxAttempts + " interval=" + interval, null);

    getOutputTerminal("out").propagate(inAssembly);
}










































public class RetryHandler extends MbJavaComputeNode {

    @Override
    public void evaluate(MbMessageAssembly inAssembly) throws MbException {

        MbOutputTerminal outRetry = getOutputTerminal("out");
        MbOutputTerminal outDLQ = getOutputTerminal("alternate");

        MbMessage inMessage = inAssembly.getMessage();
        MbMessage outMessage = new MbMessage(inMessage);
        MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly, outMessage);

        try {

            System.out.println("Retry Handler Invoked...");

            // FOLDER: Environment.Variables.Retry
            MbElement retryRoot = inAssembly.getLocalEnvironment().getRootElement()
                                             .getFirstElementByPath("Variables/Retry");

            if (retryRoot == null) {
                retryRoot = inAssembly.getLocalEnvironment().getRootElement()
                                      .getFirstElementByPath("Variables")
                                      .createElementAsLastChild(MbElement.TYPE_NAME, "Retry", null);

                retryRoot.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "Count", 1);
                retryRoot.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "Max", 3);
            }

            int count = retryRoot.getFirstElementByName("Count").getValueAsInt();
            int max   = retryRoot.getFirstElementByName("Max").getValueAsInt();

            if (count < max) {
                // Increase retry count
                retryRoot.getFirstElementByName("Count").setValue(count + 1);

                System.out.println("Retrying attempt " + (count + 1));

                outRetry.propagate(outAssembly);
            } else {
                System.out.println("Max retry reached → sending to DLQ terminal");
                outDLQ.propagate(outAssembly);
            }

        } catch (Exception e) {
            throw new MbUserException(this, "evaluate", "", "", e.toString(), null);
        }
    }
}








































var hm = require('header-math');

// Add security headers
hm.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
hm.setHeader('X-Frame-Options', 'DENY');
hm.setHeader('X-Content-Type-Options', 'nosniff');
hm.setHeader('Content-Security-Policy', "default-src 'self'");
hm.setHeader('Permissions-Policy', 'geolocation=(), microphone=()');
hm.setHeader('Referrer-Policy', 'no-referrer');

// OPTIONAL: Print them to log
console.error("Security headers added:", JSON.stringify(hm.listHeaders()));

// Return actual response body untouched
session.output.write(session.input.readAsBuffer());

































private static boolean slowEquals(byte[] a, byte[] b) {
    int diff = a.length ^ b.length;
    for (int i = 0; i < a.length && i < b.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

 





CREATE COMPUTE MODULE LoadErrorCache
CREATE FUNCTION Main() RETURNS BOOLEAN
BEGIN
    DECLARE jsonBlob BLOB ASBITSTREAM(InputRoot.BLOB.BLOB, CCSID InputProperties.CodedCharSetId);
    DECLARE jsonChar CHARACTER CAST(jsonBlob AS CHARACTER CCSID InputProperties.CodedCharSetId);
    DECLARE jsonRef REFERENCE TO InputRoot.JSON.Data;
    
    -- Parse JSON into local variable
    SET jsonRef = InputRoot.JSON.Data;
    
    -- Iterate and store in cache
    DECLARE key CHARACTER;
    DECLARE value CHARACTER;
    DECLARE mapRef REFERENCE TO jsonRef;
    MOVE mapRef FIRSTCHILD;
    WHILE LASTMOVE(mapRef) DO
        SET key = FIELDNAME(mapRef);
        SET value = FIELDVALUE(mapRef);
        CALL MbGlobalMapPut('ErrorMap', key, value);
        MOVE mapRef NEXTSIBLING;
    END WHILE;

    RETURN TRUE;
END;
END MODULE;

































import com.ibm.broker.plugin.*;

public class RetryHandler extends MbJavaComputeNode {

    @Override
    public void evaluate(MbMessageAssembly inAssembly) throws MbException {
        MbMessage inMessage = inAssembly.getMessage();
        MbMessage outMessage = new MbMessage(inMessage);
        MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly, outMessage);

        MbElement envRoot = outAssembly.getLocalEnvironment().getRootElement();
        MbElement props = outMessage.getRootElement().getFirstElementByPath("Properties");

        // 🔹 Try to get existing retry metadata
        MbElement retryConfig = envRoot.getFirstElementByPath("Variables/RetryConfig");
        int maxRetry = 0;
        int retryInterval = 0;

        if (retryConfig == null) {
            retryConfig = envRoot.createElementAsLastChild(MbElement.TYPE_NAME, "Variables", null)
                                 .createElementAsLastChild(MbElement.TYPE_NAME, "RetryConfig", null);

            // ✅ First attempt → fetch from policy
            MbPolicy policy = MbPolicy.getPolicy("UserDefined", "RetryPolicy");
            maxRetry = Integer.parseInt(policy.getPropertyValueAsString("maxRetryCount"));
            retryInterval = Integer.parseInt(policy.getPropertyValueAsString("retryInterval"));

            retryConfig.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "MaxRetryCount", maxRetry);
            retryConfig.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "RetryInterval", retryInterval);
        } else {
            maxRetry = Integer.parseInt(retryConfig.getFirstElementByPath("MaxRetryCount").getValueAsString());
            retryInterval = Integer.parseInt(retryConfig.getFirstElementByPath("RetryInterval").getValueAsString());
        }

        // 🔹 Handle Retry Count (Header-based)
        MbElement retryCountEl = props.getFirstElementByPath("RetryCount");
        int retryCount = 0;

        if (retryCountEl == null) {
            retryCount = 1;  // first try
        } else {
            retryCount = Integer.parseInt(retryCountEl.getValueAsString()) + 1;  // increment
        }

        // 🔹 Set updated retryCount in both Header & Environment
        props.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "RetryCount", retryCount);
        retryConfig.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "RetryCount", retryCount);

        // 🔹 Log or trace
        MbService.logInfo("RetryHandler", "evaluate",
                "Attempt " + retryCount + " of " + maxRetry + ", RetryInterval=" + retryInterval);

        // 🔹 Check max retry
        MbOutputTerminal out = getOutputTerminal("out");
        MbOutputTerminal fail = getOutputTerminal("alternate");

        if (retryCount <= maxRetry) {
            out.propagate(outAssembly);   // go to next compute / processing flow
        } else {
            fail.propagate(outAssembly);  // route to DLQ
        }
    }
}


































import com.ibm.broker.plugin.*;

public class RetryHandler extends MbJavaComputeNode {

    @Override
    public void evaluate(MbMessageAssembly inAssembly) throws MbException {
        MbMessage inMessage = inAssembly.getMessage();
        MbMessage outMessage = new MbMessage(inMessage);
        MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly, outMessage);

        MbElement envRoot = outAssembly.getLocalEnvironment().getRootElement();
        MbElement props = outMessage.getRootElement().getFirstElementByPath("Properties");

        // 🔹 Try to get existing retry metadata
        MbElement retryConfig = envRoot.getFirstElementByPath("Variables/RetryConfig");
        int maxRetry = 0;
        int retryInterval = 0;

        if (retryConfig == null) {
            retryConfig = envRoot.createElementAsLastChild(MbElement.TYPE_NAME, "Variables", null)
                                 .createElementAsLastChild(MbElement.TYPE_NAME, "RetryConfig", null);

            // ✅ First attempt → fetch from policy
            MbPolicy policy = MbPolicy.getPolicy("UserDefined", "RetryPolicy");
            maxRetry = Integer.parseInt(policy.getPropertyValueAsString("maxRetryCount"));
            retryInterval = Integer.parseInt(policy.getPropertyValueAsString("retryInterval"));

            retryConfig.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "MaxRetryCount", maxRetry);
            retryConfig.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "RetryInterval", retryInterval);
        } else {
            maxRetry = Integer.parseInt(retryConfig.getFirstElementByPath("MaxRetryCount").getValueAsString());
            retryInterval = Integer.parseInt(retryConfig.getFirstElementByPath("RetryInterval").getValueAsString());
        }

        // 🔹 Handle Retry Count (Header-based)
        MbElement retryCountEl = props.getFirstElementByPath("RetryCount");
        int retryCount = 0;

        if (retryCountEl == null) {
            retryCount = 1;  // first try
        } else {
            retryCount = Integer.parseInt(retryCountEl.getValueAsString()) + 1;  // increment
        }

        // 🔹 Set updated retryCount in both Header & Environment
        props.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "RetryCount", retryCount);
        retryConfig.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "RetryCount", retryCount);

        // 🔹 Log or trace
        MbService.logInfo("RetryHandler", "evaluate",
                "Attempt " + retryCount + " of " + maxRetry + ", RetryInterval=" + retryInterval);

        // 🔹 Check max retry
        MbOutputTerminal out = getOutputTerminal("out");
        MbOutputTerminal fail = getOutputTerminal("alternate");

        if (retryCount <= maxRetry) {
            out.propagate(outAssembly);   // go to next compute / processing flow
        } else {
            fail.propagate(outAssembly);  // route to DLQ
        }
    }
}



































CREATE COMPUTE MODULE RetryCompute
  CREATE FUNCTION Main() RETURNS BOOLEAN
  BEGIN
    DECLARE maxRetry INTEGER FIELDVALUE(InputRoot.Properties.MaxRetryCount);
    DECLARE retryInterval INTEGER FIELDVALUE(InputRoot.Properties.RetryInterval);

    -- Example usage
    CALL Log('Max Retries: ' || CAST(maxRetry AS CHARACTER));
    CALL Log('Retry Interval: ' || CAST(retryInterval AS CHARACTER));

    RETURN TRUE;
  END;
END MODULE;

















public class RetryHandler extends MbJavaComputeNode {

    @Override
    public void evaluate(MbMessageAssembly inAssembly) throws MbException {
        MbMessage inMessage = inAssembly.getMessage();
        MbMessage outMessage = new MbMessage(inMessage);
        MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly, outMessage);

        MbElement envRoot = inAssembly.getLocalEnvironment().getRootElement();

        // ✅ Check if already present (so we don’t re-read from policy every time)
        MbElement retryConfig = envRoot.getFirstElementByPath("Variables/RetryConfig");
        if (retryConfig == null) {
            retryConfig = envRoot.createElementAsLastChild(MbElement.TYPE_NAME, "Variables", null)
                                 .createElementAsLastChild(MbElement.TYPE_NAME, "RetryConfig", null);

            // --- Fetch from Policy only once ---
            MbPolicy policy = MbPolicy.getPolicy("UserDefined", "RetryPolicy");
            String maxRetryStr = policy.getPropertyValueAsString("maxRetryCount");
            String retryIntervalStr = policy.getPropertyValueAsString("retryInterval");

            retryConfig.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "MaxRetryCount", maxRetryStr);
            retryConfig.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "RetryInterval", retryIntervalStr);

            // ✅ Set in headers for downstream compute
            MbElement headers = inMessage.getRootElement().getFirstElementByPath("Properties");
            headers.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "MaxRetryCount", maxRetryStr);
            headers.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "RetryInterval", retryIntervalStr);
        }

        // ✅ Propagate to next node
        MbOutputTerminal out = getOutputTerminal("out");
        out.propagate(outAssembly);
    }
}



































CREATE COMPUTE MODULE PrepareEmail
  CREATE FUNCTION Main() RETURNS BOOLEAN
  BEGIN
    -- Read incoming event message (JSON)
    DECLARE jsonData REFERENCE TO InputRoot.JSON.Data;

    -- Create output structure for SMTP
    SET OutputRoot.MIME.Headers."Content-Type" = 'text/plain; charset=utf-8';

    -- FROM address (must match Gmail account used in SMTP security identity)
    SET OutputRoot.EmailOutputHeader.From = 'yourname@gmail.com';

    -- TO address (you can also read from jsonData if dynamic)
    SET OutputRoot.EmailOutputHeader.To = 'recipient@example.com';

    -- SUBJECT line
    SET OutputRoot.EmailOutputHeader.Subject = 'Customer Onboarding Successful';

    -- MESSAGE BODY
    SET OutputRoot.BLOB.BLOB = CAST(
      'Hello ' || COALESCE(jsonData.CustomerName, 'User') ||
      ',\n\nYour onboarding was successful!\n\nThank you,\nCustomer Support.'
      AS BLOB CCSID InputRoot.Properties.CodedCharSetId);

    RETURN TRUE;
  END;
END MODULE;







































CREATE COMPUTE MODULE RetryHandler
CREATE FUNCTION Main() RETURNS BOOLEAN
BEGIN
    DECLARE currentRetry INT;
    DECLARE maxRetry INT;
    DECLARE retryInterval INT;

    -- Read from Environment
    SET maxRetry = COALESCE(Environment.MaxRetryCount, 3);
    SET retryInterval = COALESCE(Environment.RetryInterval, 5000);

    -- Read from MQMD UserIdentifier or custom header (for count)
    SET currentRetry = COALESCE(CAST(InputRoot.Properties.RetryCount AS INTEGER), 0);
    SET currentRetry = currentRetry + 1;

    IF currentRetry <= maxRetry THEN
        -- Schedule next retry
        SET OutputRoot.MQMD.Expiry = retryInterval; -- can use MQRFH2 or timer queue logic
        SET OutputRoot.Properties.RetryCount = currentRetry;
        PROPAGATE TO TERMINAL 'RequeueOutput';
    ELSE
        -- Move to DLQ
        PROPAGATE TO TERMINAL 'DLQOutput';
    END IF;

    RETURN TRUE;
END;
END MODULE;
















CREATE COMPUTE MODULE MainLogic
CREATE FUNCTION Main() RETURNS BOOLEAN
BEGIN
    DECLARE shouldFail BOOLEAN TRUE; -- simulate failure
    IF shouldFail THEN
        THROW USER EXCEPTION CATALOG 'Retry' MESSAGE 1001 VALUES('Simulated failure');
    END IF;

    -- If success, pass to success output (MQOutput, etc.)
    RETURN TRUE;
END;
END MODULE;









import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.*;

public class SetRetryProperties extends MbJavaComputeNode {

    public void evaluate(MbMessageAssembly inAssembly) throws MbException {
        MbMessage inMessage = inAssembly.getMessage();
        MbMessage outMessage = new MbMessage(inMessage);
        MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly, outMessage);

        try {
            // Read retry parameters (hardcoded or load from file)
            int maxRetryCount = 3;        // e.g. from policy later
            int retryInterval = 5000;     // 5 seconds backoff

            MbElement root = outMessage.getRootElement();
            MbElement env = root.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "Environment", null);
            env.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "MaxRetryCount", maxRetryCount);
            env.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "RetryInterval", retryInterval);

            // propagate to next node (MainProcess)
            MbOutputTerminal out = getOutputTerminal("out");
            out.propagate(outAssembly);

        } catch (Exception e) {
            throw new MbUserException(this, "evaluate()", "", "", e.toString(), null);
        }
    }
}































import com.ibm.broker.javacompute.*;
import com.ibm.broker.plugin.*;

public class ReadPolicyAndDecide extends MbJavaComputeNode {

    @Override
    public void evaluate(MbMessageAssembly inAssembly) throws MbException {

        // Define two terminals for routing
        MbOutputTerminal outRetry = getOutputTerminal("outRetry");
        MbOutputTerminal outDLQ = getOutputTerminal("outDLQ");

        MbMessage inMessage = inAssembly.getMessage();
        MbMessage outMessage = new MbMessage(inMessage);
        MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly, outMessage);

        try {
            // ---- READ POLICY ----
            String policyProject = "retry";        // your policy project name
            String policyName = "retryqueue";      // your policy name

            MbPolicy policy = MbPolicyManager.getInstance()
                                  .getPolicy(policyProject, policyName, "UserDefined");

            // Read policy properties
            int maxAttempts = Integer.parseInt(policy.getPropertyValueAsString("maxAttempts"));
            int backoffMillis = Integer.parseInt(policy.getPropertyValueAsString("backoffMillis"));

            // ---- READ CURRENT ATTEMPT ----
            MbElement jsonData = outMessage.getRootElement().getFirstElementByPath("JSON/Data");
            int attempt = 0;

            if (jsonData != null && jsonData.getFirstElementByPath("retryAttempt") != null) {
                attempt = jsonData.getFirstElementByPath("retryAttempt").getValueAsInt();
            }

            // ---- APPLY BACKOFF (optional delay before next retry) ----
            if (attempt > 0 && backoffMillis > 0) {
                Thread.sleep(backoffMillis);  // delay next attempt
            }

            // ---- DECISION BASED ON ATTEMPT COUNT ----
            if (attempt < maxAttempts) {
                // Send to RETRY queue again
                outRetry.propagate(outAssembly);
            } else {
                // Mark as FAILED and send to DLQ
                jsonData.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "status", "FAILED");
                outDLQ.propagate(outAssembly);
            }

        } catch (InterruptedException ie) {
            throw new MbUserException(this, "evaluate()", "", "", "Backoff interrupted: " + ie, null);

        } catch (Exception e) {
            throw new MbUserException(this, "evaluate()", "", "", "Error: " + e.toString(), null);
        }
    }
}














CREATE COMPUTE MODULE Retry_Handler
  CREATE FUNCTION Main() RETURNS BOOLEAN
  BEGIN
    DECLARE maxAttempts INTEGER CAST(POLICY('RetryPolicy', 'UserDefined')['maxAttempts'] AS INTEGER);
    DECLARE backoff INTEGER CAST(POLICY('RetryPolicy', 'UserDefined')['backoffMillis'] AS INTEGER);

    DECLARE attempt INTEGER COALESCE(InputRoot.JSON.Data.retryAttempt, 0) + 1;

    IF attempt <= maxAttempts THEN
       SET OutputRoot.JSON.Data = InputRoot.JSON.Data;
       SET OutputRoot.JSON.Data.retryAttempt = attempt;
       PROPAGATE TO TERMINAL 'out';  -- goes to MQOutput(RETRY.Q)
    ELSE
       -- Max attempts reached → Send to DeadLetter queue
       SET OutputRoot.JSON.Data.status = 'FAILED';
       PROPAGATE TO TERMINAL 'alternate';
    END IF;
    RETURN FALSE;
  END;
END MODULE;

































DECLARE inString CHARACTER InputRoot.BLOB;  -- Or InputRoot.BLOB.BLOB depending on your flow
DECLARE str CHARACTER CAST(inString AS CHARACTER CCSID InputProperties.CodedCharSetId);

-- Extract substring starting from 136th character
DECLARE subStr CHARACTER SUBSTRING(str FROM 136);

-- Now split into tokens (amounts usually separated by space)
DECLARE amount1 CHARACTER TRIM(SUBSTRING(subStr FROM 1 FOR 20));  -- 1st amount (dynamic size)
DECLARE pos1 INT POSITION('.00' IN amount1) + 3; -- move after first amount
SET amount1 = TRIM(SUBSTRING(subStr FROM 1 FOR pos1));

DECLARE subStr2 CHARACTER SUBSTRING(subStr FROM pos1+1);
DECLARE pos2 INT POSITION('.00' IN subStr2) + 3;
DECLARE amount2 CHARACTER TRIM(SUBSTRING(subStr2 FROM 1 FOR pos2));

DECLARE subStr3 CHARACTER SUBSTRING(subStr2 FROM pos2+1);
DECLARE pos3 INT POSITION('.00' IN subStr3) + 3;
DECLARE amount3 CHARACTER TRIM(SUBSTRING(subStr3 FROM 1 FOR pos3));

-- Output to Environment or Debug
SET Environment.Variables.Amount1 = amount1;
SET Environment.Variables.Amount2 = amount2;
SET Environment.Variables.Amount3 = amount3;
















CREATE COMPUTE MODULE SetCorrelationId
    CREATE FUNCTION Main() RETURNS BOOLEAN
    BEGIN
        DECLARE ts CHAR CAST(CURRENT_TIMESTAMP AS CHAR FORMAT 'yyyyMMddHHmmssSSS');
        DECLARE rnd INT RAND() * 1000000;  -- Random 6-digit number
        DECLARE corrId CHAR ts || '_' || CAST(rnd AS CHAR);
        
        -- Store correlation id in Environment
        SET Environment.Variables.CorrelationId = corrId;
        
        -- Also add it to MQMD or HTTP headers for tracking
        IF EXISTS(OutputRoot.MQMD) THEN
            SET OutputRoot.MQMD.CorrelId = corrId;
        ELSE
            SET OutputRoot.Properties.CorrelationIdentifier = corrId;
        END IF;
        
        RETURN TRUE;
    END;
END MODULE;
























CREATE COMPUTE MODULE GenCorrelationIdAndSetup
CREATE FUNCTION Main() RETURNS BOOLEAN
BEGIN
    -- Generate Correlation ID
    DECLARE corrId CHAR CAST(UUIDASCHAR(UUID()) AS CHAR);

    -- Store Correlation ID in LocalEnvironment for Aggregate
    SET LocalEnvironment.Destination.AggregateControl.ReplyIdentifier = corrId;

    -- Setup 3 MQ destinations
    DECLARE idx INT 1;
    
    SET LocalEnvironment.Destination.MQ.DestinationData[idx].queueName = 'KYC.Q';
    SET LocalEnvironment.Destination.MQ.DestinationData[idx].queueManagerName = 'QM1';
    SET idx = idx + 1;

    SET LocalEnvironment.Destination.MQ.DestinationData[idx].queueName = 'CREDIT.Q';
    SET LocalEnvironment.Destination.MQ.DestinationData[idx].queueManagerName = 'QM1';
    SET idx = idx + 1;

    SET LocalEnvironment.Destination.MQ.DestinationData[idx].queueName = 'RISK.Q';
    SET LocalEnvironment.Destination.MQ.DestinationData[idx].queueManagerName = 'QM1';

    -- Optionally add metadata in message
    SET OutputRoot = InputRoot;
    SET OutputRoot.Properties.CorrelationIdentifier = corrId;

    RETURN TRUE;
END;
END MODULE;


CREATE COMPUTE MODULE MergeResults
CREATE FUNCTION Main() RETURNS BOOLEAN
BEGIN
    -- Prepare JSON output
    CREATE LASTCHILD OF OutputRoot DOMAIN('JSON');
    SET OutputRoot.JSON.Data.AllResponses[] = '';

    -- KYC Response
    IF EXISTS(InputRoot.XMLNSC.AggReply.KYCResponse) THEN
        SET OutputRoot.JSON.Data.KYC = InputRoot.XMLNSC.AggReply.KYCResponse;
    END IF;

    -- Credit Response
    IF EXISTS(InputRoot.XMLNSC.AggReply.CreditResponse) THEN
        SET OutputRoot.JSON.Data.Credit = InputRoot.XMLNSC.AggReply.CreditResponse;
    END IF;

    -- Risk Response
    IF EXISTS(InputRoot.XMLNSC.AggReply.RiskResponse) THEN
        SET OutputRoot.JSON.Data.Risk = InputRoot.XMLNSC.AggReply.RiskResponse;
    END IF;

    RETURN TRUE;
END;
END MODULE;


CREATE COMPUTE MODULE TimeoutHandler
CREATE FUNCTION Main() RETURNS BOOLEAN
BEGIN
    CREATE LASTCHILD OF OutputRoot DOMAIN('JSON');
    SET OutputRoot.JSON.Data.Status = 'Partial Response - Timeout Occurred';
    SET OutputRoot.JSON.Data.CorrelationId = InputRoot.Properties.CorrelationIdentifier;
    RETURN TRUE;
END;
END MODULE;


{
  "customerId": "CUST12345",
  "loanAmount": 250000,
  "currency": "INR",
  "products": ["KYC", "CREDIT", "RISK"]
}

































***BROKER CREATION**

7 mqsicreatebroker JANSURAKSHA SYS -q QM JANSURAKSHA SYS

mqsicreateexecutiongroup JANSURAKSHA SYS JANSURAKSHA_SYS_S_01

mqsireportproperties JANSURAKSHA SYS -JANSURAKSHA SYS S 01-o ComIbmCacheManager -

mqsichangeproperties JANSURAKSHA SYS -JANSURAKSHA SYS S 01 -JSON -n disableSchemaLookupExceptionWhen v notSpecified

mqsichangeproperties JANSURAKSHA SYS -JANSURAKSHA_SYS_S_01 -GlobalCache -n cacheon v true

2 mqsichangeproperties JANSURAKSHA SYS -JANSURAKSHA SYS S 01 -GlobalCache -n catalogClusterEndPoints

-v \"HEART BEAT_localhost_2840:localhost:2843:2841, HEART BEAT localhost 2844:localhost:2847:2845, CACHE localhost 3120:localhost:3123:3121\"

mqsichangeproperties JANSURAKSHA SYS - JANSURAKSHA_SYS_S_01 -GlobalCache -n catalog DomainName -v

3 localhost 2840 HEART BEAT 'WMB CACHE localhost 3120 HEART BEAT localhost 2844'

4 mqsichangeproperties JANSURAKSHA SYS JANSURAKSHA SYS S 01 -GlobalCache -n catalogserviceEndPoints -v \"localhost:2840, localhost:2844, localhost:3120\"

mqsichangeproperties JANSURAKSHA SYS JANSURAKSHA SYS_S_01 -GlobalCache -n listenerHost v localhost

7 mqsichangeproperties JANSURAKSHA_SYS -

5 6 mqsichangeproperties JANSURAKSHA SYS -JANSURAKSHA SYS_S_01 -HTTPConnector -n ConnBacklog -v 1000*

8mqsichangeproperties JANSURAKSHA SYS -JANSURAKSHA SYS S 01-0 JVM -n jvmMaxHeapSize -v '100663296 JANSURAKSHA_SYS_S 01-o JVM-n jvmMinHeapSize -v 100663296'

9mqsichangeproperties JANSURAKSHA SYS JANSURAKSHA SYS S 01 HTTPConnector in QueueCapacity v '1000'

To Check/assign Port for Broker****

1 mqsireportproperties JANSURAKSHA SYS-b httplistener -o HTTPConnector -r 2 mqsichangeproperties JANSURAKSHA SYS-b httplistener - HTTPConnector - port - 5055'

3********O Check/set keystores*****

4 mqsireportproperties JANSURAKSHA SYS -o BrokerRegistry -r

I

5 mqsichangeproperties JANSURAKSHA SYS -o BrokerRegistry -n brokerKeystoreFile -v /opt/IBM/Broker_Properties/JKS/EISBRK10 PROD NI KEYSTORE.jks

6mqsichangeproperties JANSURAKSHA SYS -o BrokerRegistry n brokerTruststoreFile -v /opt/IBM/Broker_Properties/JKS/EISBRK10 PROD N1 TRUSTSTORE.jks

7********Check DB Connectivity/Configure****

8 mqsicvp JANSURAKSHA SYS - SI

5 mqsisetdbparms JANSURAKSHA SYS U EISAPP -P EISAPP - SI

10 mqsisetdbparms JANSURAKSHA SYS -n brokerKeystore::password -u NA -p password

1 mqsisetdbparms JANSURAKSHA SYS -n brokerTruststore::password -u NA -p password




















using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

public class AESGCMEncryption
{
    // Encrypt message using AES-GCM
    public static string AESEncrypt_GCM(string message, string key)
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
            throw new ArgumentException("Key must be 16, 24, or 32 bytes.");

        // Generate random 12-byte IV
        byte[] iv = new byte[12];
        new Random().NextBytes(iv);

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(message);

        GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
        AeadParameters parameters = new AeadParameters(new KeyParameter(keyBytes), 128, iv, null);
        cipher.Init(true, parameters);

        byte[] ciphertextBytes = new byte[cipher.GetOutputSize(plaintextBytes.Length)];
        int len = cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, ciphertextBytes, 0);
        cipher.DoFinal(ciphertextBytes, len);

        // Combine IV + ciphertext
        byte[] finalBytes = new byte[iv.Length + ciphertextBytes.Length];
        Array.Copy(iv, 0, finalBytes, 0, iv.Length);
        Array.Copy(ciphertextBytes, 0, finalBytes, iv.Length, ciphertextBytes.Length);

        return Convert.ToBase64String(finalBytes);
    }

    // Decrypt AES-GCM message
    public static string AESDecrypt_GCM(string base64Ciphertext, string key)
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
            throw new ArgumentException("Key must be 16, 24, or 32 bytes.");

        byte[] inputBytes = Convert.FromBase64String(base64Ciphertext);

        // Extract IV (12 bytes)
        byte[] iv = new byte[12];
        Array.Copy(inputBytes, 0, iv, 0, iv.Length);

        // Extract ciphertext+tag
        byte[] ciphertextBytes = new byte[inputBytes.Length - iv.Length];
        Array.Copy(inputBytes, iv.Length, ciphertextBytes, 0, ciphertextBytes.Length);

        GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
        AeadParameters parameters = new AeadParameters(new KeyParameter(keyBytes), 128, iv, null);
        cipher.Init(false, parameters);

        byte[] plainBytes = new byte[cipher.GetOutputSize(ciphertextBytes.Length)];
        int len = cipher.ProcessBytes(ciphertextBytes, 0, ciphertextBytes.Length, plainBytes, 0);
        cipher.DoFinal(plainBytes, len);

        return Encoding.UTF8.GetString(plainBytes).TrimEnd('\0');
    }

    // Demo
    public static void Main()
    {
        string key = "12345678901234567890123456789012"; // 32-byte key
        string message = "Hello AES-GCM from C#!";

        string encrypted = AESEncrypt_GCM(message, key);
        Console.WriteLine("Encrypted: " + encrypted);

        string decrypted = AESDecrypt_GCM(encrypted, key);
        Console.WriteLine("Decrypted: " + decrypted);
    }
}









<xsd:element name="NOMINEE_DETALIS" dfdl:occursCountKind="expression"
             maxOccurs="9"
             dfdl:occursCount="{ xs:int(NUMBER_OF_NOMINEES) }">
    <xsd:complexType>
        <xsd:sequence>
            <!-- Nominee fields -->
            <xsd:element name="SEQUENCE" dfdl:length="1" type="xsd:string"/>
            <!-- ... rest of your nominee fields ... -->
            <xsd:element name="GAURDIANS_ADDRESS_2" dfdl:length="40" type="xsd:string"/>
            
            <!-- Conditional filler: only if this is the 3rd nominee -->
            <xsd:element name="FILLER" dfdl:length="1491" type="xsd:string"
                         dfdl:inputValueCalc='{ if (../SEQUENCE = "3") then "" else fn:error() }'
                         minOccurs="0"/>
        </xsd:sequence>
    </xsd:complexType>
</xsd:element>

vv

<?xml version="1.0" encoding="UTF-8" standalone="no"?> <xsd:schema xmlns:dfdl="http://www.ogf.org/dfdl/dfdl-1.0/" xmlns:fn="http://www.w3.org/2005/xpath-functions" xmlns:ibmDfdlExtn="http://www.ibm.com/dfdl/extensions" xmlns:ibmSchExtn="http://www.ibm.com/schema/extensions" xmlns:recFixLengthFieldsFmt="http://www.ibm.com/dfdl/RecordFixLengthFieldFormat" xmlns:xsd="http://www.w3.org/2001/XMLSchema"> <xsd:import namespace="http://www.ibm.com/dfdl/RecordFixLengthFieldFormat" schemaLocation="IBMdefined/RecordFixLengthFieldFormat.xsd"/> <xsd:annotation>	 <xsd:appinfo source="http://www.ogf.org/dfdl/">		 <dfdl:format encoding="{$dfdl:encoding}" escapeSchemeRef="" occursCountKind="fixed" ref="recFixLengthFieldsFmt:RecordFixLengthFieldsFormat"/>	 </xsd:appinfo> </xsd:annotation> <xsd:element dfdl:lengthKind="delimited" ibmSchExtn:docRoot="true" name="Request">	 <xsd:complexType>		 <xsd:sequence dfdl:separator="%CR;%LF;%WSP*;" dfdl:separatorSuppressionPolicy="anyEmpty">			 <xsd:element dfdl:initiator="" dfdl:lengthKind="delimited" name="body">				 <xsd:complexType><xsd:sequence>						 <xsd:element dfdl:length="5" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" ibmDfdlExtn:sampleValue="body_valu1" name="MSGLength" type="xsd:string"/>						 <xsd:element dfdl:length="37" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" ibmDfdlExtn:sampleValue="body_valu2" name="reqMetaData1" type="xsd:string"/>						 <xsd:element dfdl:length="5" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" ibmDfdlExtn:sampleValue="body_valu3" name="BRANCH_CODE" type="xsd:string"/><xsd:element dfdl:length="3" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" name="reqMetaData2" type="xsd:string"/> <xsd:element dfdl:length="7" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" name="REQ_TELLER_ID" type="xsd:string"/> <xsd:element dfdl:length="6" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" name="transactioncode" type="xsd:string"/> <xsd:element dfdl:length="20" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" name="reqMetaData3" type="xsd:string"/> <xsd:element dfdl:length="1" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" name="batchTandem" type="xsd:string"/> <xsd:element dfdl:length="3" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" name="reqMetaData4" type="xsd:string"/> <xsd:element dfdl:length="1" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" name="checkerFlag" type="xsd:string"/><xsd:element dfdl:length="7" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" name="SUPERVISOR_ID" type="xsd:string"/> <xsd:element dfdl:length="8" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" name="dateandtime" type="xsd:string"/> <xsd:element dfdl:length="7" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" name="CHECKER_ID_1" type="xsd:string"/> <xsd:element dfdl:length="8" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" name="META_DATA_5" type="xsd:string"/> <xsd:element dfdl:length="7" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" name="CHECKER_ID_2" type="xsd:string"/> <xsd:element dfdl:length="8" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" name="FEJNumber" type="xsd:string"/> <xsd:element dfdl:length="1" dfdl:textPadKind="padChar" dfdl:textStringJustification="left" dfdl:textStringPadCharacter="%SP;" dfdl:textTrimKind="none" name="GOV_FLAG" type="xsd:string"/> <xsd:element dfdl:length="17" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" name="ACCOUNT_NUMBER" type="xsd:string"/> <xsd:element dfdl:length="1" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" name="NUMBER_OF_NOMINEES" type="xsd:string"/> <xsd:element dfdl:length="3" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" name="TOTAL_NOMINEE_PERCENTAGE" type="xsd:string"/> <xsd:element dfdl:lengthKind="implicit" dfdl:occursCountKind="implicit" maxOccurs="9" name="NOMINEE_DETALIS"> <xsd:complexType> <xsd:sequence> <xsd:element default="" dfdl:length="1" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" name="SEQUENCE" type="xsd:string"/> <xsd:element default="" dfdl:length="40" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" name="NAME_OF_THE_NOMINEE" type="xsd:string"/> <xsd:element default="" dfdl:length="1" dfdl:textPadKind="padChar" dfdl:textStringJustification="left" dfdl:textStringPadCharacter="%SP;" dfdl:textTrimKind="none" name="NAME_TO_BE_PRINTED" type="xsd:string"/> <xsd:element default="" dfdl:length="8" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" name="DATE_OF_BIRTH" type="xsd:string"/> <xsd:element default="" dfdl:length="10" dfdl:textPadKind="padChar" dfdl:textStringJustification="left" dfdl:textStringPadCharacter="%SP;" dfdl:textTrimKind="none" name="RELATIONSHIP" type="xsd:string"/> <xsd:element default="" dfdl:length="1" dfdl:textPadKind="padChar" dfdl:textStringJustification="left" dfdl:textStringPadCharacter="%SP;" dfdl:textTrimKind="none" name="MINOR" type="xsd:string"/> <xsd:element default="" dfdl:fillByte="0" dfdl:length="60" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" name="NOMINEES_ADDRESS" type="xsd:string"/> <xsd:element default="" dfdl:length="3" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" name="NOMINEE_PERCENTAGE" type="xsd:string"/> <xsd:element default="" dfdl:length="1" dfdl:textPadKind="padChar" dfdl:textStringJustification="left" dfdl:textStringPadCharacter="%SP;" dfdl:textTrimKind="none" name="NATURE_OF_ENTITLEMENT" type="xsd:string"/> <xsd:element default="" dfdl:fillByte="0" dfdl:length="17" dfdl:textPadKind="padChar" dfdl:textStringJustification="left" dfdl:textStringPadCharacter="%SP;" dfdl:textTrimKind="none" name="AADHAAR_VRN" type="xsd:string"/> <xsd:element default="" dfdl:length="40" dfdl:textPadKind="padChar" dfdl:textStringJustification="left" dfdl:textStringPadCharacter="%SP;" dfdl:textTrimKind="none" name="GAURDIANS_NAME" type="xsd:string"/> <xsd:element default="" dfdl:length="2" dfdl:textPadKind="padChar" dfdl:textStringJustification="right" dfdl:textStringPadCharacter="0" dfdl:textTrimKind="none" ibmDfdlExtn:sampleValue="" name="GAURDIANS_AGE" type="xsd:string"/> <xsd:element default="" dfdl:length="40" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" name="GAURDIANS_ADDRESS_1" type="xsd:string"/> <xsd:element default="" dfdl:length="40" dfdl:textPadKind="padChar" dfdl:textTrimKind="none" name="GAURDIANS_ADDRESS_2" type="xsd:string"/> </xsd:sequence> </xsd:complexType> </xsd:element> </xsd:sequence>				 </xsd:complexType>			 </xsd:element> </xsd:sequence>	 </xsd:complexType> </xsd:element> </xsd:schema>










- gateway-script:
    title: Validate AccessToken Header
    source: |
      var accessToken = apim.getvariable('request.headers.AccessToken');
      if (!accessToken) {
        throw {
          status: 400,
          message: 'Missing AccessToken in request headers'
        };
      }




  - switch:
    title: Decide Which XSL
    case:
      - condition: some_condition_here
        execute:
          - xslt:
              location: local:///xsl/route_for_accounts.xsl
      - condition: another_condition
        execute:
          - xslt:
              location: local:///xsl/route_for_cards.xsl

















  - validate:
    title: validate-all-body-fields
    version: 2.7.0
    validate-against: body-param
    validate:
      - location: body
        name: RRN
        required: true
      - location: body
        name: DIGI_SIGN
        required: true
      - location: header
        name: access_token
        required: true
  catch:
    - gateway-script:
        title: handle-validate-errors
        source: |
          var apimError = apim.getvariable('apim.error');
          var detail = apimError && apimError.error && apimError.error.detail || '';
          var message = "Validation failed";
          var code = "invalid_request";

          if (detail.indexOf("RRN") !== -1) {
              message = "RRN is missing in request body";
              code = "missing_rrn";
          } else if (detail.indexOf("DIGI_SIGN") !== -1) {
              message = "DIGI_SIGN is missing in request body";
              code = "missing_digisign";
          } else if (detail.indexOf("access_token") !== -1) {
              message = "Access token header is missing";
              code = "missing_access_token";
          }

          response.statusCode = 400;
          response.headers['Content-Type'] = 'application/json';
          response.body = JSON.stringify({
              error: code,
              message: message
          });
          session.output.write(response);











      assembly:
  execute:
    - invoke:
        title: Validate Headers
        version: 1.0.0
        verb: get
        target-url: 'https://mockbackend/validate'
        timeout: 5000

    - gatewayscript:
        title: Extract AccessToken Header
        source: |
          var token = apim.getvariable('request.headers.accessToken');
          apim.setvariable('context.encryptedToken', token);

    - xslt:
        title: Decrypt AccessToken using XSLT
        version: 1.0.0
        source: |
          <?xml version="1.0" encoding="UTF-8"?>
          <xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
              xmlns:dp="http://www.datapower.com/extensions"
              extension-element-prefixes="dp">

              <xsl:template match="/">
                  <xsl:variable name="encToken" select="dp:variable('context/encryptedToken')"/>
                  <xsl:variable name="decrypted" select="dp:decrypt($encToken, 'rsa', 'EISPRIVATE')"/>
                  <dp:set-variable name="'context/AccessToken'" value="$decrypted"/>
              </xsl:template>
          </xsl:stylesheet>

    - gatewayscript:
        title: Validate Body and Token
        source: |
          var token = apim.getvariable('context.AccessToken');
          var body = apim.getvariable('request.body');
          if (!token || !body || body.length === 0) {
            apim.setvariable('message.status.code', 400);
            apim.setvariable('message.body', { error: "Missing or invalid accessToken/body" });
            apim.stop();
          }

    - invoke:
        title: Proceed to Backend
        verb: post
        target-url: 'https://backend/api/secure'
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        CREATE COMPUTE MODULE PadStringToLength
CREATE FUNCTION Main() RETURNS BOOLEAN
BEGIN
    DECLARE originalString CHARACTER 'HELLO ACE'; -- Your input string
    DECLARE targetLength INTEGER 1000;            -- Desired total length
    DECLARE currentLength INTEGER LENGTH(originalString);
    DECLARE spacesToAdd INTEGER targetLength - currentLength;
    DECLARE paddedString CHARACTER '';

    -- Add spaces only if needed
    IF spacesToAdd > 0 THEN
        SET paddedString = originalString || SPACE(spacesToAdd);
    ELSE
        -- If original string is already >= target length, trim it
        SET paddedString = SUBSTRING(originalString FROM 1 FOR targetLength);
    END IF;

    -- Output padded string to Environment for demo
    SET Environment.Variables.PaddedString = paddedString;
    RETURN TRUE;
END;
END MODULE;










public class Main {
    public static void main(String[] args) {
        String dataString = "[{\"seqNo\":\"SEQN0001\",\"DataType\":\"UID\",\"Data\":\"507339736890\",\"DataHashFormat\":\"U\"},{\"seqNo\":\"SEQN0002\",\"DataType\":\"RefKey\",\"Data\":\"2819pVxvXhII\",\"DataHashFormat\":\"I\"}]";

        dataString = dataString.trim();
        if (dataString.startsWith("[") && dataString.endsWith("]")) {
            dataString = dataString.substring(1, dataString.length() - 1);
            String[] elements = splitJsonArray(dataString);
            StringBuilder output = new StringBuilder("[");
            for (int i = 0; i < elements.length; i++) {
                String element = elements[i];
                int dataIndex = element.indexOf("\"Data\":\"");
                if (dataIndex != -1) {
                    int dataValueStart = dataIndex + "\"Data\":".length() + 1;
                    int dataValueEnd = element.indexOf("\"", dataValueStart);
                    if (dataValueEnd != -1) {
                        String dataValue = element.substring(dataValueStart, dataValueEnd);
                        String maskedData = maskData(dataValue);
                        String modifiedElement = element.replace("\"Data\":\"" + dataValue + "\"", "\"Data\":\"" + maskedData + "\"");
                        output.append(modifiedElement);
                    } else {
                        output.append(element); // In case of unexpected format, output original
                    }
                } else {
                    output.append(element); // If no "Data" field, output original
                }
                if (i < elements.length - 1) {
                    output.append(",");
                }
            }
            output.append("]");
            System.out.println("Output: " + output.toString());
        }
    }

    private static String[] splitJsonArray(String jsonArray) {
        jsonArray = jsonArray.trim();
        if (jsonArray.isEmpty()) {
            return new String[0];
        }
        String[] elements = jsonArray.split("\\},\\{");
        for (int i = 0; i < elements.length; i++) {
            if (!elements[i].startsWith("{")) {
                elements[i] = "{" + elements[i];
            }
            if (!elements[i].endsWith("}")) {
                elements[i] = elements[i] + "}";
            }
        }
        return elements;
    }

    private static String maskData(String data) {
        if (data.length() > 9) {
            return "*********" + data.substring(9);
        } else if (data.length() == 9) {
            return "*********";
        } else {
            return "*".repeat(data.length());
        }
    }
}



























private static String manualGetJsonValue(String json, String key) {
    int startIndex = json.indexOf("\"" + key + "\"");
    if (startIndex == -1) return null;
    startIndex = json.indexOf(":", startIndex) + 1;
    while (startIndex < json.length() && json.charAt(startIndex) == ' ') startIndex++;
    if (startIndex >= json.length()) return null;
    int endIndex = startIndex;
    if (json.charAt(startIndex) == '"') {
        startIndex++;
        endIndex = json.indexOf("\"", startIndex);
    } else {
        endIndex = json.indexOf(",", startIndex);
        if (endIndex == -1) endIndex = json.indexOf("}", startIndex);
    }
    if (endIndex == -1) endIndex = json.length();
    return json.substring(startIndex, endIndex);
}







public class Main {
    public static void main(String[] args) {
        // Example string representing the data array in JSON format
        String dataString = "[{\"seqNo\":\"SEQN0001\",\"DataType\":\"UID\",\"Data\":\"507339736890\",\"DataHashFormat\":\"U\"},{\"seqNo\":\"SEQN0002\",\"DataType\":\"RefKey\",\"Data\":\"2819pVxvXhII\",\"DataHashFormat\":\"I\"}]";

        // Manually parse the JSON array
        dataString = dataString.trim();
        if (dataString.startsWith("[") && dataString.endsWith("]")) {
            dataString = dataString.substring(1, dataString.length() - 1);
            String[] elements = splitJsonArray(dataString);
            for (String element : elements) {
                String dataValue = manualGetJsonValue(element, "Data");
                if (dataValue != null) {
                    String maskedData = maskData(dataValue);
                    System.out.println("Data tag name with masked value: " + maskedData);
                }
            }
        }
    }

    private static String[] splitJsonArray(String jsonArray) {
        // Simple manual splitter for JSON array elements
        jsonArray = jsonArray.trim();
        if (jsonArray.isEmpty()) {
            return new String[0];
        }
        String[] elements = jsonArray.split("\\},\\{");
        for (int i = 0; i < elements.length; i++) {
            if (!elements[i].startsWith("{")) {
                elements[i] = "{" + elements[i];
            }
            if (!elements[i].endsWith("}")) {
                elements[i] = elements[i] + "}";
            }
        }
        return elements;
    }

    private static String manualGetJsonValue(String json, String key) {
        // Manual JSON value extractor
        int index = json.indexOf("\"" + key + "\":\"");
        if (index == -1) {
            return null;                 
        }
        index += key.length() + 3;                             
        int endIndex = json.indexOf("// Key not found
        }
        index += key.length() + 3; // Move past the key and ":"
        int endIndex = json.indexOf("\"", index);
        if (endIndex == -1) {
            return null; // End quote not found
        }
        return json.substring(index, endIndex);
    }

    private static String maskData(String data) {
        if (data.length() > 9) {
            return "*********" + data.substring(9);
        } else if (data.length() == 9) {
            return "*********";
        } else {
            // For data shorter than 9 characters, mask all
            return "*".repeat(data.length());
        }
    }
}









lllllllllllll










public class Main {
    public static void main(String[] args) {
        String jsonString = "{\"purseInfoList\":{\"purseInfo\":[{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"AED\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"CAD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"AUD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"EUR\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"USD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"GBP\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"SGD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"}]}}";

        // Manually extract the "purseInfo" array block
        String purseInfoArrayRaw = extractArray(jsonString, "\"purseInfo\":[");

        // Split individual JSON objects
        String[] purseInfos = splitJsonArray(purseInfoArrayRaw);

        // Prepare value arrays
        String[] purseId = new String[purseInfos.length];
        String[] purseCurrency = new String[purseInfos.length];
        String[] purseAvailableBalance = new String[purseInfos.length];
        String[] purseCurrentBalance = new String[purseInfos.length];
        String[] purseStatus = new String[purseInfos.length];

        // Fill arrays from each object
        for (int i = 0; i < purseInfos.length; i++) {
            purseId[i] = getJsonValue(purseInfos[i], "purseId");
            purseCurrency[i] = getJsonValue(purseInfos[i], "purseCurrency");
            purseAvailableBalance[i] = getJsonValue(purseInfos[i], "purseAvailableBalance");
            purseCurrentBalance[i] = getJsonValue(purseInfos[i], "purseCurrentBalance");
            purseStatus[i] = getJsonValue(purseInfos[i], "purseStatus");
        }

        // Construct final JSON string
        String expectedOutput = "{\"purseInfoList\":{\"purseInfo\":{"
                + "\"purseId\":[\"" + String.join("\",\"", purseId) + "\"],"
                + "\"purseCurrency\":[\"" + String.join("\",\"", purseCurrency) + "\"],"
                + "\"purseAvailableBalance\":[\"" + String.join("\",\"", purseAvailableBalance) + "\"],"
                + "\"purseCurrentBalance\":[\"" + String.join("\",\"", purseCurrentBalance) + "\"],"
                + "\"purseStatus\":[\"" + String.join("\",\"", purseStatus) + "\"]"
                + "}}}";

        System.out.println(expectedOutput);
    }

    // Extract content of JSON array starting from a given key
    public static String extractArray(String json, String arrayKey) {
        int start = json.indexOf(arrayKey) + arrayKey.length();
        int end = start;
        int open = 1;

        while (end < json.length() && open > 0) {
            char c = json.charAt(end++);
            if (c == '[') open++;
            else if (c == ']') open--;
        }

        return json.substring(start, end - 1).trim();
    }

    // Split JSON objects within array
    public static String[] splitJsonArray(String arrayBody) {
        List<String> objects = new ArrayList<>();
        int start = 0;
        int braces = 0;
        for (int i = 0; i < arrayBody.length(); i++) {
            char c = arrayBody.charAt(i);
            if (c == '{') {
                if (braces == 0) start = i;
                braces++;
            } else if (c == '}') {
                braces--;
                if (braces == 0) {
                    objects.add(arrayBody.substring(start, i + 1));
                }
            }
        }
        return objects.toArray(new String[0]);
    }

    // Extract simple key-value from flat JSON object
    public static String getJsonValue(String json, String key) {
        String search = "\"" + key + "\":";
        int index = json.indexOf(search);
        if (index == -1) return "";

        index += search.length();
        while (index < json.length() && (json.charAt(index) == ' ' || json.charAt(index) == '\"')) index++;

        int end = index;
        while (end < json.length() && json.charAt(end) != '\"' && json.charAt(end) != ',' && json.charAt(end) != '}') end++;

        return json.substring(index, end).replaceAll("\"", "").trim();
    }
}








........













public class Main {
    public static void main(String[] args) {
        String jsonString = "{\"purseInfoList\":{\"purseInfo\":[{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"AED\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"CAD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"AUD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"EUR\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"USD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"GBP\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"SGD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"}]}}";

        // Manually parse the JSON string
        String purseInfoListJson = getJsonValue(jsonString, "purseInfoList");
        String purseInfoJsonArray = getJsonValue(purseInfoListJson, "purseInfo");

        // Extract the purseInfo array
        String[] purseInfoArray = splitJsonArray(purseInfoJsonArray);

        // Initialize the output arrays
        String[] purseId = new String[purseInfoArray.length];
        String[] purseCurrency = new String[purseInfoArray.length];
        String[] purseAvailableBalance = new String[purseInfoArray.length];
        String[] purseCurrentBalance = new String[purseInfoArray.length];
        String[] purseStatus = new String[purseInfoArray.length];

        // Populate the output arrays
        for (int i = 0; i < purseInfoArray.length; i++) {
            purseId[i] = getJsonValue(purseInfoArray[i], "purseId");
            purseCurrency[i] = getJsonValue(purseInfoArray[i], "purseCurrency");
            purseAvailableBalance[i] = getJsonValue(purseInfoArray[i], "purseAvailableBalance");
            purseCurrentBalance[i] = getJsonValue(purseInfoArray[i], "purseCurrentBalance");
            purseStatus[i] = getJsonValue(purseInfoArray[i], "purseStatus");
        }

        // Construct the expected output JSON string
        String expectedOutput = "{\"purseInfoList\":{\"purseInfo\":{\"purseId\":[\"" + String.join("\",\"", purseId) + "\"],\"purseCurrency\":[\"" + String.join("\",\"", purseCurrency) + "\"],\"purseAvailableBalance\":[\"" + String.join("\",\"", purseAvailableBalance) + "\"],\"purseCurrentBalance\":[\"" + String.join("\",\"", purseCurrentBalance) + "\"],\"purseStatus\":[\"" + String.join("\",\"", purseStatus) + "\"]}}}";

        System.out.println(expectedOutput);
    }

    // Helper method to get a JSON value
    public static String getJsonValue(String json, String key) {
        int startIndex = json.indexOf("\"" + key + "\":");
        if (startIndex == -1) return null;
        startIndex += key.length() + 2;
        int endIndex = json.indexOf(",", startIndex);
        if (endIndex == -1) endIndex = json.indexOf("}", startIndex);
        if (endIndex == -1) endIndex = json.length();
        String value = json.substring(startIndex, endIndex).trim();
        if (value.startsWith("\"")) value = value.substring(1, value.length() - 1);
        return value;
    }

                                          
    public static String[] splitJsonArray(String jsonArray) {
        jsonArray = jsonArray.substring(1, jsonArray.length() - 1);                   
        String[] elements = jsonArray.split("// Helper method to split a JSON array
    public static String[] splitJsonArray(String jsonArray) {
        jsonArray = jsonArray.substring(1, jsonArray.length() - 1); // Remove outer []
        String[] elements = jsonArray.split("\\},\\{");
        for (int i = 0; i < elements.length; i++) {
            if (i == 0 && !elements[i].startsWith("{")) elements[i] = "{" + elements[i];
            if (i == elements.length - 1 && !elements[i].endsWith("public class Main {
    public static void main(String[] args) {
        String jsonString = "{\"purseInfoList\":{\"purseInfo\":[{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"AED\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"CAD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"AUD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"EUR\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"USD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"GBP\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"SGD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"}]}}";

        // Manually parse the JSON string
        String purseInfoListJson = getJsonValue(jsonString, "purseInfoList");
        String purseInfoJsonArray = getJsonValue(purseInfoListJson, "purseInfo");

        // Extract the purseInfo array
        String[] purseInfoArray = splitJsonArray(purseInfoJsonArray);

        // Initialize the output arrays
        String[] purseId = new String[purseInfoArray.length];
        String[] purseCurrency = new String[purseInfoArray.length];
        String[] purseAvailableBalance = new String[purseInfoArray.length];
        String[] purseCurrentBalance = new String[purseInfoArray.length];
        String[] purseStatus = new String[purseInfoArray.length];

        // Populate the output arrays
        for (int i = 0; i < purseInfoArray.length; i++) {
            purseId[i] = getJsonValue(purseInfoArray[i], "purseId");
            purseCurrency[i] = getJsonValue(purseInfoArray[i], "purseCurrency");
            purseAvailableBalance[i] = getJsonValue(purseInfoArray[i], "purseAvailableBalance");
            purseCurrentBalance[i] = getJsonValue(purseInfoArray[i], "purseCurrentBalance");
            purseStatus[i] = getJsonValue(purseInfoArray[i], "purseStatus");
        }

        // Construct the expected output JSON string
        String expectedOutput = "{\"purseInfoList\":{\"purseInfo\":{\"purseId\":[\"" + String.join("\",\"", purseId) + "\"],\"purseCurrency\":[\"" + String.join("\",\"", purseCurrency) + "\"],\"purseAvailableBalance\":[\"" + String.join("\",\"", purseAvailableBalance) + "\"],\"purseCurrentBalance\":[\"" + String.join("\",\"", purseCurrentBalance) + "\"],\"purseStatus\":[\"" + String.join("\",\"", purseStatus) + "\"]}}}";

        System.out.println(expectedOutput);
    }

    // Helper method to get a JSON value
    public static String getJsonValue(String json, String key) {
        int startIndex = json.indexOf("\"" + key + "\":");
        if (startIndex == -1) return null;
        startIndex += key.length() + 2;
        int endIndex = json.indexOf(",", startIndex);
        if (endIndex == -1) endIndex = json.indexOf("}", startIndex);
        if (endIndex == -1) endIndex = json.length();
        String value = json.substring(startIndex, endIndex).trim();
        if (value.startsWith("\"")) value = value.substring(1, value.length() - 1);
        return value;
    }

                                          
    public static String[] splitJsonArray(String jsonArray) {
        jsonArray = jsonArray.substring(1, jsonArray.length() - 1);                   
        String[] elements = jsonArray.split("// Helper method to split a JSON array
    public static String[] splitJsonArray(String jsonArray) {
        jsonArray = jsonArray.substring(1, jsonArray.length() - 1); // Remove outer []
        String[] elements = jsonArray.split("\\},\\{");
        for (int i = 0; i < elements.length; i++) {
            if (i == 0 && !elements[i].startsWith("{")) elements[i] = "{" + elements[i];
            if (i == elements.length - 1 && !elements[i].endsWith("
            
            
            
            
            
            
            
            "purseInfoList": {
        "purseInfo": {
            "purseId": ["TRAVEL","TRAVEL","TRAVEL","TRAVEL","TRAVEL","TRAVEL","TRAVEL"]
            "purseCurrency": ["AED","CAD","AUD","EUR","USD","GBP","SGD"]
            "purseAvailableBalance": ["0.00","0.00","0.00","0.00","0.00","0.00","0.00"]
            "purseCurrentBalance": ["0.00","0.00","0.00","0.00","0.00","0.00","0.00"]
            "purseStatus": ["A","A","A","A","A","A","A",]
        },
    }



{"purseInfo": {"purseId": "TRAVEL","purseCurrency": "AED","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"},"purseInfo": {"purseId": "TRAVEL","purseCurrency": "CAD","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"},"purseInfo": {"purseId": "TRAVEL","purseCurrency": "AUD","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"},"purseInfo": {"purseId": "TRAVEL","purseCurrency": "EUR","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"},"purseInfo": {"purseId": "TRAVEL","purseCurrency": "USD","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"},"purseInfo": {"purseId": "TRAVEL","purseCurrency": "GBP","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"},"purseInfo": {"purseId": "TRAVEL","purseCurrency": "SGD","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"}}



import java.util.*;

public class Main {
    public static void main(String[] args) {
        // Example JSON string input
        String jsonString = "{\"a\":{\"0\":\"d1\",\"1\":\"d2\",\"2\":\"d3\"},\"b\":{\"0\":\"e1\",\"1\":\"e2\",\"2\":\"e3\"},\"c\":{\"0\":\"f1\",\"1\":\"f2\",\"2\":\"f3\"}}";

        // Call the function to get the parallel elements
        List<List<String>> result = getParallelElements(jsonString);

        // Print the result
        for (List<String> innerList : result) {
            System.out.println(innerList);
        }
    }

    public static List<List<String>> getParallelElements(String jsonString) {
        // Manually parse the JSON string
        Map<String, Map<String, String>> jsonData = manualJsonParse(jsonString);

        // Find the maximum length of the inner JSON objects
        int maxLength = 0;
        for (Map<String, String> innerObject : jsonData.values()) {
            maxLength = Math.max(maxLength, innerObject.size());
        }

        // Initialize the result list
        List<List<String>> result = new ArrayList<>();
        for (int i = 0; i < maxLength; i++) {
            result.add(new ArrayList<>());
        }

        // Populate the result list with parallel elements
        for (Map<String, String> innerObject : jsonData.values()) {
            for (int i = 0; i < maxLength; i++) {
                String value = innerObject.get(String.valueOf(i));
                if (value != null) {
                    result.get(i).add(value);
                }
            }
        }

        return result;
    }

    public static Map<String, Map<String, String>> manualJsonParse(String jsonString) {
        // Simple manual JSON parser for the given format
        jsonString = jsonString.trim().substring(1, jsonString.length() - 1); // Remove outer {}
        String[] parts = jsonString.split("\\},\\\"");
        Map<String, Map<String, String>> result = new HashMap<>();

        for (String part : parts) {
            part = part.replaceAll("\\\"", "").replaceAll("\\{", "").replaceAll("\\}", "");
            String[] keyValuePairs = part.split(",");
            String key = keyValuePairs[0].split("\\:")[0];
            Map<String, String> innerMap = new HashMap<>();

            for (int i = 1; i < keyValuePairs.length; i++) {
                String[] pair = keyValuePairs[i].split("\\:");
                if (pair.length == 2) {
                    innerMap.put(pair[0], pair[1]);
                }
            }

            result.put(key, innerMap);
        }

        return result;
    }
}




















import java.util.*;

public class JsonTransposePureJava {
    public static void main(String[] args) {
        // Simulating the parsed JSON structure using nested Maps
        Map<String, Map<String, String>> input = new HashMap<>();

        Map<String, String> a = Map.of("x", "d1", "y", "d2", "z", "d3");
        Map<String, String> b = Map.of("x", "e1", "y", "e2", "z", "e3");
        Map<String, String> c = Map.of("x", "f1", "y", "f2", "z", "f3");

        input.put("a", a);
        input.put("b", b);
        input.put("c", c);

        // Get all keys from the first entry (assumes all inner maps have same keys)
        Set<String> innerKeys = input.values().iterator().next().keySet();

        // Prepare the result
        List<List<String>> result = new ArrayList<>();

        for (String innerKey : innerKeys) {
            List<String> row = new ArrayList<>();
            for (String outerKey : input.keySet()) {
                Map<String, String> innerMap = input.get(outerKey);
                row.add(innerMap.get(innerKey));
            }
            result.add(row);
        }

        // Print the result
        for (List<String> row : result) {
            System.out.println(row);
        }
    }
}















import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;

public class TransposeNamedJson {
    public static void main(String[] args) {
        String jsonString = """
        {
          "a": {"x": "d1", "y": "d2", "z": "d3"},
          "b": {"x": "e1", "y": "e2", "z": "e3"},
          "c": {"x": "f1", "y": "f2", "z": "f3"}
        }
        """;

        JSONObject input = new JSONObject(jsonString);

        // Get all outer keys: a, b, c
        List<String> outerKeys = new ArrayList<>(input.keySet());

        // Collect all unique inner keys: x, y, z
        Set<String> innerKeySet = input.getJSONObject(outerKeys.get(0)).keySet();

        JSONArray result = new JSONArray();

        for (String innerKey : innerKeySet) {
            JSONArray row = new JSONArray();
            for (String outerKey : outerKeys) {
                JSONObject innerObject = input.getJSONObject(outerKey);
                row.put(innerObject.getString(innerKey));
            }
            result.put(row);
        }

        System.out.println(result.toString(2));
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
