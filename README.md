<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:dp="http://www.datapower.com/extensions"
    extension-element-prefixes="dp">
    
    <xsl:output method="xml" omit-xml-declaration="yes"/>
    
    <!-- Store Specific Response Headers -->
    <xsl:variable name="header1">
        <dp:header name="sign_auth"/>
    </xsl:variable>

    <xsl:variable name="header2">
        <dp:header name="Content-Type"/>
    </xsl:variable>

    <!-- Transform Response: Add Headers to Body -->
    <xsl:template match="/">
        <response>
            <headers>
                <sign_auth><xsl:value-of select="$header1"/></sign_auth>
                <content_type><xsl:value-of select="$header2"/></content_type>
            </headers>
            <body>
                <xsl:copy-of select="."/>
            </body>
        </response>
    </xsl:template>

</xsl:stylesheet>













var headervar headers = "";
var body = "";

// Read the input as an XML document
session.input.readAsXML(function (error, xml) {
    if (error) {
        console.error("Error reading input XML: " + error);
        session.output.write("<error>Failed to parse response</error>");
        return;
    }

    // Use XPath to extract values
    var headersNode = xml.xpath("string(//response/headers)");
    var bodyNode = xml.xpath("//response/body");

    // Extract headers as a string
    if (headersNode) {
        headers = headersNode;
    }

    // Extract body as a string (convert XML to text)
    if (bodyNode && bodyNode.length > 0) {
        body = bodyNode[0].toXMLString();  // Convert XML node to string
    }

    console.info("Extracted Headers: " + headers);
    console.info("Extracted Body: " + body);

    // Return the response with headers and body
    session.output.write("<response><headers>" + headers + "</headers><body>" + body + "</body></response>");
});s = "";
var body = "";

// Read the input as an XML document
session.input.readAsXML(function (error, xml) {
    if (error) {
        console.error("Error reading input XML: " + error);
        session.output.write("<error>Failed to parse response</error>");
        return;
    }

    // Use XPath to select nodes
    var headersNode = xml.selectSingleNode("//response/headers");
    var bodyNode = xml.selectSingleNode("//response/body");

    // Extract headers and body
    if (headersNode) {
        headers = headersNode.textContent;
    }
    if (bodyNode) {
        body = bodyNode.toString();  // Convert XML body to a string
    }

    console.info("Extracted Headers: " + headers);
    console.info("Extracted Body: " + body);

    // Return the response with headers and body
    session.output.write("<response><headers>" + headers + "</headers><body>" + body + "</body></response>");
});






<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:dp="http://www.datapower.com/extensions"
    extension-element-prefixes="dp">
    
    <xsl:output method="xml" omit-xml-declaration="yes"/>
    
    <!-- Capture Response Headers -->
    <xsl:variable name="responseHeaders">
        <dp:http-response-headers/>
    </xsl:variable>

    <!-- Transform Response: Add Headers to Body -->
    <xsl:template match="/">
        <response>
            <headers>
                <xsl:value-of select="$responseHeaders"/>
            </headers>
            <body>
                <xsl:copy-of select="."/>
            </body>
        </response>
    </xsl:template>

</xsl:stylesheet>



var headers = "";
var body = "";

session.input.readAsXML(function (error, xml) {
    if (error) {
        console.error("Error reading input XML: " + error);
        session.output.write("<error>Failed to parse response</error>");
        return;
    }

    // Extract Headers and Body from transformed response
    if (xml) {
        var headersNode = xml.getElementsByTagName("headers")[0];
        var bodyNode = xml.getElementsByTagName("body")[0];

        if (headersNode) {
            headers = headersNode.textContent;
        }

        if (bodyNode) {
            body = bodyNode.textContent;
        }
    }

    console.info("Extracted Headers: " + headers);
    console.info("Extracted Body: " + body);

    // Return the response with headers
    session.output.write("<response><headers>" + headers + "</headers><body>" + body + "</body></response>");
});




















var storedHeaders = context.getVariable('var://session/original_response_headers');
console.info("Retrieved Headers: " + JSON.stringify(storedHeaders));
session.output.write(storedHeaders);





<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:dp="http://www.datapower.com/extensions"
    extension-element-prefixes="dp">
    
    <xsl:output method="xml" omit-xml-declaration="yes"/>
    
    <!-- Store Response Headers in a Session Variable -->
    <dp:set-variable name="'var://session/original_response_headers'" 
                     value="dp:http-response-headers()"/>

    <!-- Debug: Log the stored response headers -->
    <dp:set-variable name="'var://service/debug_log'"
                     value="dp:get-variable('var://session/original_response_headers')"/>

    <!-- Pass-through the response body unchanged -->
    <xsl:template match="/">
        <xsl:copy-of select="."/>
    </xsl:template>
    
</xsl:stylesheet>













// Capture response headers
var responseHeaders = context.getVariable('var://headers');

// Store them in a persistent variable
context.setVariable('var://service/original_response_headers', responseHeaders);

// Log the headers for debugging
console.info("Stored Response Headers: " + JSON.stringify(responseHeaders));


var originalHeaders = context.getVariable('var://service/original_response_headers');
session.output.write(originalHeaders);


















if (session.response && typeof session.response === "object") {
    session.response.statusCode = 200;
    session.response.reasonPhrase = "Success";
} else {
    session.variables.set("var://service/response/status-code", 200);
    session.variables.set("var://service/response-reason-phrase", "Success");
}

// Override response body with success message
session.output.write({
    "status": "success",
    "errorCode": 0,
    "message": "Operation completed successfully"
});
















session.context.set("var://service/response/status-code", "200");
session.context.set("var://service/response/reason-phrase", "Success");

session.output.write({
    "status": "success",
    "errorCode": 0,
    "message": "Operation completed successfully"
});






session.output.write({
    "status": "success",
    "errorCode": 0,
    "message": "Operation completed successfully"
});

// Ensure HTTP response is always 200 OK
session.response.statusCode = 200;
session.response.reasonPhrase = "Success";


# Library-Management
Library Management System is a system which maintains the information about the books present in the library, their authors, the members of library to whom books are 
issued and all. This is very difficult to organize manually. Maintenance of all this information manually is a very complex task. Owing to the advancement of technology, 
organization of an Online Library becomes much simple.The maintenance of the records is made efficient, as all the records are stored in the ACCESS database, through 
which data can be retrieved easily. It makes entire process online where student can search books, staff can generate reports and do book transactions.The navigation 
control is provided in all the forms to navigate through the large amount of records. 
The Library Management has been designed to computerize and automate the operations performed over the information about the members, book issues and returns and all 
other operations. This computerization of library helps in many instances of its maintenance. It reduces the workload of management as most of the manual work done is 
reduced.
