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
