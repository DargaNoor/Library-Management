CREATE COMPUTE MODULE SetMQHeadersForConsumer
    CREATE FUNCTION Main() RETURNS BOOLEAN
    BEGIN
        -- Assuming you have received a message and want to modify its headers
        
        -- Example: Set the Message ID
        SET OutputRoot.MQMD.MsgId = CAST('1234567890ABCDEF' AS BLOB);
        
        -- Example: Set the Correlation ID
        SET OutputRoot.MQMD.CorrelId = CAST('0987654321FEDCBA' AS BLOB);
        
        -- Example: Set Reply-to Queue Manager
        SET OutputRoot.MQMD.ReplyToQMgr = 'REPLY_QMGR';
        
        -- Example: Set Reply-to Queue
        SET OutputRoot.MQMD.ReplyToQ = 'REPLY_QUEUE';
        
        -- Copy the incoming message to the output message if needed
        SET OutputRoot.BLOB.BLOB = InputRoot.BLOB.BLOB;
        
        -- Set the Output Message Domain (if required)
        SET OutputRoot.Properties.MessageDomain = 'MQMD';
        
        RETURN TRUE;
    END;
END MODULE;



CREATE COMPUTE MODULE PrepareRequestMessage
    CREATE FUNCTION Main() RETURNS BOOLEAN
    BEGIN
        -- Copy input message to output message
        SET OutputRoot = InputRoot;

        -- Ensure the MQMD header exists
        IF NOT EXISTS(OutputRoot.MQMD) THEN
            CREATE NEXTSIBLING OF OutputRoot.Properties DOMAIN('MQMD') NAME 'MQMD';
        END IF;

# Library-Management
Library Management System is a system which maintains the information about the books present in the library, their authors, the members of library to whom books are 
issued and all. This is very difficult to organize manually. Maintenance of all this information manually is a very complex task. Owing to the advancement of technology, 
organization of an Online Library becomes much simple.The maintenance of the records is made efficient, as all the records are stored in the ACCESS database, through 
which data can be retrieved easily. It makes entire process online where student can search books, staff can generate reports and do book transactions.The navigation 
control is provided in all the forms to navigate through the large amount of records. 
The Library Management has been designed to computerize and automate the operations performed over the information about the members, book issues and returns and all 
other operations. This computerization of library helps in many instances of its maintenance. It reduces the workload of management as most of the manual work done is 
reduced.
