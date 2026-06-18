                    TLS 1.2

 Client
    |
    | HTTPS
    |
+-----------+
| Load      |
| Balancer  |
+-----------+
    |
    | HTTPS
    |
+-----------+
| DataPower |
| SSL Server|
| Profile   |
+-----------+
    |
    | HTTPS
    |
+-----------+
| IBM ACE   |
| HTTPInput |
| HTTPReq   |
+-----------+
    |
    | HTTPS
    |
 Backend APIs
 
 
 
 
                  Need Validation

 Client
    |
    V
+--------------+
| LoadBalancer |
| TLS 1.3      |
+--------------+
      |
      V
+--------------+
| DataPower    |
| SSL Server   |
| SSL Client   |
| Crypto Prof. |
+--------------+
      |
      V
+--------------+
| IBM ACE      |
| HTTPInput    |
| HTTPRequest  |
| Java 17      |
+--------------+
      |
      V
+--------------+
| Backend APIs |
| TLS 1.3      |
+--------------+
 
 
 
 # Library-Management
Library Management System is a system which maintains the information about the books present in the library, their authors, the members of library to whom books are 
issued and all. This is very difficult to organize manually. Maintenance of all this information manually is a very complex task. Owing to the advancement of technology, 
organization of an Online Library becomes much simple.The maintenance of the records is made efficient, as all the records are stored in the ACCESS database, through 
which data can be retrieved easily. It makes entire process online where student can search books, staff can generate reports and do book transactions.The navigation 
control is provided in all the forms to navigate through the large amount of records. 
The Library Management has been designed to computerize and automate the operations performed over the information about the members, book issues and returns and all 
other operations. This computerization of library helps in many instances of its maintenance. It reduces the workload of management as most of the manual work done is 
reduced.
