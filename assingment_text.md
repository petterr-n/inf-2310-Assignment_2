I THINK this was the assignment text, this is some of it alteast.

No code was included, everything is made from scratch. Can be made in whatever programming-language you want.

Assignent 2 inf-2310:

using rsa encryption over a tcp server and client

Client connects to server to ask for a file.
Clients symmetric key is encrypted with servers public key.
Server decrypts symmetric key with its private key.
Server encrypts file with the decrypted symmetric key and transfers it to client.
Client decrypts the file received from the server.


The client will use network sockets to connect to the server over the Internet. 
The server program uses the socket API to establish a TCP listening socket that accepts incoming connections.  
It is acceptable to hard-code the TCP port number as a constant value in your application. 
But the server should accept the path to the file to serve as a command-line argument. 
Likewise, the client should accept the hostname of the server to connect to as a command-line argument.

Need both symmetric and asymmetric encryption.
You may freely choose the particular algorithms to use in each case, though we suggest using AES for symmetric encryption, and RSA for asymmetric encryption. 

Usage of any library offering cryptographic functions is permitted. 
However, you may not use existing implementations of key-exchange protocols. 
In particular, you may not use existing libraries for SSL and TLS. 
If you are in doubt, please contact the TAs.

Write a report about it :)
