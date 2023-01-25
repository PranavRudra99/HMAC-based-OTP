Compilation:
cd src
make

Execution:
-------------------------------------------------
initially[one time]-

./server
./client [--initialize]
-------------------------------------------------
The --initialize option is used to set the initial values for shared key and counter. After executing with the initialize option, the ClientProperties & ServerProperties files are generated, and the client and the server can send/receive OTP codes.


-------------------------------------------------
After initialization-

./server
./client
-------------------------------------------------
Note: The server should be running before executing the client.

In the src folder, there are 2 cpp files, 1 header file:
client.cpp
server.cpp
util.h

client.cpp: Contains the client code, and can be executed to send an OTP value that's calculated based on the shared key and counter value in ClientProperties.txt
server.cpp: Contains the server code, and can be executed to verify the received OTP value against the OTP value that's calculated based on the shared key and counter value in ServerProperties.txt
