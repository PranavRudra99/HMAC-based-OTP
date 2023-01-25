compile:
	g++ client.cpp util.h -L/usr/lib -lssl -lcrypto -o client; g++ server.cpp util.h -L/usr/lib -lssl -lcrypto -o server;
