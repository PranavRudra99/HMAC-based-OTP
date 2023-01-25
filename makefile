compile:
	g++ client.cpp -L/usr/lib -lssl -lcrypto -o client; g++ server.cpp -L/usr/lib -lssl -lcrypto -o server;
