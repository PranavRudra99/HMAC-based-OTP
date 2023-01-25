compile:
	g++  util.h client.cpp -L/usr/lib -lssl -lcrypto -o client; g++ util.h server.cpp -L/usr/lib -lssl -lcrypto -o server;
