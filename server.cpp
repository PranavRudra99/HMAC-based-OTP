#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <array>
#include <cstring>
#include <fstream>

using namespace std;

string key;

std::string CalcHmacSHA256(std::string_view decodedKey, std::string_view msg)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash;
    unsigned int hashLen;

    HMAC(
        EVP_sha1(),
        decodedKey.data(),
        static_cast<int>(decodedKey.size()),
        reinterpret_cast<unsigned char const*>(msg.data()),
        static_cast<int>(msg.size()),
        hash.data(),
        &hashLen
    );
    std::stringstream out;
    for (unsigned int i=0; i < hashLen; i++) {
        out << std::setfill('0') << std::setw(2) << std::right << std::hex << (int)hash.data()[i];
    }
    return out.str();
}

void GeneratePropertiesFile(string fileName, char* key){
  int count = 0;
  ofstream PropertiesFile(fileName);
  PropertiesFile << key;
  PropertiesFile << endl;
  PropertiesFile << count;
  PropertiesFile.close();
}

void InitializeConnection(char* key){
  string serverPropertiesFile = "ServerProperties.txt";
  GeneratePropertiesFile(serverPropertiesFile, key);
}

bool IsInitializtionStep(char* buf, char* init){
  std::stringstream strstream(buf);
  std::string str;
  bool result = false;
  if(buf != NULL){
    int iterator = 0;
    while(std::getline(strstream, str, '\n')){
      if(strcmp(str.c_str(), init)){
        result = true;
        key = str.c_str();
      }
    }
  }
  return result;
}

int main(int argc, char **argv){
    int server_sockfd;		// server socket fd	
	struct sockaddr_in server_addr;		// server info struct
	server_addr.sin_family=AF_INET; 	// TCP/IP
	server_addr.sin_addr.s_addr=INADDR_ANY;		// server addr--permit all connection
	server_addr.sin_port=htons(8000); 		// server port
	
    char* init = (char*)"initialize";
	/* create socket fd with IPv4 and TCP protocal*/
	if((server_sockfd=socket(PF_INET,SOCK_STREAM,0))<0) {  
					perror("socket error");
					return 1;
	}

	/* bind socket with server addr */
	if(bind(server_sockfd,(struct sockaddr *)&server_addr,sizeof(struct sockaddr))<0) {
					perror("bind error");
					return 1;
	}

	/* listen connection request with a queue length of 20 */
	if(listen(server_sockfd,20)<0) {
					perror("listen error");
					return 1;
	}
	printf("listen success.\n");

	char recv_buf[65536];
	memset(recv_buf, '\0', sizeof(recv_buf));

	while (1) {
		struct sockaddr_in client_addr;
		socklen_t length = sizeof(client_addr);
		// block on accept until positive fd or error
		int conn = accept(server_sockfd, (struct sockaddr*)&client_addr,&length);
		if(conn<0) {
			perror("connect");
			return -1;
		}

		printf("new client accepted.\n");

		char client_ip[INET_ADDRSTRLEN] = "";
		inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

		while(recv(conn, recv_buf, sizeof(recv_buf), 0) > 0 ){
		        if(IsInitializtionStep(recv_buf, init)){
		          InitializeConnection((char*)key.c_str());
		        }
			memset(recv_buf, '\0', strlen(recv_buf));
			break;
		}
	}

	printf("closed. \n");
	close(server_sockfd);
	return 0;
}
