#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <array>
#include <fstream>

using namespace std;

std::string CalcHmacSHA(std::string_view decodedKey, std::string_view msg)
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

void GenerateHexString(char str[], int length)
{
  char hex_characters[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
  int i;
  srand(time(0));
  for(i=0;i<length;i++)
  {
    str[i]=hex_characters[rand()%16];
  }
  str[length]=0;
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
  string clientPropertiesFile = "ClientProperties.txt";
  string serverPropertiesFile = "ServerProperties.txt";
  GeneratePropertiesFile(clientPropertiesFile, key);
  GeneratePropertiesFile(serverPropertiesFile, key);
}

int main(int argc, char **argv){
  string msg = "";
  int length = 20;
  char key[length];
  struct sockaddr_in server_addr;     // set server addr and port
      memset(&server_addr, 0, sizeof(server_addr));
      server_addr.sin_family = AF_INET;
      server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
      server_addr.sin_port = htons(8000);  // server default port
  int sock_client;
  char send_buf[65536];
      memset(send_buf, '\0', sizeof(send_buf));
  char* send_content;
  if(argc == 2){
    if(strcmp(argv[1],"initialize")){
      cout << "Initializing connection!" << endl;
      GenerateHexString(key, length);
      InitializeConnection(key);
      send_content = (char*)"Initialize";
      strcpy(send_buf, send_content);
      strcat(send_buf, "\n");
      strcat(send_buf, key);
    }
  }
  
  if ((sock_client = socket(AF_INET,SOCK_STREAM, 0)) < 0) {
      return 0;
  }

    //connect server, return 0 with success, return -1 with error
  if (connect(sock_client, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
  {
      perror("connect");
      return 0;
  }

  char server_ip[INET_ADDRSTRLEN]="";
  inet_ntop(AF_INET, &server_addr.sin_addr, server_ip, INET_ADDRSTRLEN);
  printf("connected server(%s:%d). \n", server_ip, ntohs(server_addr.sin_port));

  //send a message to server
  send(sock_client, send_buf, strlen(send_buf), 0);
  close(sock_client);

  return 0;
    /*std::string_view key_view{key};
    std::string_view msg_view{msg};
    std::cout << CalcHmacSHA(key_view, msg_view) << std::endl;*/
}

