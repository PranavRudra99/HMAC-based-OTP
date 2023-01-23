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

void GeneratePropertiesFile(string fileName, char* key, int count){
  ofstream PropertiesFile(fileName);
  PropertiesFile << key;
  PropertiesFile << endl;
  PropertiesFile << count;
  PropertiesFile.close();
}

string GetHmacSHAValue(string key, string msg){
    std::string_view key_view{key};
    std::string_view msg_view{msg};
    return CalcHmacSHA(key_view, msg_view);
}

void UpdatePropertiesFile(string fileName, string key, string count){
  int updatedCount = atoi(count.c_str()) + 1;
  GeneratePropertiesFile(fileName, (char*)key.c_str(), updatedCount);
}

int main(int argc, char **argv){
  string msg = "";
  struct sockaddr_in server_addr;     // set server addr and port
      memset(&server_addr, 0, sizeof(server_addr));
      server_addr.sin_family = AF_INET;
      server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
      server_addr.sin_port = htons(8000);  // server default port
  int sock_client;
  char send_buf[65536];
      memset(send_buf, '\0', sizeof(send_buf));
  char* send_content;
  string clientPropertiesFile = "ClientProperties.txt";
  if(argc == 1){
    ifstream PropertiesFile(clientPropertiesFile); 
    if(PropertiesFile.good()){
      string count;
      string storedKey;
      getline(PropertiesFile, storedKey, '\n');
      getline(PropertiesFile, count, '\n');
      string HMACShaCode = GetHmacSHAValue(storedKey, count);
      cout <<"HMAC-SHA1 Code:"<< HMACShaCode << endl;
      UpdatePropertiesFile(clientPropertiesFile, storedKey, count);
    }
    else{
      cout << "Need Initialization!" << endl;
      return -1;
    }
  }
  if(argc == 2){
    char* init = (char*)"initialize";
    if(strcmp(argv[1], init)){
      int length = 20;
      char key[length];
      cout << "Initializing connection!" << endl;
      GenerateHexString(key, length);
      GeneratePropertiesFile(clientPropertiesFile, key, 0);
      send_content = init;
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
}
