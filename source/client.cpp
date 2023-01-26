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
#include "util.h"

#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <array>
#include <cstring>
#include <fstream>

using namespace std;

void GenerateHexString(char str[], int length)
{
  int i;
  srand(time(0));
  for(i=0;i<length;i++)
  {
    str[i]=hex_characters[rand()%16];
  }
  str[length]=0;
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
  if ((sock_client = socket(AF_INET,SOCK_STREAM, 0)) < 0) {
      return 0;
  }

    //connect server, return 0 with success, return -1 with error
  if (connect(sock_client, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
  {
      perror("connect");
      return 0;
  }
  if(argc == 1){
    ifstream PropertiesFile(clientPropertiesFile); 
    if(PropertiesFile.good()){
      string sharedKey = GetSharedKey(clientPropertiesFile);
      string count = GetCurrentCount(clientPropertiesFile);
      string OTPCode = CalculateOTP(sharedKey, count);
      UpdatePropertiesFile(clientPropertiesFile, sharedKey, count);
      strcpy(send_buf, OTPCode.c_str());
      char server_ip[INET_ADDRSTRLEN]="";
      inet_ntop(AF_INET, &server_addr.sin_addr, server_ip, INET_ADDRSTRLEN);
      printf("connected server(%s:%d). \n", server_ip, ntohs(server_addr.sin_port));
      cout <<"Sending OTP:" << OTPCode << endl;
      send(sock_client, send_buf, strlen(send_buf), 0);
      char recv_buf[65536];
      memset(recv_buf, '\0', sizeof(recv_buf));
      while(1){
        while(recv(sock_client, recv_buf, sizeof(recv_buf), 0) > 0 ){
          std::stringstream strstream(recv_buf);
          std::string str = "";
          if(recv_buf != NULL){
            std::getline(strstream, str, '\n');
            cout <<"Response from server:"<< str << endl;
            close(sock_client);
            return 1;
          }
        }
      }
    }
    else{
      cout << "Need Initialization!" << endl;
      return -1;
    }
  }
  if(argc == 2){
    char* init = (char*)"initialize";
    if(strcmp(argv[1], init)){
      int length = 40;
      char key[length];
      cout << "Initializing connection!" << endl;
      GenerateHexString(key, length);
      GeneratePropertiesFile(clientPropertiesFile, key, 0);
      send_content = init;
      strcpy(send_buf, send_content);
      strcat(send_buf, "\n");
      strcat(send_buf, key);
      
      char server_ip[INET_ADDRSTRLEN]="";
      inet_ntop(AF_INET, &server_addr.sin_addr, server_ip, INET_ADDRSTRLEN);
      printf("connected server(%s:%d). \n", server_ip, ntohs(server_addr.sin_port));

  //send a message to server
  send(sock_client, send_buf, strlen(send_buf), 0);
  close(sock_client);

    }
  }
  return 0;
}
