#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
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

string key;

bool IsInitializtionStep(char* buf, string init){
  std::stringstream strstream(buf);
  std::string str;
  bool result = false;
  if(buf != NULL){
    int iterator = 0;
    while(std::getline(strstream, str, '\n')){
      if(str == init){
        result = true;
      }
      key = str;
    }
  }
  return result;
}

string FetchOTP(char *buf){
  std::stringstream strstream(buf);
  std::string str = "";
  if(buf != NULL){
   std::getline(strstream, str, '\n');
  }
  return str;
}

int AccountForUnSync(string key, string count, string ReceivedOTPCode){
  int lowRange = GetLowRange(count);
  int highRange = GetHighRange(count);
  //cout << lowRange <<":::::" << highRange << endl;
  if(lowRange < highRange){
    for(int i = lowRange; i <= highRange; i++){
      string countVar = std::to_string(i);
      string CalculatedOTP = CalculateOTP(key, countVar);
      if(CalculatedOTP == ReceivedOTPCode){
        return i;
      }
    }
  }
  else{
    for(int i = lowRange; i < max_counter_value; i++){
      string countVar = std::to_string(i);
      string CalculatedOTP = CalculateOTP(key, countVar);
      if(CalculatedOTP == ReceivedOTPCode){
        return i;
      }
    }
    for(int i = 0; i <= highRange; i++){
      string countVar = std::to_string(i);
      string CalculatedOTP = CalculateOTP(key, countVar);
      if(CalculatedOTP == ReceivedOTPCode){
        return i;
      }
    }
  }
  return -1;
}

int main(int argc, char **argv){
    int server_sockfd;		// server socket fd	
	struct sockaddr_in server_addr;		// server info struct
	server_addr.sin_family=AF_INET; 	// TCP/IP
	server_addr.sin_addr.s_addr=INADDR_ANY;		// server addr--permit all connection
	server_addr.sin_port=htons(8000); 		// server port
	
    string init = "initialize";
    string serverPropertiesFile = "ServerProperties.txt";
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

		char client_ip[INET_ADDRSTRLEN] = "";
		inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

		while(recv(conn, recv_buf, sizeof(recv_buf), 0) > 0 ){
		        if(IsInitializtionStep(recv_buf, init)){
                          GeneratePropertiesFile(serverPropertiesFile, (char*)key.c_str(), 0);
		        }
		        else{
                          char send_buf[65536];
                          memset(send_buf, '\0', sizeof(send_buf));
		          string ReceivedOTPCode = FetchOTP(recv_buf);
		          cout << "Received OTP:" << ReceivedOTPCode << endl;
                          string sharedKey = GetSharedKey(serverPropertiesFile);
                          string count = GetCurrentCount(serverPropertiesFile);
                          int code = AccountForUnSync(sharedKey, count, ReceivedOTPCode);
		          if(code != -1){
		            count = std::to_string(code);
		            UpdatePropertiesFile(serverPropertiesFile, sharedKey, count);
		            strcpy(send_buf, "Accepted");
		            cout << "Valid OTP" << endl;
		          }
		          else{
		            strcpy(send_buf, "Rejected");
		            cout << "Invalid OTP" << endl;
		          }
		          send(conn, send_buf, strlen(send_buf), 0);
		        }
			memset(recv_buf, '\0', strlen(recv_buf));
			break;
		}
	}

	printf("closed. \n");
	close(server_sockfd);
	return 0;
}
