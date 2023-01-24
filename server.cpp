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

char hex_characters[]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

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

void GeneratePropertiesFile(string fileName, char* key){
  int count = 0;
  ofstream PropertiesFile(fileName);
  PropertiesFile << key;
  PropertiesFile << endl;
  PropertiesFile << count;
  PropertiesFile.close();
}

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

string GetOTP(char *buf){
  std::stringstream strstream(buf);
  std::string str = "";
  if(buf != NULL){
   std::getline(strstream, str, '\n');
  }
  return str;
}

int GetIntValueOfHex(char character){
  for(int i = 0; i < 16; i++){
    if(character == hex_characters[i]){
      return i;
    }
  }
  return -1;
}

char getReducedValue(char character){
  int intVal = GetIntValueOfHex(character);
  if(intVal > 7){
    intVal = intVal - 8;
  }
  return hex_characters[intVal];
}


string GetUnsignedValue(string code){
  char firstChar = code[0];
  char unsignedChar = getReducedValue(firstChar);
  string substr = code.substr(1, 7);
  return unsignedChar + substr;
}

string GetHmacSHAValue(string key, string msg){
    std::string_view key_view{key};
    std::string_view msg_view{msg};
    return CalcHmacSHA(key_view, msg_view);
}

string TruncateHMACSHACode(string HMACSHACode){
  char c = HMACSHACode[39];
  int index = GetIntValueOfHex(c);
  index *=2;
  string ReducedCode = HMACSHACode.substr(index, 8);
  cout << ReducedCode << endl;
  string unsignedValue = GetUnsignedValue(ReducedCode);
  cout << unsignedValue << endl;
  return unsignedValue;
}

string GetPaddedString(int val){
  if(val == 0){
    return "000000";
  }
  if(val < 10){
    return "00000" + std::to_string(val); 
  }
  if(val < 100){
    return "0000" + std::to_string(val); 
  }
  if(val < 1000){
    return "000" + std::to_string(val); 
  }
  if(val < 10000){
    return "00" + std::to_string(val); 
  }
  if(val < 100000){
    return "0" + std::to_string(val);
  }
  return std::to_string(val);
}

string GetOTP(string HexString){
    unsigned int value;
    int mod = 1000000;
    std::istringstream iss(HexString);
    iss >> std::hex >> value;
    std::cout << value << std::endl;
    int val = value%mod;
    string otp = GetPaddedString(val);
    return otp;
}

string CalculateOTP(string propertiesFileName){
ifstream PropertiesFile(propertiesFileName); 
  if(PropertiesFile.good()){
    string count;
    string storedKey;
    getline(PropertiesFile, storedKey, '\n');
    getline(PropertiesFile, count, '\n');
    string HMACSHACode = GetHmacSHAValue(storedKey, count);
    cout <<"HMAC-SHA1 Code:"<< HMACSHACode << endl;
    //UpdatePropertiesFile(propertiesFileName, storedKey, count); /*uncomment*/
    //HMACSHACode = "ffffffffe6f7e1af99f9dcdf6227467b8abce9c0";
    //HMACSHACode = "00000000e6f7e1af99f9dcdf6227467b8abce9c0";
    string TruncatedCode = TruncateHMACSHACode(HMACSHACode);
    string OTPCode = GetOTP(TruncatedCode);
    cout << OTPCode << endl;
    return OTPCode;
  }
  return "";
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

		printf("new client accepted.\n");

		char client_ip[INET_ADDRSTRLEN] = "";
		inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

		while(recv(conn, recv_buf, sizeof(recv_buf), 0) > 0 ){
		        if(IsInitializtionStep(recv_buf, init)){
                          GeneratePropertiesFile(serverPropertiesFile, (char*)key.c_str());
		        }
		        else{
		          string ReceivedOTPCode = GetOTP(recv_buf);
		          cout << "Received OTP:" << ReceivedOTPCode << endl;
		          string CalculatedOTPCode = CalculateOTP(serverPropertiesFile);
		        }
			memset(recv_buf, '\0', strlen(recv_buf));
			break;
		}
	}

	printf("closed. \n");
	close(server_sockfd);
	return 0;
}
