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

#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <array>
#include <cstring>
#include <fstream>

using namespace std;

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

void GeneratePropertiesFile(string fileName, char* key, int count){
  ofstream PropertiesFile(fileName);
  PropertiesFile << key;
  PropertiesFile << endl;
  PropertiesFile << count;
  PropertiesFile.close();
}

void UpdatePropertiesFile(string fileName, string key, string count){
  int updatedCount = atoi(count.c_str()) + 1;
  GeneratePropertiesFile(fileName, (char*)key.c_str(), updatedCount);
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
  //cout << ReducedCode << endl;
  string unsignedValue = GetUnsignedValue(ReducedCode);
  //cout << unsignedValue << endl;
  return unsignedValue;
}

string GetOTP(string HexString){
    unsigned int value;
    int mod = 1000000;
    std::istringstream iss(HexString);
    iss >> std::hex >> value;
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
    UpdatePropertiesFile(propertiesFileName, storedKey, count); /*uncomment*/
    //HMACSHACode = "ffffffffe6f7e1af99f9dcdf6227467b8abce9c0";
    //HMACSHACode = "00000000e6f7e1af99f9dcdf6227467b8abce9c0";
    string TruncatedCode = TruncateHMACSHACode(HMACSHACode);
    string OTPCode = GetOTP(TruncatedCode);
    cout << OTPCode << endl;
    return OTPCode;
  }
  return "";
}
