#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <iostream>
#include <string>
#include <string_view>
#include <array>

using namespace std;

std::string CalcHmacSHA256(std::string_view decodedKey, std::string_view msg)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash;
    unsigned int hashLen;

    HMAC(
        EVP_sha256(),
        decodedKey.data(),
        static_cast<int>(decodedKey.size()),
        reinterpret_cast<unsigned char const*>(msg.data()),
        static_cast<int>(msg.size()),
        hash.data(),
        &hashLen
    );

    return std::string{reinterpret_cast<char const*>(hash.data()), hashLen};
}

int main(int argc, char **argv){
  cout << "Hello" << endl;
  string_view key = "pokemon";
  string_view msg = "abcd";
  std::string result = CalcHmacSHA256(key, msg);
  cout << result << endl;
  return 1;
}
