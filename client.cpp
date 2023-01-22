#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <iomanip>
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

int main(int argc, char **argv){
    std::string key = "Pokemon";
    std::string msg = "foo";
    std::string_view key_view{key};
    std::string_view msg_view{msg};
    std::cout << CalcHmacSHA256(key_view, msg_view) << std::endl;
}
