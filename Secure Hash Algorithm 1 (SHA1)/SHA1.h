#ifndef SHA1_H
#define SHA1_H

#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

using namespace std;

class SHA1
{
    public:
        // K[t] is the constance value to be used for the iteration t of the hash computation
        const uint32_t K[4] = 
        {
            0x5a827999,
            0x6ed9eba1,
            0x8f1bbcdc,
            0xca62c1d6
        };

        // For SHA1, the initial hash value H[0] shall consist of the following five 32-bit words in hex
        uint32_t H0, H1, H2, H3, H4;

        string pad_message(string);
        uint32_t ROTL(uint32_t x, int n);
        
        void processBlocks(string&);
        void processBlock(string&);

        uint32_t Ch(uint32_t, uint32_t, uint32_t);
        uint32_t Maj(uint32_t, uint32_t, uint32_t);
        uint32_t Parity(uint32_t, uint32_t, uint32_t);

        string getHash();
        string digest(string);

};


#endif