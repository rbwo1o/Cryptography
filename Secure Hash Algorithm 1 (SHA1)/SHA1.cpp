#include "SHA1.h"

string SHA1::pad_message(string message)
{
    uint64_t originalLength = message.length() * 8;

    // append a single '1' bit
    string paddedMessage = message + static_cast<char>(0x80);

    size_t paddingLength = (448 - ((originalLength + 8) % 512) + 512) % 512;

    // append the 0s
    for(int i = 0; i < paddingLength; i+=8)
    {
        paddedMessage += static_cast<char>(0x00);
    }

    // append the bytes of the 64 bit original length 
    paddedMessage += static_cast<char>((originalLength >> 56) & 0xFF);
    paddedMessage += static_cast<char>((originalLength >> 48) & 0xFF);
    paddedMessage += static_cast<char>((originalLength >> 40) & 0xFF);
    paddedMessage += static_cast<char>((originalLength >> 32) & 0xFF);
    paddedMessage += static_cast<char>((originalLength >> 24) & 0xFF);
    paddedMessage += static_cast<char>((originalLength >> 16) & 0xFF);
    paddedMessage += static_cast<char>((originalLength >> 8) & 0xFF);
    paddedMessage += static_cast<char>(originalLength & 0xFF);

    return paddedMessage;
}





/* Function: ROTL
 * Parameters: a 32 bit word to be shifted, and the number of positions to circular shift the word to the left
 * Return: a 32 bit word that has been circularly left shifted by n positions.
 * Description: The rotate left (circular left shift) operation is defined by ROTL(x, n) 
 *              where x is a w-bit(32) word and n is an integer with 0 <= n <= w(32) is defined by
 *              ROTL(x, n) =  (x << n) | (x >> (w - n))
 *              Thus ROTL(x, n) is equivalent to a circular shift (rotation) of x by n positions to the left.
 * 
*/
uint32_t SHA1::ROTL(uint32_t x, int n)
{
    return (x << n) ^ (x >> (32 - n));
}


uint32_t SHA1::Parity(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}



uint32_t SHA1::Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}


uint32_t SHA1::Ch(uint32_t x, uint32_t y, uint32_t z) // !!!
{
    return (x & y) ^ ((~x) & z);
}






// iterate through each 64 byte (512 bit) block
void SHA1::processBlocks(string& paddedMessage)
{
    // Initialize hash values
    this->H0 = 0x67452301;
    this->H1 = 0xEFCDAB89;
    this->H2 = 0x98BADCFE;
    this->H3 = 0x10325476;
    this->H4 = 0xC3D2E1F0;

    for(int i = 0; i < paddedMessage.length(); i+=64)
    {
        string block = paddedMessage.substr(i, 64);
        processBlock(block);
    }
}




// process the block
void SHA1::processBlock(string& block) // this is coming in at 64 bytes (512 bits)
{
    // prepare the message schedule
    vector<uint32_t> W(80); // of size 80

    // populate first 16 words 
    for(int t = 0; t < 16; t++)
    {
        // 0 <= t <= 15
        W[t] = (static_cast<uint8_t>(block[t * 4]) << 24) |
                 (static_cast<uint8_t>(block[t * 4 + 1]) << 16) |
                 (static_cast<uint8_t>(block[t * 4 + 2]) << 8) |
                 static_cast<uint8_t>(block[t * 4 + 3]);
    }

    // expand the word schedule to 80
    for(int t = 16; t < 80; t++)
    {
        W[t] = ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    // initialize the five working variables a, b, c, d, and e with the (i-1)st hash value
    uint32_t a = this->H0;
    uint32_t b = this->H1;
    uint32_t c = this->H2;
    uint32_t d = this->H3;
    uint32_t e = this->H4;

    // main loop
    for(int i = 0; i < 80; i++)
    {
        uint32_t f, k;

        if(i < 20)
        {
            f = Ch(b, c, d);
            k = this->K[0];
        }
        else if(i < 40)
        {
            f = Parity(b, c, d);
            k = this->K[1];
        }
        else if(i < 60)
        {
            f = Maj(b, c, d);
            k = this->K[2];
        }
        else
        {
            f = Parity(b, c, d);
            k = this->K[3];
        }
    

        uint32_t temp = ROTL(a, 5) + f + e + k + W[i];
        e = d;
        d = c;
        c = ROTL(b, 30);
        b = a;
        a = temp;
    }

    // Update hash values
    this->H0 += a;
    this->H1 += b;
    this->H2 += c;
    this->H3 += d;
    this->H4 += e;
}





string SHA1::getHash()
{
    ostringstream oss;
    oss << hex << setfill('0') << setw(8) << this->H0
               << setw(8) << this->H1
               << setw(8) << this->H2
               << setw(8) << this->H3
               << setw(8) << this->H4;

    return oss.str(); 
}




string SHA1::digest(string message)
{
    string paddedMessage = pad_message(message);
    processBlocks(paddedMessage);
    return getHash();
}