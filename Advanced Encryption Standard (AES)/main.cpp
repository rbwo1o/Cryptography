#include <iostream>
#include "AES.h"


int main()
{
    string input = "00112233445566778899aabbccddeeff";

    string key128 = "000102030405060708090a0b0c0d0e0f";
    string k1 = "2b7e151628aed2a6abf7158809cf4f3c";
    string key192 = "000102030405060708090a0b0c0d0e0f1011121314151617";
    string key256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    string dInput = "69c4e0d86a7b0430d8cdb78070b4c55a";
    string dInput192 = "dda97ca4864cdfe06eaf70a0ec0d7191";
    string dInput256 = "8ea2b7ca516745bfeafc49904b496089";

    string testInput = "3243f6a8885a308d313198a2e0370734";
    string testKey = "2b7e151628aed2a6abf7158809cf4f3c";

    AES aes128(dInput256, key256);
    aes128.Decipher();
    
    //AES aes192(input, key192);
   
    //AES aes256(input, key256);

    return 0;
}