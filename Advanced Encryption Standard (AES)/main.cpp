/*
 * Author:          Robert Blaine Wilson
 * 
 * Date:            2/17/2023
 * 
 * Synopsis:        This program is the implementation of the Rijndael AES algorithm as described in https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 *                  This application performs block level encryption and decryption using each key size described in AES.
 *
 * Compilation:     g++ -c main.cpp AES.cpp
 *                  g++ -o aes main.o AES.o
 * 
 * Usage:           ./aes
*/

#include <iostream>
#include "AES.h"


int main()
{
    // clear text
    string input = "00112233445566778899aabbccddeeff";

    // Keys
    string key128 = "000102030405060708090a0b0c0d0e0f";
    string key192 = "000102030405060708090a0b0c0d0e0f1011121314151617";
    string key256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    // hard-coded cipher text used as input for decryption
    string dInput = "69c4e0d86a7b0430d8cdb78070b4c55a";
    string dInput192 = "dda97ca4864cdfe06eaf70a0ec0d7191";
    string dInput256 = "8ea2b7ca516745bfeafc49904b496089";



    /* class-based implementation */

    AES aes128(input, key128, 1); // aes encryption object
    aes128.Cipher(); // cipher
    cout << endl;

    AES Iaes128(dInput, key128, 0); // aes decryption object
    Iaes128.Decipher(); // call decipher
    cout << endl;

    AES aes192(input, key192, 1);
    aes192.Cipher();
    cout << endl;

    AES Iaes192(dInput192, key192, 0);
    Iaes192.Decipher();
    cout << endl;

    AES aes256(input, key256, 1);
    aes256.Cipher();
    cout << endl;

    AES Iaes256(dInput256, key256, 0);
    Iaes256.Decipher();

    return 0;
}