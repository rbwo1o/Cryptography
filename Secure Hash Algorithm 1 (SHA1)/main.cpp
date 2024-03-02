#include <iostream>
#include "SHA1.h"
#include <string>

using namespace std;

int main()
{
    SHA1 sha1;

    cout << "----- PROJECT:MAC ATTACK -----" << endl;
    cout << "Part 1 - Implement SHA-1" << endl << endl;
    
    cout << sha1.digest("This is a test of SHA-1.") << endl;
    cout << sha1.digest("Kerckhoff's principle is the foundation on which modern cryptography is built.") << endl;
    cout << sha1.digest("SHA-1 is no longer considered a secure hashing algorithm.") << endl;
    cout << sha1.digest("SHA-2 or SHA-3 should be used in place of SHA-1.") << endl;
    cout << sha1.digest("Never roll your own crypto!") << endl;
    
    return 0;
}