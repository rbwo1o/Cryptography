/*
 * Author:          Robert Blaine Wilson
 * 
 * Date:            2/17/2023
 * 
 * Synopsis:        This file contains AES class method definitions. 
*/

#include "AES.h"


// -------------------------------------- FINITE FIELD ARITHMETIC -------------------------------------- 

/* Function: ffAdd
 * Parameters: The two elements of the finite field to be added
 * Return: The sum of two elements in a finite field
 * Description: The addition of two elements in a finite field is achieved by “adding” the coefficients for the corresponding powers in the polynomials for the two elements. 
 *              The addition is performed with the XOR operation
*/
uint8_t AES::ffAdd(uint8_t a, uint8_t b)
{
    return a ^ b;
}




/* Function: xtime
 * Parameters: A byte polynomial to be multiplied by x
 * Return: The resulting reduced polynomial
 * Description: This function multiplies the byte polynomial by x by shifting the bits of the polynomial left by 1.
 *              If the most signicificant bit of the parameter is set, the resulting polynomial is reduced by XOR with a irreducible polynomial 0x1b
*/
uint8_t AES::xtime(uint8_t byte)
{
    uint8_t result = byte << 1; // left shift by 1

    // check if the most significant bit is set
    if(byte & 0x80)
    {
        // XOR with the irreducible polynomial 0x1b
        result ^= 0x1b;
    }

    return result;
}




/* Function: ffMultiply
 * Parameters: A multiplicand byte a, and a multiplier byte b to be multiplied in the finite field
 * Return: A byte that represents the result of the finite field multiplication
 * Description: Multiplication by higher powers of x can be implemented by repeated application of xtime(). 
 *              By adding intermediate results, multiplication by any constant can be implemented.
 *              This function multiplies two elements of a finite field by iterating through the multiplicand,
 *              if the current iteration bit is set, the indermediate sum is XOR by the current value of the multiplier
 *              Note: There is no need to prepare the values on the 7th iteration because it is the last round.
*/
uint8_t AES::ffMultiply(uint8_t a, uint8_t b)
{
    uint8_t sum = 0;

    for(int i = 0; i < 8; i++)
    {
        // check if a[i] is set
        if(a & 0x1)
        {
            // XOR current sum with current multiplier
            sum ^= b;
        }

        // prepare multiplier and multiplicand for the next round
        if(i < 7)
        {
            // update multiplier using xtime()
            b = xtime(b);
            // right shift the bits of the multiplicand by 1; this is used prepare the next iteration bit a[i+1]
            a >>= 1;
        }
    }

    return sum;
}




// -------------------------------------- S-Box -------------------------------------- 

/* Function: SBoxSub
 * Parameters: A byte to substitute
 * Return: The substitution value of the byte parameter
 * Description: This function extracts the row and column data from the byte parameter and returns its corresponding position in the S-Box table
*/
uint8_t AES::sBoxSub(uint8_t byte)
{
    // extract the row and column for the lookup table
    int row = static_cast<int>( (byte >> 4) & 0xF );
    int col = static_cast<int>( byte & 0xF );

    return this->SBox[(row * 16) + col];
}




// -------------------------------------- KEY EXPANSION -------------------------------------- 

/* Function: rotWord
 * Parameters: a word to perform the cyclic rotation
 * Return: A word that has experienced cyclic rotation
 * Description: The function RotWord() takes a word [a0,a1,a2,a3] as input, performs a cyclic permutation, and returns the word [a1,a2,a3,a0].
*/
uint32_t AES::rotWord(uint32_t word)
{
    // extract the 4 bytes from the word
    uint8_t b0 = (word >> 24) & 0xFF;
    uint8_t b1 = (word >> 16) & 0xFF;
    uint8_t b2 = (word >> 8) & 0xFF;
    uint8_t b3 = word & 0xFF;

    // cyclic permutation: [a0, a1, a2, a3] -> [a1, a2, a3, a0]
    uint32_t w = static_cast<uint32_t>(b1) << 24 |
                 static_cast<uint32_t>(b2) << 16 |
                 static_cast<uint32_t>(b3) << 8 |
                 static_cast<uint32_t>(b0);
    
    return w;
}




/* Function: subWord
 * Parameters: a word to substitute
 * Return: A word that represents a collection of substituted bytes from the word parameter
 * Description: This function takes a four-byte input word and substitutes each byte in that word with its appropriate value from the S-Box.
*/
uint32_t AES::subWord(uint32_t word)
{
    // extract bytes from word
    uint8_t b0 = (word >> 24) & 0xFF;
    uint8_t b1 = (word >> 16) & 0xFF;
    uint8_t b2 = (word >> 8) & 0xFF;
    uint8_t b3 = word & 0xFF;

    // create a new word with substituted byte values
    uint32_t w = static_cast<uint32_t>( sBoxSub(b0) ) << 24 |
                 static_cast<uint32_t>( sBoxSub(b1) ) << 16 |
                 static_cast<uint32_t>( sBoxSub(b2) ) << 8 |
                 static_cast<uint32_t>( sBoxSub(b3) );

    return w;
}




/* Function: KeyExpansion
 * Parameters: A vector of bytes that represents the cipher key, a vector of words that represends the key schedule, an integer value for the number of words in the cipher key
 * Return: None
 * Description: This function generates the key schedule to be used based on the provided cipher key.
*/
void AES::KeyExpansion(vector<uint8_t> key, vector<uint32_t> w, int Nk)
{
    for(int i = 0; i < Nk; i++)
    {


        uint32_t word = static_cast<uint32_t>( key.at( 4 * i ) ) << 24 |
                        static_cast<uint32_t>( key.at( (4 * i) + 1 ) ) << 16 |
                        static_cast<uint32_t>( key.at( (4 * i) + 2 ) ) << 8 |
                        static_cast<uint32_t>( key.at( (4 * i) + 3 ) );
        
        //cout << "0x " << static_cast<int>(key.at( 4 * i )) << static_cast<int>(key.at( 4 * i ) +1) << static_cast<int>(key.at( 4 * i )+2) << static_cast<int>(key.at( 4 * i )+3) << endl;

        w.push_back(word);
    }


    uint32_t temp;
    for(int i = Nk; i < this->Nb * (this->Nr + 1); i++)
    {
        temp = w.at(i-1);

        if(i % Nk == 0)
        {
            temp = subWord(rotWord(temp)) ^ Rcon[(i/Nk) - 1];
        }
        else if(Nk > 6 && i % Nk == 4)
        {
            temp = subWord(temp);
        }

        w.push_back(w.at(i - Nk) ^ temp);
    }

    this->w = w;

}




/* Function: initRcon
 * Parameters: An integer representing the number of rounds
 * Return: None
 * Description: This function initializes the constant round word array used in key expansion
*/
void AES::initRcon(int Nr)
{
    uint8_t rvalue = 0x01;

    for(int i = 0; i < Nr; i++)
    {
        uint32_t rword = static_cast<uint32_t>( rvalue ) << 24; // {x[i-1]}, {00}, {00}, {00} -> {x[i-1]000000}
        
        this->Rcon.push_back(rword);
        rvalue = xtime(rvalue);
    }
}




/* Function: printKey()
 * Parameters: None
 * Return: None
 * Description: This function prints the key vector in hexadecimal notation
*/
void AES::printKey()
{
    cout << "--- print key ---" << endl;
    cout << "0x ";
    for(int i = 0; i < this->key.size(); i++)
    {
        cout << hex << static_cast<int>(this->key.at(i)) << " ";
    }
    cout << endl;
}




/* Function: printKeySchedule
 * Parameters: None
 * Return: None
 * Description: This function prints each key to be used in the key schedule w
*/
void AES::printKeySchedule()
{
    // TEST
    cout << "-- Key Schedule (w) --" << endl;
    int count = 0;
    for(int i = 0; i < this->w.size(); i+=4)
    {
        cout << count << "). 0x" << hex << setw(8) << setfill('0') << static_cast<int>( this->w.at(i) ) << static_cast<int>( this->w.at(i+1) ) << static_cast<int>( this->w.at(i+2) ) << static_cast<int>( this->w.at(i+3) ) << endl;
        count++;
    }
}




/* Function: Constructor
 * Parameters: The input string, and key string to be used by AES
 * Return: an AES object
 * Description: The contrsuctor intiializes the input, key, and dependency variables that are used throughout the algorithm
*/
AES::AES(string input, string key, bool encrypt)
{
    this->Nb = 4;
    
    initState(input);

    initKey(key, encrypt);

    if(encrypt)
    {
        cout << endl << "PLAINTEXT:          " << input << endl;
        cout << "KEY:                " << key << endl << endl;
    }


    initRcon(this->Nr);

    KeyExpansion(this->key, this->w, this->Nk);
}




/* Function: initState
 * Parameters: a string representing the input bytes
 * Return: None
 * Desciption: This function initializes the 2D state array by converting the byte string into bytes and placing the bytes into the array in column major order
*/
void AES::initState(string input)
{
    vector<int> bytes;
    for(int i = 0; i < input.length(); i+=2)
    {
        uint8_t byte = static_cast<uint8_t>( stoi( input.substr(i, 2), 0, 16 ) );
        bytes.push_back(byte);
    }

    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            state[j][i] = bytes.at((i*4) + j);
        }
    }
}




/* Function: printState
 * Parameters: None
 * Return: None
 * Description: This function prints the 2D state array
*/
void AES::printState()
{
   // cout << "--- state ---" << endl;
    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            cout << hex << setw(2) << setfill('0') << static_cast<int>( state[j][i] );
            //if(j == 3)
            //{
                //cout << endl;
            //}
        }
    }
}




/* Function: initKey
 * Parameters: a string value representing the key
 * Return: None
 * Description: This function initializes the key vector atttribute by converting the key string into an array of bytes to be used by AES
*/
void AES::initKey(string key, bool encrypt)
{
    if(!encrypt)
    {
        cout << "INVERSE CIPHER (DECRYPT):" << endl;
    }

    switch((key.length() / 2) * 8) // 128, 192, 256
    {
        case 128:
        {
            if(encrypt)
            {
                cout << "C.1   AES-128 (Nk=4, Nr=10)" << endl;
            }
            this->Nk = 4;
            this->Nr = 10;
            break;
        }
        case 192:
        {
            if(encrypt)
            {
                cout << "C.2   AES-192 (Nk=6, Nr=12)" << endl;
            }
            this->Nk = 6;
            this->Nr= 12;
            break;
        }
        case 256:
        {
            if(encrypt)
            {
                cout << "C.3   AES-256 (Nk=8, Nr=14)" << endl;
            }
            this->Nk = 8;
            this->Nr = 14;
            break;
        }
        default:
        {
            return;
        }
    }

    for(int i = 0; i < key.length(); i+=2)
    {
        uint8_t byte = static_cast<uint8_t>( ( stoi (key.substr(i, 2), 0, 16) ) );
        this->key.push_back(byte);
    }
}




/* Function: Cipher
 * Parameters: None
 * Return: None
 * Description: This function performs AES cipher on the input state with the key as decribed in AES
*/
void AES::Cipher()
{
    cout << "CIPHER (ENCRYPT):" << endl;
    
    // we have state
    // we have key schedule
    
    cout << "round[ 0].input     ";
    printState();
    cout << endl;

    int index = 0;
    cout << "round[" << setw(2) << setfill(' ') << 0 << "].k_sch     ";
    AddRoundKey(this->state, this->w, index);
    index += 4;

    int i = 0;
    for(i = 0; i < Nr - 1; i++)
    {
        cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].start     ";
        printState();
        cout << endl;

        SubBytes(this->state);
        cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].s_box     ";
        printState();
        cout << endl;

        ShiftRows(this->state);
        cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].s_row     ";
        printState();
        cout << endl;

        MixColumns(this->state);
        cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].m_col     ";
        printState();
        cout << endl;

        
        cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].k_sch     ";
        AddRoundKey(this->state, this->w, index); // key schedule!!

        index += 4;
    }

    // last round
    cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].start     ";
    printState();
    cout << endl;

    SubBytes(this->state);
    cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].s_box     ";
    printState();
    cout << endl;

    ShiftRows(this->state);
    cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].s_row     ";
    printState();
    cout << endl;

    cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].k_sch     ";
    AddRoundKey(this->state, this->w, index);

    cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].output    ";
    printState();
    index += 4;
    cout << endl;
}




/* AddRoundKey
 * Parameters: A reference to the 2D state array, the Key Schedule vector, and the index of the round key to XOR
 * Return: None
 * Description: This transformation adds a round key to the state using XOR
*/
void AES::AddRoundKey(uint8_t (&state)[4][4], vector<uint32_t> w, int index) // pass the location of the offset of the key schedule
{
    for(int i = 0; i < 4; i++)
    {
        // get state column word
        uint32_t word = static_cast<uint32_t>( state[0][i] ) << 24 |
                        static_cast<uint32_t>( state[1][i] ) << 16 |
                        static_cast<uint32_t>( state[2][i] ) << 8 |
                        static_cast<uint32_t>( state[3][i] );
        
        word ^= w.at(i+index);
        
        //cout << hex << setw(8) << setfill('0') << word << endl;
        cout << hex << setw(8) << setfill('0') << w.at(i+index);
        // put back in state
        uint8_t s0 = static_cast<uint8_t>( (word >> 24) & 0xFF );
        uint8_t s1 = static_cast<uint8_t>( (word >> 16) & 0xFF );
        uint8_t s2 = static_cast<uint8_t>( (word >> 8) & 0xFF );
        uint8_t s3 = static_cast<uint8_t>( word & 0xFF );

        state[0][i] = s0;
        state[1][i] = s1;
        state[2][i] = s2;
        state[3][i] = s3;
    }
    cout << endl;
}




/* Function: SubBytes
 * Parameters: A reference to the 2D state array
 * Return: None
 * Description: This transformation substitutes each byte in the state with its corresponding value from the S-Box
*/
void AES::SubBytes(uint8_t (&state)[4][4])
{
    for(int i = 0; i < 4; i++)
    {
        uint32_t word = static_cast<uint32_t>( state[0][i] ) << 24 |
                        static_cast<uint32_t>( state[1][i] ) << 16 |
                        static_cast<uint32_t>( state[2][i] ) << 8 |
                        static_cast<uint32_t>( state[3][i] );
        
        word = subWord(word);

        uint8_t s0 = static_cast<uint8_t>( (word >> 24) & 0xFF );
        uint8_t s1 = static_cast<uint8_t>( (word >> 16) & 0xFF );
        uint8_t s2 = static_cast<uint8_t>( (word >> 8) & 0xFF );
        uint8_t s3 = static_cast<uint8_t>( word & 0xFF );

        state[0][i] = s0;
        state[1][i] = s1;
        state[2][i] = s2;
        state[3][i] = s3;
    }
}




/* Function: ShiftRows
 * Parameters: A reference to the 2D state array
 * Return: None
 * Description: This transformation performs a circular shift on each row in the state
*/
void AES::ShiftRows(uint8_t (&state)[4][4])
{
    for(int i = 0; i < 4; i++)
    {   
        for(int j = 0; j < i; j++)
        {
            // get the row
            uint32_t row = static_cast<uint32_t>( (state[i][0] << 24) ) |
                        static_cast<uint32_t>( (state[i][1] << 16) ) |
                        static_cast<uint32_t>( (state[i][2] << 8) ) |
                        static_cast<uint32_t>( (state[i][3]) );

            uint8_t r0 = static_cast<uint8_t>( (row >> 24) & 0xFF );
            uint8_t r1 = static_cast<uint8_t>( (row >> 16) & 0xFF );
            uint8_t r2 = static_cast<uint8_t>( (row >> 8) & 0xFF );
            uint8_t r3 = static_cast<uint8_t>( row & 0xFF );

            state[i][0] = r1;
            state[i][1] = r2;
            state[i][2] = r3;
            state[i][3] = r0;
        }
    }
}




/* Function: MixColumns
 * Parameters: A reference to the 2D state array
 * Return: None
 * Description: This transformation treats each column in state as a four-term polynomial. This polynomial is multiplied (modulo another polynomial) by a fixed polynomial with coefficients
*/
void AES::MixColumns(uint8_t (&state)[4][4])
{
    // fixed polynomial matrix a(x)
    // a[4][4] = 
    // {
    //  {02, 03, 01, 01},    
    //  {01, 02, 03, 01}, 
    //  {01, 01, 02, 03}, 
    //  {03, 01, 01, 02} 
    // };

    //cout << "--- Mix Columns ---" << endl;

    for(int i = 0; i < this->Nb; i++)
    {
        uint8_t s0 = state[0][i];
        uint8_t s1 = state[1][i];
        uint8_t s2 = state[2][i];
        uint8_t s3 = state[3][i];

        state[0][i] = ffMultiply(0x02, s0) ^ ffMultiply(0x03, s1) ^ s2 ^ s3;
        state[1][i] = s0 ^ ffMultiply(0x02, s1) ^ ffMultiply(0x03, s2) ^ s3;
        state[2][i] = s0 ^ s1 ^ ffMultiply(0x02, s2) ^ ffMultiply(0x03, s3);
        state[3][i] = ffMultiply(0x03, s0) ^ s1 ^ s2 ^ ffMultiply(0x02, s3);
    }
}








// -------------------------------------- INVERSE METHODS -------------------------------------- 

/* Function: InvsBoxSub
 * Parameters: A byte to substitute
 * Return: The value of the byte's inverse substitution
 * Description: This function performs substitution on the inverse S-Box
*/
uint8_t AES::InvsBoxSub(uint8_t byte)
{
    // extract the row and column for the lookup table
    int row = static_cast<int>( (byte >> 4) & 0xF );
    int col = static_cast<int>( byte & 0xF );

    return this->InvSBox[(row * 16) + col];
}



/* Function: InvsBoxSub
 * Parameters: A word to substitute
 * Return: The value of the words's inverse substitution
 * Description: This function performs substitution on each byte of the word parameter in the inverse S-Box
*/
uint32_t AES::InvsubWord(uint32_t word)
{
    // extract bytes from word
    uint8_t b0 = (word >> 24) & 0xFF;
    uint8_t b1 = (word >> 16) & 0xFF;
    uint8_t b2 = (word >> 8) & 0xFF;
    uint8_t b3 = word & 0xFF;

    // create a new word with substituted byte values
    uint32_t w = static_cast<uint32_t>( InvsBoxSub(b0) ) << 24 |
                 static_cast<uint32_t>( InvsBoxSub(b1) ) << 16 |
                 static_cast<uint32_t>( InvsBoxSub(b2) ) << 8 |
                 static_cast<uint32_t>( InvsBoxSub(b3) );

    return w;
}




/* Function: InvSubBytes
 * Parameters: A reference to the 2D state array
 * Return: None
 * Description: This transformation substitutes each byte in the state with its corresponding value from the inverse S-Box, thus reversing the effect of a subBytes() operation
*/
void AES::InvSubBytes(uint8_t (&state)[4][4])
{
    for(int i = 0; i < 4; i++)
    {
        uint32_t word = static_cast<uint32_t>( state[0][i] ) << 24 |
                        static_cast<uint32_t>( state[1][i] ) << 16 |
                        static_cast<uint32_t>( state[2][i] ) << 8 |
                        static_cast<uint32_t>( state[3][i] );
        
        word = InvsubWord(word);

        uint8_t s0 = static_cast<uint8_t>( (word >> 24) & 0xFF );
        uint8_t s1 = static_cast<uint8_t>( (word >> 16) & 0xFF );
        uint8_t s2 = static_cast<uint8_t>( (word >> 8) & 0xFF );
        uint8_t s3 = static_cast<uint8_t>( word & 0xFF );

        state[0][i] = s0;
        state[1][i] = s1;
        state[2][i] = s2;
        state[3][i] = s3;
    }
}




/* Function: InvShiftRows
 * Parameters: A reference to the 2D state array
 * Return: None
 * Description: This transformation performs the inverse of shiftRows() on each row in the state
*/
void AES::InvShiftRows(uint8_t (&state)[4][4])
{
    //cout << "-- Shift Rows --" << endl;
    for(int i = 0; i < 4; i++)
    {   
        //cout << "0x " << hex << setw(8) << setfill('0') << static_cast<int>(row) << " " << endl;
        for(int j = 0; j < i; j++)
        {
            // get the row
            uint32_t row = static_cast<uint32_t>( (state[i][0] << 24) ) |
                        static_cast<uint32_t>( (state[i][1] << 16) ) |
                        static_cast<uint32_t>( (state[i][2] << 8) ) |
                        static_cast<uint32_t>( (state[i][3]) );

            uint8_t r0 = static_cast<uint8_t>( (row >> 24) & 0xFF );
            uint8_t r1 = static_cast<uint8_t>( (row >> 16) & 0xFF );
            uint8_t r2 = static_cast<uint8_t>( (row >> 8) & 0xFF );
            uint8_t r3 = static_cast<uint8_t>( row & 0xFF );

            state[i][0] = r3;
            state[i][1] = r0;
            state[i][2] = r1;
            state[i][3] = r2;
        }
    }
}




/* Function: InvMixColumns
 * Parameters: A reference to a 2D state array
 * Return: None
 * Description: This transformation is the inverse of mixColumns
*/
void AES::InvMixColumns(uint8_t (&state)[4][4])
{
    // fixed polynomial matrix a(x)
    // a[4][4] = 
    // {
    //  {0e, 0b, 0d, 09},    
    //  {09, 0e, 0b, 0d}, 
    //  {0d, 09, 0e, 0b}, 
    //  {0b, 0d, 09, 0e} 
    // };

    for(int i = 0; i < this->Nb; i++)
    {
        uint8_t s0 = state[0][i];
        uint8_t s1 = state[1][i];
        uint8_t s2 = state[2][i];
        uint8_t s3 = state[3][i];

        state[0][i] = ffMultiply(0x0e, s0) ^ ffMultiply(0x0b, s1) ^ ffMultiply(0x0d, s2) ^ ffMultiply(0x09, s3);
        state[1][i] = ffMultiply(0x09, s0) ^ ffMultiply(0x0e, s1) ^ ffMultiply(0x0b, s2) ^ ffMultiply(0x0d, s3);
        state[2][i] = ffMultiply(0x0d, s0) ^ ffMultiply(0x09, s1) ^ ffMultiply(0x0e, s2) ^ ffMultiply(0x0b, s3);
        state[3][i] = ffMultiply(0x0b, s0) ^ ffMultiply(0x0d, s1) ^ ffMultiply(0x09, s2) ^ ffMultiply(0x0e, s3);
    }
}




/* Function: Decipher
 * Parameters: None
 * Return: None
 * Description: This function performs AES inverse cipher on the input state with the key as decribed in AES
*/
void AES::Decipher()
{
    // we have state
    // we have key schedule
    
    cout << "round[ 0].iinput    ";
    printState();
    cout << endl;
 

    int index = (Nr*Nb);
    cout << "round[" << setw(2) << setfill(' ') << 0 << "].ik_sch    ";
    AddRoundKey(this->state, this->w, index);
    index -= 4;

    int i = 0;
    for(i = 0; i < Nr - 1; i++)
    {
        cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].istart    ";
        printState();
        cout << endl;

        InvShiftRows(this->state);
        cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].is_row    ";
        printState();
        cout << endl;

        InvSubBytes(this->state);
        cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].is_box    ";
        printState();
        cout << endl;
        
        cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].ik_sch    ";
        AddRoundKey(this->state, this->w, index);
        
        cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].ik_add    ";
        printState();
        InvMixColumns(this->state);

        cout << endl;
        index -= 4;
    }

    // last round
    cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].istart    ";
    printState();
    cout << endl;

    InvShiftRows(this->state);
    cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].is_row    ";
    printState();
    cout << endl;

    InvSubBytes(this->state);
    cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].is_box    ";
    printState();
    cout << endl;

    cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].ik_sch    ";
    AddRoundKey(this->state, this->w, index);

    cout << "round[" << setw(2) << setfill(' ') << dec << i+1 << "].ioutput   ";
    printState();
    cout << endl;
}