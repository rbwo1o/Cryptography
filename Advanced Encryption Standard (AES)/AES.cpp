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



































//--------------------------------------
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
        //cout << "temp: " << hex << setw(8) << setfill('0') << static_cast<int>(temp) << endl;
        //cout << "after rotWord: " << hex << setw(8) << setfill('0') << static_cast<int>(rotWord(temp)) << endl;
        //cout << "after subWord: " << hex << setw(8) << setfill('0') << static_cast<int>(subWord(rotWord(temp))) << endl;
        //cout << "rcon[i/Nk]: " << hex << setw(8) << setfill('0') << static_cast<int>( Rcon[i/Nk - 1] ) << endl;
        //cout << "After XOR with Rcon: " << hex << setw(8) << setfill('0') << static_cast<int>( subWord(rotWord(temp)) ^ Rcon[i/Nk - 1] ) << endl;
        //cout << "w[i-Nk]: " << hex << setw(8) << setfill('0') << static_cast<int>( subWord( w.at(i-Nk) ) ) << endl;
        //cout << "w[i] = temp XOR w[i-k]: " << hex << setw(8) << setfill('0') << static_cast<int>( (subWord(rotWord(temp)) ^ Rcon[i/Nk]) ^ w.at(i-Nk) ) << endl;
        //cout << endl << endl << endl;

        if(i % Nk == 0)
        {
            temp = subWord(rotWord(temp)) ^ Rcon[i/Nk - 1];
        }
        else if(Nk > 6 && i % Nk == 4)
        {
            temp = subWord(temp);
        }

        w.push_back(w.at(i - Nk) ^ temp);
    }

    this->w = w;

}







void AES::initRcon(int Nr)
{
    uint8_t rvalue = 0x01;

    cout << "--- RCON ---" << endl;
    for(int i = 0; i < Nr; i++)
    {
        uint32_t rword = static_cast<uint32_t>( rvalue ) << 24; // {x[i-1]}, {00}, {00}, {00} -> {x[i-1]000000}
        
        cout << "0x" << hex << static_cast<int>(rword) << endl;
        this->Rcon.push_back(rword);
        rvalue = xtime(rvalue);
    }
}











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






void AES::printKeySchedule()
{
    // TEST
    cout << "-- Key Schedule (w) --" << endl;
    int count = 0;
    for(int i = 0; i < this->w.size(); i+=4)
    {
        cout << count << "). 0x" << hex << setw(8) << setfill('0') << static_cast<int>( this->w.at(i) ) << static_cast<int>( this->w.at(i+1) ) << static_cast<int>( this->w.at(i+2) ) << static_cast<int>( this->w.at(i+3) ) << endl;
        //cout << count << "). 0x" << hex << setw(8) << setfill('0') <<  static_cast<int>( w.at(i) ) << endl;
        count++;
    }
}
































AES::AES(string input, string key)
{
    // input is a fixed length of 16 bytes ??
    this->Nb = 4;
    
    initState(input);
    printState();

    initKey(key);
    initRcon(this->Nr);

    printKey();
    KeyExpansion(this->key, this->w, this->Nk);
}




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


void AES::printState()
{
    cout << "--- state ---" << endl;
    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            cout << hex << setw(2) << setfill('0') << static_cast<int>( state[i][j] ) << " ";
            if(j == 3)
            {
                cout << endl;
            }
        }
    }
}




void AES::initKey(string key)
{
    switch((key.length() / 2) * 8) // 128, 192, 256
    {
        case 128:
        {
            cout << "--- AES 128 ---" << endl;
            this->Nk = 4;
            this->Nr = 10;
            break;
        }
        case 192:
        {
            cout << "--- AES 192 ---" << endl;
            this->Nk = 6;
            this->Nr= 12;
            break;
        }
        case 256:
        {
            cout << "--- AES 256 ---" << endl;
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
        cout << "0b " << hex << static_cast<int>( byte ) << endl;
    }
}




















void AES::Cipher()
{
    // we have state
    // we have key schedule
    
    // 1) add round key
    // printState();
    //cout << this->w.size() / 4 << endl;
    //printKeySchedule();
    //cout << "--- START ---" << endl;
    cout << endl;
    printState();
    int index = 0;
    AddRoundKey(this->state, this->w, index);
    index += 4;
    //cout << "-- AFTER FIRST XOR-- " << endl;
    cout << endl;
    cout << endl;
    printState();

    for(int i = 0; i < Nr - 1; i++)
    {
        SubBytes(this->state);
        //cout << i+1 << ") --- AFTER SUB BYTES ---" << endl;
        //cout << endl;
        //printState();
        // loop
        ShiftRows(this->state);
        //cout << i+1 << ") --- AFTER SHIFT ROWS ---" << endl;
        //cout << endl;
        //printState();
        //printState();
        MixColumns(this->state);
        //cout << i+1 << ") --- AFTER MIX COLUMNS ---" << endl;
        //cout << endl;
        //printState();
        cout << endl;
        
        AddRoundKey(this->state, this->w, index);
        //cout << i+1 << ") --- AFTER ROUND KEY ---" << endl;
        //cout << endl;
        printState();
        cout << endl;
        index += 4;
        //printState();
    }

    // last round
    SubBytes(this->state);
    ShiftRows(this->state);
    AddRoundKey(this->state, this->w, index);
    index += 4;
    //cout << "--- CIPHER TEXT ---" << endl;
    printState();
}



// CIPHER
void AES::AddRoundKey(uint8_t (&state)[4][4], vector<uint32_t> w, int index) // pass the location of the offset of the key schedule
{
    cout << "XOR with value" << endl;
    for(int i = 0; i < 4; i++)
    {
        //cout << "Here" << endl;
        // get state column word
        uint32_t word = static_cast<uint32_t>( state[0][i] ) << 24 |
                        static_cast<uint32_t>( state[1][i] ) << 16 |
                        static_cast<uint32_t>( state[2][i] ) << 8 |
                        static_cast<uint32_t>( state[3][i] );
        
        //cout << "Here now" << endl;
        // XOR by keyschedule offset [i]
        word ^= w.at(i+index);
        
        cout << hex << setw(8) << setfill('0') << word << endl;
        //cout << hex << setw(8) << setfill('0') << w.at(i+index) << endl;
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
    //cout << endl << endl;
}








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










void AES::ShiftRows(uint8_t (&state)[4][4])
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

            state[i][0] = r1;
            state[i][1] = r2;
            state[i][2] = r3;
            state[i][3] = r0;
        }
    }
}









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