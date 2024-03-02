import hashlib
import random
import string

bit_sizes = [8, 10, 12, 14, 16, 18, 20, 22]


# trunc sha1 wrapper
def Trunc_SHA1(text, bits):
    # create SHA1 object
    sha1 = hashlib.sha1()
    sha1.update(text.encode('utf-8'))

    # hex digest int
    hexDigestInt = int(sha1.hexdigest(), 16)

    return hex( hexDigestInt & ((1 << bits) - 1) )




# pre image attack
def preimage_attack(bits):
    # results
    results = []
    # get target hash
    target_hash = Trunc_SHA1(generate_random_string(40), bits)

    for i in range(50):
        candidate_hash = Trunc_SHA1(generate_random_string(40), bits)
        attempts = 0
        while candidate_hash != target_hash:
            candidate_hash = Trunc_SHA1(generate_random_string(40), bits)
            attempts += 1
        print(attempts)
        results.append(attempts)
    return results





# collision attack
def collision_attack(bits):
    # results
    results = []
    
    
    for i in range(50):
        hashes = []
        candidatehash = Trunc_SHA1(generate_random_string(40), bits)

        attempts = 0
        while candidatehash not in hashes:
            attempts += 1
            hashes.append(candidatehash)
            candidatehash = Trunc_SHA1(generate_random_string(40), bits)
        #print(f"{firstHash}    ----    {secondHash}")
        print(str(attempts))
        results.append(attempts)
    return results




def generate_random_string(length):
    characters = string.ascii_letters
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string



#preimage_attack(22)
collision_attack(22)
# 50 rounds of pre-image attacks

#print(generate_random_string(2))
#print(generate_random_string(4))
#print(generate_random_string(8))

# 50 rounds of collision attacks

# operate on 8, 10, 12, 14, 16, 18, 20, 22 bits

# custom data structure [ [bits, attempts before success], ]
