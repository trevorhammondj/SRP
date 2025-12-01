import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# My functions from PKC project

#fast modular exponentiation function, this function basically distributes
#modular arithimetic throughout an exponent's multiplication through converting to
#binary 
def mod_exp(base, exp, mod):
    result = 1
    base = base % mod  #makeing sure the base is smaller than the modulus
    
    #processing each bit of the exponent
    while exp > 0:
        
        #checks if the lowest bit is 1
        if exp & 1:
            #multiplys the result by the current base value and
            #the distributed modular arithimetic
            result = (result * base) % mod
        
        #squares the base for the next bit position and
        #the distributed modular arithimetic
        base = (base * base) % mod
        
        #shifts right to move to the next bit
        exp = exp >> 1
    
    return result

#this function tests if a number is prime, although not with 100% certainty
#although with enough rounds performed like around 10, the chance of being wrong
#is practically 0.
def miller_rabin(p, num_rounds=10):
    #handles the small cases first
    if p < 2:
        return False
    if p == 2:
        return True  #since 2 is prime
    if p == 3:
        return True  #since 3 is prime
    if p % 2 == 0:
        return False  #even numbers > 2 are not prime
    
    #to start write p-1 as 2^s * d
    #then keep dividing by 2 until we get an odd number
    s = 0
    d = p - 1
    
    while d % 2 == 0:
        d = d // 2
        s = s + 1
    
    #p - 1 = 2^s * d, and d is odd
    
    #test with random witnesses
    for round_num in range(num_rounds):
        
        #pick a random witness between 2 and p-2
        a = random.randint(2, p - 2)
        
        #calculate x = a^d mod p
        x = mod_exp(a, d, p)
        
        #if x is 1 or p-1, which is -1 mod p, this witness passes
        if x == 1 or x == p - 1:
            continue  #try the next witness
        
        #square x up to s-1 times
        found_minus_one = False
        
        for j in range(s - 1):
            x = mod_exp(x, 2, p)  #x = x^2 mod p
            
            #if i hit -1, which is p-1, this witness passes
            if x == p - 1:
                found_minus_one = True
                break
        
        #if i never found -1, then p is definitely composite
        if not found_minus_one:
            return False
    
    #all witnesses passed so p is probably prime
    return True

#basic gcd function that uses the euclidean algorithm
#that being: gcd(a, b) = gcd(b, a mod b)
def gcd(a, b):
    while b != 0:
        remainder = a % b
        a = b
        b = remainder
    return a


#the extended euclidean algorithm which
#calculates gcd(a,b) = a * s + b * t and returns (gcd, s, t)
#using from slides a = r_(-2), b = r_(-1)
#stops when r_n divides r_(n-1), gcd = r_n
def extended_euclidean(a, b):
    
    #initializing using notation from the slides
    #r_(-2) = a, r_(-1) = b
    r_minus2 = a
    r_minus1 = b
    
    #s_(-2) = 1, s_(-1) = 0 (since a = a*1 + b*0)
    s_minus2 = 1
    s_minus1 = 0
    
    #t_(-2) = 0, t_(-1) = 1 (since b = a*0 + b*1)
    t_minus2 = 0
    t_minus1 = 1
    
    #keep iterating until the remainder is 0
    while r_minus1 != 0:
        
        #calculate the quotient: q_i = r_(i-2) // r_(i-1)
        q = r_minus2 // r_minus1
        
        #calculate the new remainder: r_i = r_(i-2) - r_(i-1) * q_i
        r_new = r_minus2 - r_minus1 * q
        
        #calculate the new s: s_i = s_(i-2) - s_(i-1) * q_i
        s_new = s_minus2 - s_minus1 * q
        
        #calculate the new t: t_i = t_(i-2) - t_(i-1) * q_i
        t_new = t_minus2 - t_minus1 * q
        
        #shift everything down for next iteration
        r_minus2 = r_minus1
        r_minus1 = r_new
        
        s_minus2 = s_minus1
        s_minus1 = s_new
        
        t_minus2 = t_minus1
        t_minus1 = t_new
    
    #r_minus2 now holds the gcd
    #s_minus2 and t_minus2 hold s and t
    gcd_result = r_minus2
    s = s_minus2
    t = t_minus2
    
    return (gcd_result, s, t)

#converts an integer to bytes
def int_to_bytes(num):
    #calculates the min number of bytes needed to represent the integer
    byte_len = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_len, byteorder='big')

#converts from bytes to ints
def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

#########################################
#
#new functions for this project are below
#
#########################################

#sha256 hash function, takes one or multiple inputs and hashes them together
def hash_sha256(*values):
    hasher = hashlib.sha256()
    for val in values:
        #if the value is an int, convert to big endian bytes
        if isinstance(val, int):
            hasher.update(int_to_bytes(val))
        #if the valuse is a string, encode it to bytes using ascii
        elif isinstance(val, str):
            hasher.update(val.encode('ascii'))
        #if the value is already bytes just use the bytes directly
        elif isinstance(val, bytes):
            hasher.update(val)
        #if the value is none of these throw error and give the type it is
        else:
            raise TypeError(f"Incorrect type: {type(val)}")
    return hasher.digest()

#hashes a value using the sha256 hash function
#and returns the hash as an integer
def hash_to_int(*values):
    digest = hash_sha256(*values)
    return bytes_to_int(digest)

#xors two bytes if there are of equal length
def xor_bytes(b1, b2):
    #checks the string lengths, gives the lengths if they are different
    if len(b1) != len(b2):
        raise ValueError(f"Byte strings are not the same length.\n"
                         f"b1 length: {len(b1)}\n"
                         f"b2 length: {len(b2)}")
    
    #a list to store the xor results
    results = []

    #loops through each pair of bytes and xors them
    for i in range(len(b1)):
        xored_byte = b1[i] ^ b2[i]
        results.append(xored_byte)
    #converts the list of ints back into bytes
    return bytes(results)

#my srp implementation
def main_srp():    
    #get 'g' and 'p' from the server
        
    #after a few runs i believe 'g' is always 5, but you can uncomment the code
    #to input a different 'g' value
    g = 5 #int(input("Enter g value: ").strip())
    p = int(input("Enter p value: ").strip())
    
    #select a random 'a' as the private key which should be less than 'p'
    a = random.randint(2, p - 2)

    #calculate the public key: using diffehellman
    g_a = mod_exp(g, a, p)
    
    #print the value for the server
    print(f"\nThe public key: ")
    print(f"g^a = {g_a}\n")
        
    #the values needed from the server for the next step

    #grabbing the password
    password = input("Enter the password: ").strip()

    #grabbing the salt(hex)
    salt_hex = input("Enter salt(hex): ").strip()
    salt = bytes.fromhex(salt_hex) #converting the hex string to bytes
        
    #grabbing the B_bar value
    B_bar = int(input("Enter B_bar (server's public value): ").strip())
    
    #grabbing the netid
    net_id = input("Enter your netId (username): ").strip()
    
    #calculate the hashed password
    
    #hash the salt and password together for the first iteration
    x_bytes = hash_sha256(salt, password)
    
    #hash the given hash 999 more times
    for i in range(999):
        x_bytes = hash_sha256(x_bytes)
    
    #convert the final hash to an integer and print for server
    x = bytes_to_int(x_bytes)
    print(f"Password hash as an int, x = {x}\n")
    
    #calculate k which is given by hashing p and g together
    k = hash_to_int(p, g)
    print(f"k = {k}\n")
    
    #calculate v which is g^x (mod p)
    v = mod_exp(g, x, p)
    
    #calculate g^b = B_bar - k * v (mod p)
    
    #since B_bar ≡ k*v + g^b (mod p)
    #g^b ≡ B_bar - k*v (mod p)
    kv = (k * v) % p
    g_b = (B_bar - kv) % p
    
    print(f"g^b = {g_b}\n")
    
    #calculate u which is the hash of g^a and g^b
    u = hash_to_int(g_a, g_b)
    print(f"u = {u}\n")
    
    #calculate the shared key which is = (g^b)^(a + u*x) (mod p)
    
    exp = a + u * x
    shared_key = mod_exp(g_b, exp, p)
    
    print(f"Shared key = {shared_key}\n")
    
    #allowing the user to submit the above info before giving more
    input("\n\nPress the Enter key after submitting the values above to continue\n")
    
    #calculate M1 = H(H(p) ⊕ H(g) || H(netId) || salt || g^a || g^b || shared_key)
    
    Hp = hash_sha256(p)
    Hg = hash_sha256(g)
    HpXORHg = xor_bytes(Hp, Hg)
    
    HnetId = hash_sha256(net_id)
    
    M1 = hash_sha256(HpXORHg, HnetId, salt, g_a, g_b, shared_key)
    M1_hex = M1.hex()
    
    print(f"M1 = {M1_hex}\n")
    
    #calculate M2 = H(g^a || M1 || shared_key)
    
    M2 = hash_sha256(g_a, M1, shared_key)
    M2_hex = M2.hex()
    
    print(f"M2 = {M2_hex}\n")

#run main
main_srp()