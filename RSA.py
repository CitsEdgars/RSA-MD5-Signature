import math
import random
import hashlib

def random_prime(int_range):
    primes = []
    for num in range(int_range[0], int_range[1]):
        if (num + 1) % 6 or (num - 1):
            if is_prime(num):
                primes.append(num)
    rnd_idx = random.randint(1, len(primes))
    return primes[rnd_idx - 1]
    
def is_prime(num):
    prime = True
    until = int(math.sqrt(num))+1
    for i in range(2, until):
        if not num % i:
            prime = False
            break
    return prime

def remove_duplicates(list):
    streak_symbol = None
    new_list = []
    for sym in list:
        if streak_symbol != sym:
            new_list.append(sym)
            streak_symbol = sym
    return new_list

def prime_factors(num, factors = None):
    until = int(math.sqrt(num))+1
    if factors is None: factors = []
    for i in range(2, until):
        if not num % i:
            factors.append(i)
            break
    else: 
        factors.append(int(num))
        return factors
    prime_factors(num/i, factors)
    return(factors)


def is_coprime(a, b):
    coprime = True
    a_primes = remove_duplicates(prime_factors(a))
    b_primes = remove_duplicates(prime_factors(b))
    for a_prime in a_primes:
        for b_prime in b_primes:
            if a_prime == b_prime:
                coprime = False
    return coprime

def calculate_keys(N, fi, random_prime = True):
    # Encryption key - Such that is (1<e<fi) && coprime with N and fi (Also public key)
    encryption_key = 0
    all_possibilities = range(2, (fi-1))
    viable_possibilities = []
    for i in all_possibilities:
        if is_coprime(i, N) and is_coprime(i, fi):
            viable_possibilities.append(i)

    # print(viable_possibilities)
    if len(viable_possibilities) == 1:
        encryption_key = viable_possibilities[0]
    elif len(viable_possibilities) == 0:
        print("No keys available")
        return
    else:
        rand_idx = random.randint(1, len(viable_possibilities))
        encryption_key = viable_possibilities[rand_idx-1]

    # Decryption key - Such that de(mod(fi)) = 1 (Also, private key)
    decryption_key = 1
    if random_prime:
        rand_count = random.randint(1, int(math.sqrt(fi)/2))
    else:
        rand_count = random.randint(1, 1)
    while(True):
        if (encryption_key * decryption_key) % fi == 1:
            if rand_count == 0:
                break
            decryption_key += 1
            rand_count -= 1
        else: 
            decryption_key += 1
    
    return (encryption_key, N), (decryption_key, N)

def generate_keys(low_bnd, upr_bnd):
    diff = upr_bnd - low_bnd
    p = random_prime((low_bnd, upr_bnd))
    q = random_prime((p + 1, p + diff))
    print("p:{}, q:{}".format(p,q))
    N = p * q
    fi = (p-1)*(q-1)
    print("N:{}, fi:{}".format(N,fi))
    enc_key, dec_key = calculate_keys(N, fi, False)
    return enc_key, dec_key

def encrypt_RSA(key, value):
    res = value**key[0] % key[1]
    encrypted_val = res
    return encrypted_val

def decdrypt_RSA(value, key):
    res = value**key[0] % key[1]
    decrypte_val = res
    return decrypte_val

def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int.from_bytes(text.encode(encoding, errors), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors) or '\0'

if __name__ == "__main__":

    # Alise izveido atslegu parus
    public_key, private_key = generate_keys(17, 23)
    print(private_key, public_key)

    # Alise izveido vestuli
    message_text = "KINO"

    # Pielieto MD5 message digest algoritmu
    message_digest = hashlib.md5(message_text.encode()).digest()
    print(message_digest)

    # Python manipulacijas, lai dabutu 1st bit skaitlisko vertibu
    first_byte = str(message_digest)[2:][0]
    bits = text_to_bits(first_byte).replace('b','')
    numerical_val = int(bits,2)    
    print("Original:", numerical_val)

    print("{} => {} => {} => {}".format(message_digest, first_byte, bits, numerical_val))

    # Alise izmanto privato atslegu, lai aizsifretu parakstu
    cypher_text = encrypt_RSA(private_key, numerical_val)
    print("Encrypted:", cypher_text)

    # Alise nosuta zinojumu, ko Bobs sanem
    sent_document = [cypher_text, message_text]
    print(sent_document)

    # Bobs izmanto Alises publisko atslegu, lai atsifretu paraksta skaitlisko bita vertibu
    plain_text = decdrypt_RSA(cypher_text, public_key)
    print("Decrypted:", plain_text)

    # Bobs iegust digest 1.o bit no sanemtas vestules 
    first_byte = str(message_digest)[2:][0]
    bits = text_to_bits(first_byte).replace('b','')
    numerical_val = int(bits,2)    
    print("Received message digest:", numerical_val)

    if (numerical_val == plain_text):
        print("Document has not been tampered with!")
    else:
        print("Document has been tampered with!")


    