from random import randrange


block_size = None


# vérifie si un nombre est premier ou non
def is_prime(n):
    if n > 0:
        for x in range(2, n - 1, 1):
            if n % x == 0:
                return False
        return True
    return False


# renvoie des p et q qui remplissent les conditions
def get_p_and_q():
    p = None
    q = None
    min_range = 10000
    max_range = 99999
    while p is None or (p == q or not is_prime(p)):
        p = randrange(min_range, max_range)
    while q is None or (p == q or not is_prime(q)):
        q = randrange(min_range, max_range)
    return p, q


# renvoie le plus grand commun diviseur de 2 nombres
def pgcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# algorithme présent dans le cours, il renvoie les coefficients de Bézout
def extended_euclidean_algorithm(a, b):
    r = a
    r2 = b
    u = 1
    v = 0
    u2 = 0
    v2 = 1
    while r2 != 0:
        q = r // r2
        rs = r
        us = u
        vs = v
        r = r2
        u = u2
        v = v2
        r2 = rs - q * r2
        u2 = us - q * u2
        v2 = vs - q * v2
    return r, u, v


# génère les clés publiques et privées
def generate_keys():
    p, q = get_p_and_q()
    n = p * q
    phi = (p - 1) * (q - 1)
    if p > q:
        e = p
    else:
        e = q
    for e in range(e + 1, phi - 1):
        if pgcd(phi, e) == 1:
            break
    r, d, v = extended_euclidean_algorithm(e, phi)
    d = d % phi
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key


# algorithme rho de Pollard trouvé sur le web, il permet de retrouver p et q à partir de n
def pollard_rho(n, x=1, f=lambda x: x ** 2 + 1):
    y = f(x) % n
    p = pgcd(y - x, n)
    while p == 1:
        x = f(x) % n
        y = f(f(y)) % n
        p = pgcd(y - x, n)
    if p == n:
        return None
    return p, n // p


# retrouve d et donc la clé privée à partir de p, q, e et n
def get_private_key(p, q, e, n):
    phi = (p - 1) * (q - 1)
    r, d, v = extended_euclidean_algorithm(e, phi)
    d = d % phi
    private_key = (d, n)
    return private_key


# découpe une chaine de caractère en blocs
def split_into_block(string, size):
    array = []
    for i in range(len(string), size-1, -size):
        array.append(string[i-size:i])
    if len(string) % size != 0:
        array.append(to_block(string[0:len(string) % size], size))
    array.reverse()
    return array


# créer un bloc à partir d'un chaine
def to_block(string, size=None):
    if size is not None and int(size) > len(string):
        while int(size) - len(string) != 0:
            string = "0" + string
    return string


# convertie en code ascii et eventuellement en bloc un caractères
def to_ascii(character, size=None):
    ascii_code = str(ord(character))
    ascii_code = to_block(ascii_code, size)
    return ascii_code

# chiffre un nombre avec la clé publique
def encrypt_number(number, public_key):
    e, n = public_key
    return pow(number, e, n)


# chiffre un caractère avec la clé publique
def encrypt_character(character, public_key):
    return encrypt_number(ord(character), public_key)


# chiffre par caractère un message avec la clé publique
def encrypt_by_character(message, public_key, delimiter=" "):
    encrypted_message = ""
    for character in message[:-1]:
        encrypted_message += str(encrypt_character(character, public_key)) + delimiter
    encrypted_message += str(encrypt_character(message[len(message) - 1], public_key))
    return encrypted_message


# chiffre par blocs un message avec la clé publique
def encrypt_by_block(message, public_key, delimiter=" "):
    global block_size
    base = 256
    # e, n = public_key
    # block_size = floor(log(n, base))
    block_size = len(str(base))
    coded_message = ""
    encrypted_message = ""
    for character in message[:-1]:
        coded_message += to_ascii(character, block_size)
    coded_message += to_ascii(message[len(message) - 1], block_size)
    coded_message_array = split_into_block(coded_message, block_size + 1)
    for block in coded_message_array[:-1]:
        encrypted_message += str(encrypt_number(int(block), public_key)) + delimiter
    encrypted_message += str(encrypt_number(int(coded_message_array[len(coded_message_array) - 1]), public_key))
    return encrypted_message


# déchiffre un message vers le code ascii de chaque caractère avec la clé privée
def decrypt_from_character_to_ascii_code(message, private_key, delimiter=" "):
    d, n = private_key
    decrypted_message = ""
    encrypted_characters = message.split(delimiter)
    for encrypted_character in encrypted_characters[:-1]:
        decrypted_message += str(pow(int(encrypted_character), d, n)) + delimiter
    decrypted_message += str(pow(int(encrypted_characters[len(encrypted_characters) - 1]), d, n))
    return decrypted_message


# déchiffre un message par caractère avec la clé privée
def decrypt_from_character(message, private_key, delimiter=" "):
    d, n = private_key
    decrypted_message = ""
    encrypted_characters = message.split(delimiter)
    for encrypted_character in encrypted_characters:
        decrypted_message += chr(pow(int(encrypted_character), d, n))
    return decrypted_message


# déchiffre un message par blocs avec la clé privée
def decrypt_from_block(message, private_key):
    global block_size
    decrypted_to_ascii_code = decrypt_from_character_to_ascii_code(message, private_key).split(" ")
    decrypted_reblocked = ""
    for block in decrypted_to_ascii_code[:-1]:
        decrypted_reblocked += to_block(block, block_size + 1) + " "
    decrypted_reblocked += to_block(decrypted_to_ascii_code[len(decrypted_to_ascii_code) - 1], block_size + 1)
    characters_ascii = split_into_block(decrypted_reblocked.replace(" ", ""), block_size)
    final_decrypted = ""
    for character in characters_ascii:
        if int(character) != 0:
            final_decrypted += chr(int(character))
    return final_decrypted


def main():
    global block_size
    public_key, private_key = generate_keys()
    print("Clé publique = %s ; Clé privée = %s" % (public_key, private_key))
    message = input("Entrez le message : ")
    print("Message =", message)

    # Chiffrement par caractères
    print("\nChiffrement par caractères")
    encrypted = encrypt_by_character(message, public_key)
    print("Message chiffré par caractères =", encrypted)
    decrypted = decrypt_from_character_to_ascii_code(encrypted, private_key)
    print("Message déchiffré par caractères (ASCII code) =", decrypted)
    decrypted = decrypt_from_character(encrypted, private_key)
    print("Message déchiffré par caractères =", decrypted)

    # Chiffrement par blocs
    print("\nChiffrement par blocs")
    encrypted_by_block = encrypt_by_block(message, public_key)
    print("Message chiffré par blocs =", encrypted_by_block)
    decrypted_from_block = decrypt_from_block(encrypted_by_block, private_key)
    print("Message déchiffré par blocs =", decrypted_from_block)

    # Crack 1
    print("\nCrack 1")
    public_key = 12413, 13289
    p, q = pollard_rho(13289)
    e, n = public_key
    private_key = get_private_key(p, q, e, n)
    encrypted = "9197, 6284, 12836, 8709, 4584, 10239, 11553, 4584, 7008, 12523, 9862, 356, 5356, 1159, 10280, 12523, 7506, 6311"
    print("Message chiffré =", encrypted)
    decrypted = decrypt_from_character_to_ascii_code(encrypted, private_key, ", ")
    print("Message déchiffré =", decrypted)

    # Crack 2
    print("\nCrack 2")
    public_key = 163119273, 755918011
    p, q = pollard_rho(13289)
    e, n = public_key
    private_key = get_private_key(p, q, e, n)
    encrypted = "671828605, 407505023, 288441355, 679172842, 180261802"
    print("Message chiffré =", encrypted)
    decrypted = decrypt_from_character_to_ascii_code(encrypted, private_key, ", ")
    print("Message déchiffré =", decrypted)


if __name__ == "__main__":
    main()
