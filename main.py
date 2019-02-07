from random import randrange

from Person import Person


def is_prime(n):
    if n > 0:
        for x in range(2, n - 1, 1):
            if n % x == 0:
                return False
        return True
    return False


def get_p_and_q():
    p = None
    q = None
    min_range = 1000000
    max_range = 9999999
    while p is None or (p == q or not is_prime(p)):
        p = randrange(min_range, max_range)
    while q is None or (p == q or not is_prime(q)):
        q = randrange(min_range, max_range)
    return p, q


def pgcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


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


def generate_keys():
    p, q = get_p_and_q()
    # print("p =", p, "; q =", q)
    n = p * q
    # print("n =", n)
    phi = (p - 1) * (q - 1)
    # print("phi =", phi)
    if p > q:
        e = p
    else:
        e = q
    for e in range(e + 1, phi - 1):
        if pgcd(phi, e) == 1:
            break
    # print("e =", e)
    r, d, v = extended_euclidean_algorithm(e, phi)
    d = d % phi
    # print("d =", d)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key


def get_private_key(p, q, e, n):
    phi = (p - 1) * (q - 1)
    r, d, v = extended_euclidean_algorithm(e, phi)
    d = d % phi
    private_key = (d, n)
    return private_key


def encrypt_number(number, key):
    e, n = key
    return pow(number, e, n)


def encrypt_character(character, key):
    return encrypt_number(ord(character), key)


def encrypt(message, key, delimiter=" "):
    encrypted_message = ""
    for character in message[:-1]:
        encrypted_message += str(encrypt_character(character, key)) + delimiter
    encrypted_message += str(encrypt_character(message[len(message) - 1], key))
    return encrypted_message


def decrypt_to_ascii_code(message, key, delimiter=" "):
    d, n = key
    decrypted_message = ""
    encrypted_characters = message.split(delimiter)
    for encrypted_character in encrypted_characters[:-1]:
        decrypted_message += str(pow(int(encrypted_character), d, n)) + delimiter
    decrypted_message += str(pow(int(encrypted_characters[len(encrypted_characters) - 1]), d, n))
    return decrypted_message


def decrypt(message, key, delimiter=" "):
    d, n = key
    decrypted_message = ""
    encrypted_characters = message.split(delimiter)
    for encrypted_character in encrypted_characters:
        decrypted_message += chr(pow(int(encrypted_character), d, n))
    return decrypted_message


def main():
    public_key, private_key = generate_keys()

    # public_key = 12413, 13289  # Crack 1

    # public_key = 163119273, 755918011  # Crack 2

    # Crack
    # p, q = pollard_rho(13289)
    # e, n = public_key
    # private_key = get_private_key(p, q, e, n)

    print("Clé publique = %s ; Clé privée = %s" % (public_key, private_key))

    message = input("Entrez le message : ")
    print("Message =", message)
    encrypted = encrypt(message, public_key, ", ")

    # encrypted = "9197, 6284, 12836, 8709, 4584, 10239, 11553, 4584, 7008, 12523, 9862, 356, 5356, 1159, 10280, 12523, 7506, 6311"  # Crack 1

    # encrypted = "671828605, 407505023, 288441355, 679172842, 180261802"  # Crack 2

    print("Message chiffré =", encrypted)
    decrypted = decrypt(encrypted, private_key, ", ")
    print("Message déchiffré =", decrypted)


    # Crack 1
    print("\nCrack 1")
    public_key = 12413, 13289  # Crack 1
    p, q = pollard_rho(13289)
    e, n = public_key
    private_key = get_private_key(p, q, e, n)
    encrypted = "9197, 6284, 12836, 8709, 4584, 10239, 11553, 4584, 7008, 12523, 9862, 356, 5356, 1159, 10280, 12523, 7506, 6311"
    print("Message chiffré =", encrypted)
    decrypted = decrypt_to_ascii_code(encrypted, private_key, ", ")
    print("Message déchiffré =", decrypted)

    # Crack 2
    print("\nCrack 2")
    public_key = 163119273, 755918011
    p, q = pollard_rho(13289)
    e, n = public_key
    private_key = get_private_key(p, q, e, n)
    encrypted = "671828605, 407505023, 288441355, 679172842, 180261802"
    print("Message chiffré =", encrypted)
    decrypted = decrypt_to_ascii_code(encrypted, private_key, ", ")
    print("Message déchiffré =", decrypted)


if __name__ == "__main__":
    main()
