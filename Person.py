from random import randrange


class Person:
    public_key = None
    private_key = None

    def __init__(self):
        self.public_key, self.private_key = self.generate_keys()

    def is_prime(self, n):
        if n > 0:
            for x in range(2, n - 1, 1):
                if n % x == 0:
                    return False
            return True
        return False

    def get_p_and_q(self):
        p = None
        q = None
        min_range = 100
        max_range = 999
        while p is None or (p == q or not self.is_prime(p)):
            p = randrange(min_range, max_range)
        while q is None or (p == q or not self.is_prime(q)):
            q = randrange(min_range, max_range)
        return p, q

    def pgcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a

    def extended_euclidean_algorithm(self, a, b):
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

    def generate_keys(self):
        p, q = self.get_p_and_q()
        print("p =", p, "; q =", q)
        n = p * q
        print("n =", n)
        phi = (p - 1) * (q - 1)
        print("phi =", phi)
        if p > q:
            e = p
        else:
            e = q
        for e in range(e + 1, phi - 1):
            if self.pgcd(phi, e) == 1:
                break
        print("e =", e)
        r, d, v = self.extended_euclidean_algorithm(e, phi)
        d = d % phi
        print("d =", d)
        public_key = (e, n)
        private_key = (d, n)
        return public_key, private_key

    def decrypt(self, message, delimiter=" "):
        d, n = self.private_key
        decrypted_message = ""
        encrypted_characters = message.split(delimiter)
        for encrypted_character in encrypted_characters:
            decrypted_message += chr(pow(int(encrypted_character), d, n))
        return decrypted_message
