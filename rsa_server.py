# simple_tcp_server.py
from socket import *
import random
import secrets
import sys # Importante para ler argumentos da linha de comando

# --- FUNÇÕES DE CRIPTOGRAFIA ---
def is_prime(n):
    if n <= 1: return False
    i = 2
    while i < n:
        if n % i == 0:
            return False
        i += 1
    return True

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False

    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small:
        return True

    for p in small:
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    def witness(a: int) -> bool:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                return True
        return False

    k = 12
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        if not witness(a):
            return False

    return True

def generate_odd_candidate(bits: int) -> int:
    candidate = secrets.randbits(bits)
    candidate |= (1 << (bits - 1))
    candidate |= 1
    return candidate

def generate_large_prime(bits: int) -> int:
    while True:
        candidate = generate_odd_candidate(bits)
        if is_probable_prime(candidate):
            return candidate

def generate_rsa_keys_4096(e=65537):
    prime_bits = 2048

    while True:
        p = generate_large_prime(prime_bits)
        q = generate_large_prime(prime_bits)

        if p == q:
            continue

        n = p * q

        if n.bit_length() != 4096:
            continue

        phi = (p - 1) * (q - 1)

        if gcd(e, phi) != 1:
            continue

        d = mod_inverse(e, phi)
        public_key = (e, n)
        private_key = (d, n)
        return public_key, private_key

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_value, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_value, x, y

def mod_inverse(e, phi):
    gcd_value, x, _ = extended_gcd(e, phi)
    if gcd_value != 1:
        raise ValueError("Não existe inverso modular para os valores informados.")
    return x % phi

def mod_exp(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus
    return result

def generate_rsa_keys(p, q, e=65537):
    if not is_prime(p) or not is_prime(q):
        raise ValueError("p e q devem ser primos.")
    if p == q:
        raise ValueError("p e q devem ser diferentes.")

    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1:
        raise ValueError("e deve ser coprimo de phi(n).")

    d = mod_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def rsa_encrypt_number(number, public_key):
    e, n = public_key
    if number >= n:
        raise ValueError("O número a ser cifrado deve ser menor que n.")
    return mod_exp(number, e, n)

def rsa_decrypt_number(cipher_number, private_key):
    d, n = private_key
    return mod_exp(cipher_number, d, n)

def caesar_encrypt(text, shift):
    encrypted = ""
    for char in text:
        encrypted += chr((ord(char) + shift) % 256)
    return encrypted

def caesar_decrypt(text, shift):
    decrypted = ""
    for char in text:
        decrypted += chr((ord(char) - shift) % 256)
    return decrypted

def main():
    # --- LEITURA DOS ARGUMENTOS (argv) ---
    if len(sys.argv) != 2:
        print("Uso correto: python simple_tcp_server.py <PORTA>")
        sys.exit(1)

    serverPort = int(sys.argv[1]) # Convertendo a porta para inteiro

    # --- CONFIGURAÇÃO DO SOCKET ---
    serverSocket = socket(AF_INET,SOCK_STREAM)
    serverSocket.bind(("",serverPort))
    serverSocket.listen(5)
    print(f"TCP Server Secure Iniciado na porta {serverPort}...\n")

    # --- ETAPA 3: DIFFIE-HELLMAN ---
    P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
        16
    )
    G = 2

    if not is_probable_prime(P):
        print("Erro de configuração: P não é primo!")
        exit()

    print("[RSA] Bob - Server está gerando chaves RSA de 4096 bits. Aguarde...")
    rsa_public_key, rsa_private_key = generate_rsa_keys_4096()
    print("[RSA] Bob - Server gerou as chaves RSA de 4096 bits com sucesso.")
    print(f"[RSA] Chave pública do Bob - servidor (e, n): {rsa_public_key}")
    print(f"[RSA] Tamanho de n em bits: {rsa_public_key[1].bit_length()}")

    while True:
        connectionSocket, addr = serverSocket.accept()
        print(f"\nConexão estabelecida com: {addr}")
        connectionSocket.send(f"{rsa_public_key[0]},{rsa_public_key[1]}\n".encode("utf-8"))

        socket_file = connectionSocket.makefile("r", encoding="utf-8")

        client_public_data = socket_file.readline().strip()
        client_e, client_n = map(int, client_public_data.split(","))
        rsa_client_public_key = (client_e, client_n)
        print(f"[RSA] Chave pública da Alice - cliente recebida: {rsa_client_public_key}")

        encrypted_A = int(socket_file.readline().strip())
        print(f"[RSA] Valor A cifrado recebido: {encrypted_A}")

        A = rsa_decrypt_number(encrypted_A, rsa_private_key)
        print(f"[Diffie-Hellman] Valor público A decifrado: {A}")

        b = secrets.randbits(256)
        if b < 2:
            b = 2
        B = mod_exp(G, b, P)

        encrypted_B = rsa_encrypt_number(B, rsa_client_public_key)
        print(f"[Diffie-Hellman] Valor público B gerado pelo Bob - servidor: {B}")
        print(f"[RSA] Valor B cifrado para envio: {encrypted_B}")

        connectionSocket.send(f"{encrypted_B}\n".encode("utf-8"))

        shared_key = mod_exp(A, b, P)
        caesar_key = (shared_key % 25) + 1

        print(f"[Diffie-Hellman] Chave Simétrica Gerada: {shared_key}")
        print(f"[CÉSAR] Chave de deslocamento derivada do Diffie-Hellman: {caesar_key}")
        print("[FLUXO] RSA protegeu os valores A e B do Diffie-Hellman.")
        print("[FLUXO] Diffie-Hellman gerou a chave simétrica, da qual foi derivada a chave da Cifra de César.")

        # --- ETAPA 2: COMUNICAÇÃO CONTÍNUA COM CIFRA DE CÉSAR ---
        while True:
            sentence = connectionSocket.recv(65000).decode("utf-8")
            if not sentence:
                print("Alice - cliente encerrou a conexão.")
                break

            print(f"[CÉSAR] Mensagem criptografada recebida da Alice - cliente: {repr(sentence)}")

            decrypted_received = caesar_decrypt(sentence, caesar_key)
            print(f"[CÉSAR] Mensagem da Alice - cliente decriptografada com chave {caesar_key}: {decrypted_received}")

            if decrypted_received.lower() == "sair":
                print("Alice - cliente solicitou encerramento da conversa.")
                break

            response = input("Digite a resposta do Bob - servidor: ")
            encrypted_response = caesar_encrypt(response, caesar_key)
            connectionSocket.send(encrypted_response.encode("utf-8"))

            print(f"[CÉSAR] Resposta original do Bob - servidor: {response}")
            print(f"[CÉSAR] Resposta criptografada com chave {caesar_key}: {repr(encrypted_response)}")

            if response.lower() == "sair":
                print("Bob - servidor encerrou a conversa.")
                break

        connectionSocket.close()

if __name__ == "__main__":
    main()  