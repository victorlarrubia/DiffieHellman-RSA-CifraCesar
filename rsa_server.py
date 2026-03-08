# simple_tcp_server.py
from socket import *
import random
import sys
from urllib import response # Importante para ler argumentos da linha de comando

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
    P = 23
    G = 5

    if not is_prime(P):
        print("Erro de configuração: P não é primo!")
        exit()

    rsa_public_key, rsa_private_key = generate_rsa_keys(61, 53)
    print(f"[RSA] Chave pública do servidor: {rsa_public_key}")

    while True:
        connectionSocket, addr = serverSocket.accept()
        print(f"\nConexão estabelecida com: {addr}")
        connectionSocket.send(f"{rsa_public_key[0]},{rsa_public_key[1]}".encode("utf-8"))

        socket_file = connectionSocket.makefile("r", encoding="utf-8")

        client_public_data = socket_file.readline().strip()
        client_e, client_n = map(int, client_public_data.split(","))
        rsa_client_public_key = (client_e, client_n)
        print(f"[RSA] Chave pública do cliente recebida: {rsa_client_public_key}")

        encrypted_A = int(socket_file.readline().strip())
        print(f"[RSA] Valor A cifrado recebido: {encrypted_A}")

        A = rsa_decrypt_number(encrypted_A, rsa_private_key)
        print(f"[Diffie-Hellman] Valor público A decifrado: {A}")

        b = random.randint(2, 20)
        B = mod_exp(G, b, P)

        encrypted_B = rsa_encrypt_number(B, rsa_client_public_key)
        print(f"[Diffie-Hellman] Valor público B gerado pelo servidor: {B}")
        print(f"[RSA] Valor B cifrado para envio: {encrypted_B}")

        connectionSocket.send(str(encrypted_B).encode("utf-8"))

        shared_key = mod_exp(A, b, P)
        print(f"[Diffie-Hellman] Chave Simétrica Gerada: {shared_key}")
        print(f"[CÉSAR] Chave de deslocamento derivada do Diffie-Hellman: {shared_key}")
        print("[FLUXO] RSA protegeu os valores A e B do Diffie-Hellman.")
        print("[FLUXO] Diffie-Hellman gerou a chave simétrica usada pela Cifra de César.")

        # --- ETAPA 2: COMUNICAÇÃO CONTÍNUA COM CIFRA DE CÉSAR ---
        while True:
            sentence = connectionSocket.recv(65000).decode("utf-8")
            if not sentence:
                print("Cliente encerrou a conexão.")
                break

            print(f"[CÉSAR] Mensagem criptografada recebida do cliente: {repr(sentence)}")

            decrypted_received = caesar_decrypt(sentence, shared_key)
            print(f"[CÉSAR] Mensagem do cliente decriptografada com chave {shared_key}: {decrypted_received}")

            if decrypted_received.lower() == "sair":
                print("Cliente solicitou encerramento da conversa.")
                break

            response = input("Digite a resposta do servidor: ")
            encrypted_response = caesar_encrypt(response, shared_key)
            connectionSocket.send(encrypted_response.encode("utf-8"))

            print(f"[CÉSAR] Resposta original do servidor: {response}")
            print(f"[CÉSAR] Resposta criptografada com chave {shared_key}: {repr(encrypted_response)}")

            if response.lower() == "sair":
                print("Servidor encerrou a conversa.")
                break

        connectionSocket.close()

if __name__ == "__main__":
    main()  