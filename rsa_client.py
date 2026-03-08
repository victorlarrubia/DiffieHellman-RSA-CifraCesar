
# simple_tcp_client.py
from socket import *
import random
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
    # sys.argv[0] é o nome do script, [1] é o IP, [2] é a Porta
    if len(sys.argv) != 3:
        print("Uso correto: python simple_tcp_client.py <IP_DO_SERVIDOR> <PORTA>")
        sys.exit(1)

    serverName = sys.argv[1]
    serverPort = int(sys.argv[2]) # Convertendo a porta para inteiro

    # --- CONFIGURAÇÃO DO SOCKET ---
    print(f"Tentando conectar a {serverName}:{serverPort}...")
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((serverName, serverPort))

    rsa_public_data = clientSocket.recv(1024).decode("utf-8")
    rsa_e, rsa_n = map(int, rsa_public_data.split(","))
    rsa_server_public_key = (rsa_e, rsa_n)
    print(f"[RSA] Chave pública recebida do servidor: {rsa_server_public_key}")

    rsa_client_public_key, rsa_client_private_key = generate_rsa_keys(47, 59)
    clientSocket.send(f"{rsa_client_public_key[0]},{rsa_client_public_key[1]}\n".encode("utf-8"))
    print(f"[RSA] Chave pública do cliente enviada ao servidor: {rsa_client_public_key}")

    # --- ETAPA 3: DIFFIE-HELLMAN PROTEGIDO COM RSA ---
    P = 23
    G = 5

    if not is_prime(P):
        print("Erro de configuração: P não é primo!")
        clientSocket.close()
        exit()

    a = random.randint(2, 20)
    A = mod_exp(G, a, P)

    encrypted_A = rsa_encrypt_number(A, rsa_server_public_key)

    print(f"[Diffie-Hellman] Valor público A gerado pelo cliente: {A}")
    print(f"[RSA] Valor A cifrado para envio: {encrypted_A}")

    clientSocket.send(f"{encrypted_A}\n".encode("utf-8"))

    encrypted_B = int(clientSocket.recv(1024).decode("utf-8"))
    print(f"[RSA] Valor B cifrado recebido do servidor: {encrypted_B}")

    B = rsa_decrypt_number(encrypted_B, rsa_client_private_key)
    print(f"[Diffie-Hellman] Valor público B decifrado: {B}")

    shared_key = mod_exp(B, a, P)
    print(f"[Diffie-Hellman] Chave Simétrica Gerada: {shared_key}")
    print(f"[CÉSAR] Chave de deslocamento derivada do Diffie-Hellman: {shared_key}")
    print("[FLUXO] RSA protegeu os valores A e B do Diffie-Hellman.")
    print("[FLUXO] Diffie-Hellman gerou a chave simétrica usada pela Cifra de César.")

    # --- ETAPA 2: COMUNICAÇÃO CONTÍNUA COM CIFRA DE CÉSAR ---
    while True:
        sentence = input("Digite a mensagem do cliente: ")

        encrypted_sentence = caesar_encrypt(sentence, shared_key)
        print(f"[CÉSAR] Mensagem original do cliente: {sentence}")
        print(f"[CÉSAR] Mensagem criptografada com chave {shared_key}: {repr(encrypted_sentence)}")
        clientSocket.send(encrypted_sentence.encode("utf-8"))

        if sentence.lower() == "sair":
            print("Cliente encerrou a conversa.")
            break

        modifiedSentence = clientSocket.recv(65000).decode("utf-8")
        if not modifiedSentence:
            print("Servidor encerrou a conexão.")
            break

        print(f"[CÉSAR] Mensagem criptografada recebida do servidor: {repr(modifiedSentence)}")

        decrypted_text = caesar_decrypt(modifiedSentence, shared_key)
        print(f"[CÉSAR] Mensagem do servidor decriptografada com chave {shared_key}: {decrypted_text}")

        if decrypted_text.lower() == "sair":
            print("Servidor solicitou encerramento da conversa.")
            break

    clientSocket.close()

if __name__ == "__main__":
    main()  
