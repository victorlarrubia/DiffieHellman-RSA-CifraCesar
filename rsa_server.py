# simple_tcp_server.py
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

    while True:
        connectionSocket, addr = serverSocket.accept()
        print(f"\nConexão estabelecida com: {addr}")
        
        A = int(connectionSocket.recv(1024).decode("utf-8"))
        
        b = random.randint(2, 20)
        B = (G**b) % P
        
        connectionSocket.send(bytes(str(B), "utf-8"))
        
        shared_key = (A**b) % P
        print(f"[Diffie-Hellman] Chave Simétrica Gerada: {shared_key}")

        # --- ETAPA 2: COMUNICAÇÃO COM CIFRA DE CÉSAR ---
        sentence = connectionSocket.recv(65000).decode("utf-8")
        print(f"Recebido do Cliente (Criptografado): {repr(sentence)}")

        decrypted_received = caesar_decrypt(sentence, shared_key)
        print("Received From Client (Decriptografado):", decrypted_received)

        capitalizedSentence = decrypted_received.upper()

        encrypted_response = caesar_encrypt(capitalizedSentence, shared_key)
        connectionSocket.send(bytes(encrypted_response, "utf-8"))

        print("Sent back to Client (Criptografado):", repr(encrypted_response))
        connectionSocket.close()

if __name__ == "__main__":
    main()  