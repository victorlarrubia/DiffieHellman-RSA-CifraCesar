
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

    # --- ETAPA 3: DIFFIE-HELLMAN ---
    P = 23 
    G = 5  

    if not is_prime(P):
        print("Erro de configuração: P não é primo!")
        clientSocket.close()
        exit()

    a = random.randint(2, 20)
    A = (G**a) % P

    clientSocket.send(bytes(str(A), "utf-8"))
    B = int(clientSocket.recv(1024).decode("utf-8"))

    shared_key = (B**a) % P
    print(f"[Diffie-Hellman] Chave Simétrica Gerada: {shared_key}")

    # --- ETAPA 2: COMUNICAÇÃO COM CIFRA DE CÉSAR ---
    sentence = input("Input lowercase sentence: ")

    encrypted_sentence = caesar_encrypt(sentence, shared_key)
    print(f"Enviando criptografado: {repr(encrypted_sentence)}")
    clientSocket.send(bytes(encrypted_sentence, "utf-8"))

    modifiedSentence = clientSocket.recv(65000).decode("utf-8")
    print(f"Recebido do servidor (criptografado): {repr(modifiedSentence)}")

    decrypted_text = caesar_decrypt(modifiedSentence, shared_key)
    print("Received from Make Upper Case Server (Decriptografado):", decrypted_text)

    clientSocket.close()

if __name__ == "__main__":
    main()  
