# Diffie-Hellman + RSA + Cifra de César em Socket TCP

Projeto acadêmico desenvolvido em Python para demonstrar, em comunicação TCP entre duas máquinas distintas, a integração entre:

- **RSA (criptografia assimétrica)** com chaves de **4096 bits**
- **Diffie-Hellman (troca de chave simétrica)**
- **Cifra de César (criptografia simétrica da mensagem)**

A proposta do trabalho consistiu em implementar um fluxo em que **Alice (Client)** e **Bob (Server)** se comunicam por socket TCP, protegendo os valores trocados no Diffie-Hellman com **RSA autoral**, e utilizando a chave compartilhada derivada para alimentar a **Cifra de César**.

---

## Sumário

- [Diffie-Hellman + RSA + Cifra de César em Socket TCP](#diffie-hellman--rsa--cifra-de-césar-em-socket-tcp)
  - [Sumário](#sumário)
  - [Objetivo](#objetivo)
  - [Arquitetura da solução](#arquitetura-da-solução)
  - [Como os algoritmos utilizados](#como-os-algoritmos-utilizados)
    - [RSA](#rsa)
    - [Diffie-Hellman](#diffie-hellman)
    - [Cifra de César](#cifra-de-césar)
    - [Tecnologias utilizadas](#tecnologias-utilizadas)
    - [Execução](#execução)
    - [O que o Wireshark permite ver](#o-que-o-wireshark-permite-ver)
    - [Importante](#importante)
    - [Conclusão](#conclusão)

---

## Objetivo

O objetivo deste projeto foi construir uma prova de conceito funcional que evidenciasse:

1. a comunicação entre **duas máquinas distintas**;
2. a troca de informações por **socket TCP**;
3. a proteção dos valores públicos do **Diffie-Hellman** com **RSA**;
4. a derivação de uma chave simétrica para a **Cifra de César**;
5. a visualização do tráfego no **Wireshark**.

Na demonstração final:

- **Bob (Server)** foi executado em uma **instância EC2 da AWS**;
- **Alice (Client)** foi executada na **máquina local**;
- o tráfego foi capturado localmente com **Wireshark**.

---

## Arquitetura da solução

O fluxo adotado foi o seguinte:

1. **Bob (Server)** gera um par de chaves **RSA 4096 bits**.
2. Bob envia sua **chave pública RSA** para Alice.
3. **Alice (Client)** gera seu próprio par **RSA 4096 bits**.
4. Alice envia sua **chave pública RSA** para Bob.
5. Alice gera seu valor público do **Diffie-Hellman (R1 / A)**.
6. Alice cifra `A` com a chave pública RSA de Bob e envia.
7. Bob decifra `A` com sua chave privada RSA.
8. Bob gera seu valor público do **Diffie-Hellman (R2 / B)**.
9. Bob cifra `B` com a chave pública RSA de Alice e envia.
10. Alice decifra `B` com sua chave privada RSA.
11. Ambos calculam a mesma **chave simétrica Diffie-Hellman**.
12. A partir da chave Diffie-Hellman é derivada uma **chave de deslocamento da Cifra de César**.
13. Alice e Bob passam a trocar mensagens cifradas com a Cifra de César.

---

## Como os algoritmos utilizados

### RSA

O RSA foi utilizado para **proteger os valores públicos do Diffie-Hellman durante o trânsito**.

Isso significa que, no tráfego da rede:

- as **chaves públicas RSA** aparecem em claro, o que é esperado;
- os valores públicos do DH (`R1 / A` e `R2 / B`) aparecem **cifrados**;
- sem a chave privada correspondente, não é possível recuperar diretamente `R1 / A` e `R2 / B`.

### Diffie-Hellman

O Diffie-Hellman foi utilizado para que Alice e Bob chegassem à **mesma chave simétrica compartilhada**, sem que ela fosse enviada diretamente pela rede.

### Cifra de César

A mensagem trocada entre Alice e Bob foi cifrada com a **Cifra de César**, utilizando uma **chave derivada da chave compartilhada Diffie-Hellman**:

```python
caesar_key = (shared_key % 25) + 1
```

Assim, a chave da César não foi escolhida manualmente, mas sim obtida a partir do resultado do Diffie-Hellman.


### Tecnologias utilizadas

- Python 3

- Socket TCP

- AWS EC2

- CloudShell

- Wireshark

- Git / GitHub

### Execução

**1. Configuração da captura no Wireshark**
   
Para acompanhar o tráfego entre a máquina local e a EC2, foi utilizado o filtro:

```python
tcp port 12000 and host <IP_PUBLICO_DA_EC2>
```

Depois, para focar apenas nos pacotes com dados da aplicação, foi usado o filtro de exibição:

```python
tcp.len > 0
```

![Filtro do Wireshark](docs/images/filtros_wireshark.png)

A captura foi configurada para monitorar somente o tráfego TCP entre a máquina local e a instância EC2 na porta do servidor.

**2. Inicialização dos participantes**

Bob (Server) é iniciado na instância EC2, escutando na porta 12000.

    cd ~/DiffieHellman-RSA-CifraCesar
    python3 rsa_server.py 12000

![Início do servidor na EC2](docs/images/inicio_server_ec2.png)


Alice (Client) é iniciada localmente e se conecta ao IP público da instância EC2.

    cd ~/Documentos/DiffieHellman-RSA-CifraCesar
    source .venv/bin/activate
    python rsa_client.py <IP_PUBLICO_DA_EC2> 12000

![Início do cliente local](docs/images/inicio_client_local.png)

**3. Geração e troca das chaves**

Bob gera seu par RSA com módulo de 4096 bits.

![Geração de chaves no servidor EC2](docs/images/chaves_server_ec2.png)

Alice também gera seu par RSA com módulo de 4096 bits.

![Geração de chaves no cliente local](docs/images/chaves_client_local.png)

**4. Evidências da troca criptográfica no Wireshark**

Pacotes que evidenciam o transporte dos dados da fase inicial da negociação criptográfica entre Alice e Bob.

![Troca de chaves observada no Wireshark 1](docs/images/chaves_wireshark1.png)
![Troca de chaves observada no Wireshark 2](docs/images/chaves_wireshark2.png)
![Troca de chaves observada no Wireshark 3](docs/images/chaves_wireshark3.png)
![Troca de chaves observada no Wireshark 4](docs/images/chaves_wireshark4.png)

**5. Conversa cifrada nos terminais**

Conversa completa observada por Bob (Server / EC2)

![Mensagens no servidor EC2](docs/images/mensagens_server_ec2.png)

Conversa completa observada por Alice (Client / local)

![Mensagens no cliente local](docs/images/mensagens_client_local.png)

Nesses terminais é possível observar:

- geração dos valores do Diffie-Hellman;

- derivação da chave da Cifra de César;

- mensagens originais;

- mensagens cifradas;

- mensagens decifradas.

**6. Evidências do payload cifrado no Wireshark**
   
Mensagem cifrada correspondente a 'Oi, Bob!'

![Mensagens cifradas no Wireshark 1](docs/images/mensagens_wireshark1.png)

Resposta cifrada correspondente a 'Olá, Alice!'observada no tráfego

![Mensagens cifradas no Wireshark 2](docs/images/mensagens_wireshark2.png)

Mensagem maior cifrada

![Mensagens cifradas no Wireshark 3](docs/images/mensagens_wireshark3.png)

Outra resposta cifrada

![Mensagens cifradas no Wireshark 4](docs/images/mensagens_wireshark4.png)

Continuação da conversa cifrada

![Mensagens cifradas no Wireshark 5](docs/images/mensagens_wireshark5.png)

Outra evidência de payload cifrado

![Mensagens cifradas no Wireshark 6](docs/images/mensagens_wireshark6.png)

Mensagem de encerramento da conversa

![Mensagens cifradas no Wireshark 7](docs/images/mensagens_wireshark7.png)

Última evidência da troca cifrada

![Mensagens cifradas no Wireshark 8](docs/images/mensagens_wireshark8.png)

Esses prints mostram que o conteúdo da aplicação trafega na rede em forma cifrada, não em texto puro.

### O que o Wireshark permite ver

No tráfego capturado, é possível observar:

- os pacotes TCP trocados entre Alice e Bob;

- os payloads contendo:

  - chaves públicas RSA;

  - valores públicos do Diffie-Hellman protegidos com RSA;

  - mensagens cifradas com a Cifra de César.

Isso é esperado e compatível com o funcionamento do protocolo implementado.

### Importante

As chaves públicas RSA aparecem em claro por definição, pois são públicas.
O objetivo do RSA, neste projeto, foi proteger os valores do Diffie-Hellman (`R1 / A` e `R2 / B`) durante o transporte.

### Conclusão

O projeto demonstrou com sucesso:

- comunicação TCP entre duas máquinas distintas;

- uso de RSA 4096 bits;

- proteção dos valores trocados pelo Diffie-Hellman;

- derivação de uma chave simétrica para a Cifra de César;

- troca de mensagens cifradas entre Alice e Bob;

- observação do tráfego no Wireshark.

Além disso, a implementação evoluiu de uma versão didática com parâmetros pequenos para uma versão mais robusta, com:

- RSA 4096 bits

- Diffie-Hellman fortalecido

- chave da César derivada da chave compartilhada

Dessa forma, é possível evidenciar o funcionamento combinado de criptografia assimétrica, troca segura de chaves e criptografia simétrica em comunicação de rede.
