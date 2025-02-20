import socket
import threading
import syslog
import hashlib
import os

# Configuração do servidor proxy
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 8080
SYSLOG_SERVER = '192.168.1.100'  # IP do servidor SysLog

# Função para calcular a hash do próprio código (integridade)
def verificar_integridade(arquivo):
    hasher = hashlib.sha256()
    with open(arquivo, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

# Envia logs para o servidor SysLog
def log_syslog(mensagem):
    syslog.openlog(ident="ProxyServer", logoption=syslog.LOG_PID)
    syslog.syslog(syslog.LOG_INFO, mensagem)

# Encaminha tráfego entre cliente e servidor
def forward_traffic(source, destination):
    """Encaminha dados entre duas conexões socket"""
    def forward(src, dst):
        while True:
            try:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
            except:
                break
        src.close()
        dst.close()

    threading.Thread(target=forward, args=(source, destination)).start()
    threading.Thread(target=forward, args=(destination, source)).start()

# Função para tratar conexões de clientes (navegador)
def handle_client(client_socket, client_address):
    try:
        # Recebe a requisição do navegador
        request = client_socket.recv(4096).decode('utf-8', errors='ignore')

        if not request:
            client_socket.close()
            return

        # Exibir informações da requisição
        print(f"\n📥 Requisição recebida de {client_address}:")
        print(request.split("\n")[0])

        # Se for uma requisição HTTPS (CONNECT)
        if request.startswith("CONNECT"):
            try:
                # Divide corretamente a linha inicial da requisição
                request_line = request.split("\n")[0]
                parts = request_line.split()

                if len(parts) < 2:
                    raise ValueError("Formato de requisição CONNECT inválido")

                host_port = parts[1]

                # Extrai host e porta corretamente
                if ":" in host_port:
                    host, port = host_port.split(":")
                    port = int(port)
                else:
                    host, port = host_port, 443  # Assume porta 443 se não especificado

                print(f"🔗 Criando túnel para {host}:{port}")

                # Criar conexão com o servidor de destino
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.connect((host, port))
                client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                # Encaminhar tráfego entre cliente e servidor
                forward_traffic(client_socket, server_socket)

            except Exception as e:
                print(f"⚠️ Erro ao processar CONNECT: {e}")
                client_socket.close()

            return

        # Verifica se a URL contém "monitorando" e bloqueia
        print("\n\n\n\n\n\nAAAAAAAAAAAAAAAAAA\n\n\n\n\n",request)
        if "monitorando" in request.lower():
            print("🚫 Acesso bloqueado")
            log_syslog(f"Acesso negado ao cliente {client_address}")

            response = """HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n
            <html><body><h1>Acesso não autorizado!</h1></body></html>"""
            
            client_socket.sendall(response.encode())
            client_socket.close()
            return

        # Extrai o host do cabeçalho HTTP
        lines = request.split("\n")
        host_line = [line for line in lines if line.startswith("Host:")]
        if not host_line:
            print("❌ Host não encontrado na requisição!")
            client_socket.close()
            return

        host = host_line[0].split(":")[1].strip()

        # Conectar ao servidor de destino
        print(f"🌍 Encaminhando requisição para {host}")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((host, 80))
        server_socket.sendall(request.encode())

        # Recebe a resposta do servidor
        response = server_socket.recv(4096)
        server_socket.close()

        # Enviar resposta ao navegador
        client_socket.sendall(response)
        client_socket.close()

        # Log no SysLog
        log_syslog(f"Cliente {client_address} acessou {host}")

    except Exception as e:
        print(f"⚠️ Erro: {e}")
        client_socket.close()

# Inicializa o servidor proxy
def start_proxy():
    # Verificação de integridade antes de rodar o proxy
    hash_file = "hash.txt"
    if os.path.exists(hash_file):
        with open(hash_file, 'r') as f:
            hash_original = f.read().strip()
        hash_atual = verificar_integridade(__file__)
        print(hash_atual)

        if hash_original != hash_atual:
            print("⚠️ ALERTA! O código foi modificado. Abortando execução.")
            log_syslog("⚠️ Integridade comprometida! Código alterado!")
            #return
    else:
        print("⚠️ Arquivo de hash não encontrado. Ignorando verificação de integridade.")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((PROXY_HOST, PROXY_PORT))
    server.listen(5)
    print(f"🚀 Proxy rodando em {PROXY_HOST}:{PROXY_PORT}")

    while True:
        client_socket, client_address = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        thread.start()

# Inicia o proxy
if __name__ == "__main__":
    start_proxy()