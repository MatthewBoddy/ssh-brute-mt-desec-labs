# ssh-brute-mt-desec-labs
SSH Credential Tester - DESEC Lab (Multithreaded)

AVISO: Use apenas em ambientes de laboratório autorizados.

Criei esse Brute Force em utilitário SSH para resolver alguns laboratórios da DESEC, estarei deixando ele público caso seja útil para alguém!
Sinta-se à vontade para copiar e modificar.

## USO:
python3 ssh_brute_mt.py <lista_usuarios> <lista_senhas> <IP_alvo> [opcoes]

- print_lock  : garante que apenas 1 thread por vez escreve no terminal.
- stop_event  : quando setado (stop_event.set()), todas as threads param.

## FLAGS:
- --port    22     Porta SSH (padrão: 22)
- --timeout 5      Segundos por tentativa
- --delay   0.5    Pausa entre tentativas (evita banimento)
- --verbose        Exibe cada tentativa na tela
- --stop           Para imediatamente ao achar 1ª credencial
