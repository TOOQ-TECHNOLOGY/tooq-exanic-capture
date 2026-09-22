# Tooq-Exanic-Capture

Captura de frames ExaNIC em PCAP ou ERF, com rotação por tempo e/ou tamanho.

## Compilar e testar

A compilação usa a biblioteca estática `libs/exanic/libexanic.a`.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Os testes não exigem a placa: verificam registros PCAP, snaplen, rotação,
colisões de nomes, erros de escrita/flush/fechamento, limites numéricos e
recepção de frames válidos/abortados/com CRC inválido em um buffer simulado.

## Uso

```bash
sudo ./build/exanic-capture -i enp23s0 -G 60 -C 100 -w /tmp/captura.pcap
```

- `-i`: interface Linux ou porta, por exemplo `exanic0:0`.
- `-w`: nome base de saída; `-` envia o fluxo binário para stdout.
- `-G`: intervalo positivo em segundos, medido pelo relógio monotônico.
- `-C`: limite positivo em milhões de bytes; rotaciona antes de um registro ultrapassar o limite.
- `-s`: bytes capturados por frame, de 1 a 16384. O PCAP preserva também o tamanho original.
- `-F`: `pcap` (padrão) ou `erf`.
- `-R`: diretório de saída quando `-w` não contém diretório.
- `-D`: sincroniza arquivo e diretório com `fsync` na finalização.
- `-H`: timestamps de hardware; requer relógio da placa sincronizado.
- `-N`: resolução de nanossegundos no PCAP.
- `-p`: não habilita modo promíscuo.
- `--ptp --hw-clock-scale utc|tai`: habilita timestamp de hardware, PCAP em
  nanossegundos, conversão explícita para UTC e monitoramento sem interromper
  a captura quando o sincronismo cair. Limite padrão de aviso: 1 µs.
- `--ptp-audit on|off`: liga/desliga somente a auditoria JSONL (padrão `on`,
  exige `--ptp`). Monitoramento e avisos em stderr continuam ativos.

Veja [configuração PTP/Timebeat e auditoria por arquivo](docs/ptp.md).
O modo PTP exige confirmar a escala do relógio. A integração de telemetria
Timebeat depende de um mapeamento validado com a saída da instalação;
sem telemetria, o estado é registrado como desconhecido.

As portas dos filtros são números decimais de 0 a 65535.
Sem `-w`, os frames são exibidos em texto. Rotação, `-R` e `-D` exigem
saída para arquivo e não podem ser combinados com `-w -`.

## Integridade e publicação

Durante a captura, o nome é `captura1.pcap.part`. Somente após verificar
escritas, flush e fechamento, o programa publica `captura1.pcap`.
Consumidores devem processar apenas os nomes finais, ignorando `.part`.

A publicação usa hard link no mesmo diretório seguido da remoção do nome
temporário: o nome final aparece atomicamente e nunca substitui um arquivo
existente. O filesystem precisa suportar hard links. Se a publicação falhar,
o programa termina com erro e mantém o temporário quando possível.
Uma interrupção entre o link e a remoção pode deixar ambos os nomes para
o mesmo arquivo completo.

Reiniciar a captura pula índices ocupados por arquivos finais ou temporários.
Não há criação automática de pastas por dia nem recuperação automática de
temporários abandonados. O diretório de saída é criado se seu pai já existir.

A rotação ocorre entre registros, na chegada do próximo frame válido.
Sem tráfego, não são criados arquivos periódicos vazios. Com `-G` e `-C`,
a primeira condição atendida dispara a rotação e reinicia o intervalo.
Um registro maior que o limite é mantido inteiro em um arquivo, que pode
ultrapassar o limite.

Frames abortados, com CRC inválido ou com erros de recepção são descartados
e contabilizados. A recepção usa a proteção da biblioteca ExaNIC contra
sobrescrita do buffer durante a cópia. Frames maiores que 16 KiB são descartados.

Falhas de escrita ou finalização encerram a captura com código diferente de
zero, sem publicar o arquivo incompleto. SIGINT/SIGTERM pedem encerramento
normal e finalização do arquivo. SIGKILL, crash ou queda de energia podem
deixar um `.part` incompleto; não o renomeie sem validar seu conteúdo.

Sem `-D`, o fechamento bem-sucedido não garante persistência após queda de
energia. Com `-D`, o arquivo é sincronizado antes da publicação e o diretório
depois dela, respeitando as garantias do filesystem e do dispositivo.
Esse modo pode atrasar a recepção durante a rotação e aumentar perdas por
overflow. A escrita usa buffer de 1 MiB; não é feito fsync por pacote.
A saída stdout é um fluxo e não tem o protocolo de publicação de arquivos.

Para sincronizar os drivers, consulte o projeto
[ExaNIC](https://github.com/cisco/exanic-software).
