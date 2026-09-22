# Timestamp de hardware e monitoramento PTP

O serviço de sincronismo configurado no host é responsável por ajustar o relógio. O capturador
não inicia `ptp4l`, `phc2sys`, `exanic-clock-sync` nem escreve configurações de relógio.
Não execute outro sincronizador concorrente sobre o mesmo PHC.

## Preparação do host

- Identifique a interface, o dispositivo ExaNIC e o PHC usados na captura.
- Configure a referência PTP e o domínio no serviço de sincronismo escolhido.
- Confirme o suporte a timestamps de hardware e qual serviço disciplina cada relógio.
- Verifique a escala efetiva do PHC (UTC ou TAI); não presuma TAI apenas por receber PTP.
- Disponibilize telemetria do relógio capturado e valide seu formato e unidade de offset.
  Logs operacionais não equivalem necessariamente a snapshots de sincronismo.

Se utilizar Timebeat, sua CLI oferece as consultas abaixo. A disponibilidade e
o acesso dependem da versão e da configuração do serviço:

```text
show phc devices
show clocks offset
show servo sources
show ptp peers
```

É necessário confirmar qual PHC corresponde à placa capturada. Uma outra porta
da mesma placa pode compartilhar o relógio; outra placa não está automaticamente
sincronizada só porque recebe tráfego no mesmo servidor. Confirme a configuração
de sincronismo de cada placa usada na captura.

## Captura

Depois de confirmar que o PHC está em **UTC**:

```bash
sudo ./build/exanic-capture -i exanic0:0 -G 60 -w /tmp/captura.pcap \
  --ptp --hw-clock-scale utc --ptp-domain 0 \
  --ptp-max-offset-ns 1000 --ptp-status-socket /run/exanic-capture-ptp.sock
```

Dispositivo, porta, domínio e caminhos são exemplos. Substitua-os pelos valores
do host e da rede PTP; o domínio da captura deve corresponder ao da telemetria.

Se estiver em **TAI**, substitua `--hw-clock-scale utc` por
`--hw-clock-scale tai --tai-offset kernel`. O capturador consulta `adjtimex`
somente em leitura para obter TAI−UTC. Ele **não** usa o estado do relógio do
Linux como prova de sincronismo da ExaNIC.

Se o kernel não tiver um offset válido, informe `--tai-offset SEGUNDOS` com o
valor confirmado na referência PTP. Não há constante de leap seconds embutida.
Um valor manual precisa ser atualizado operacionalmente quando mudar TAI−UTC;
um offset de kernel precisa ser mantido pelo serviço de sincronismo.

`--ptp` habilita `-H` e `-N` automaticamente e exige a escala explícita.
TAI é convertido para UTC subtraindo o offset dos segundos, sem mudar a fração.
UTC não recebe essa subtração. No modo TAI/kernel, o offset é relido a cada
segundo; se a leitura falhar durante a captura, mantém-se o último valor e
marca-se a correção como desatualizada.

Uma configuração inválida, hardware sem relógio utilizável ou ausência de
offset inicial para converter TAI impede o início. Isso não é uma espera por
lock: **estado desconhecido, perda de PTP, holdover, offset excessivo e queda
do monitor nunca suspendem nem encerram a captura**. Não há troca automática
para timestamp de software durante uma falha. Erros de gravação continuam fatais.
Um timestamp fora do intervalo representável em PCAP/ERF também gera erro.

## Estados e alertas

| Estado | Significado |
| --- | --- |
| `unknown` | Não há telemetria recente, ou falta identidade da referência |
| `synced` | O provedor reportou sincronismo, identidade/escala conferem e o offset está no limite |
| `degraded` | O provedor reportou sincronismo, mas offset, domínio, GM ou escala não conferem |
| `holdover` | O provedor reportou manutenção de relógio sem referência ativa |
| `unsynced` | O provedor reportou perda de sincronismo |

O limite padrão é **1000 ns (1 µs)** em valor absoluto: exatamente 1000 ns é
aceito, acima gera aviso. É configurável por `--ptp-max-offset-ns`.
`--ptp-domain N` confere o domínio configurado; `--ptp-expected-gm ID` fixa opcionalmente
o grandmaster esperado. Sem esta opção, trocas de GM são registradas e permitidas.
`--ptp-clock-id ID` identifica o relógio na telemetria (padrão: nome ExaNIC
resolvido, por exemplo `exanic0`). O mapeamento do provedor deve apontar para
esse mesmo PHC, não apenas para o relógio do sistema.

O monitor consulta uma fila local não bloqueante aproximadamente a cada segundo,
mesmo sem tráfego. São processadas no máximo 16 mensagens por consulta. A
telemetria expira após 5 s por padrão (`--ptp-stale-seconds`), com até um intervalo
de consulta adicional para observar a expiração. Uma mensagem inválida não renova
a validade anterior. Não existe garantia física de precisão por pacote derivada
somente dessa amostragem: o estado reportado não substitui medição de erro absoluto.

## Auditoria por arquivo

`--ptp-audit on|off` liga ou desliga a gravação do JSONL. O padrão é `on`,
preservando o comportamento anterior. A opção exige `--ptp` e é definida ao
iniciar o processo. Com `--ptp-audit off`, nenhum arquivo de auditoria é criado;
o monitoramento, os avisos em stderr e a conversão de timestamps continuam ativos.
Arquivos de auditoria de execuções anteriores não são apagados.

Com a auditoria habilitada, cada captura em modo PTP recebe um arquivo
`captura1.pcap.ptp.jsonl` contendo:

- identidade do relógio, escala declarada, origem da correção e limites;
- amostras de sincronismo, offset, GM, domínio e correção TAI−UTC;
- `next_packet`, índice começando em 1 do próximo registro ao observar o estado;
- no encerramento, total de registros e quantos não tinham sincronismo confirmado.

O PCAP permanece padrão e não recebe campos adicionais. O JSONL pode ser lido
durante a captura; um evento `end` com `capture_complete: true` indica que o
capturador concluiu a publicação do PCAP. Não é uma publicação atômica dos dois
arquivos e não há `fsync` do JSONL. Se o processo cair, o último registro de
auditoria pode ficar incompleto. Falha na auditoria gera aviso e não para os
pacotes. Esses metadados são observacionais, não um certificado de sincronismo.
Com `-w -` ou saída textual, os avisos vão para stderr e não há JSONL por arquivo.

## Integração do provedor de telemetria

O capturador aceita telemetria normalizada e há uma ponte JSON configurável em
`tools/ptp_status_bridge.py`. Não há parser nativo específico para Timebeat ou
outro serviço: valide o mapeamento contra uma amostra real da versão instalada.
Sem telemetria válida, a captura funciona, mas permanece `unknown`.

A ponte roda em outro processo: consultas HTTP, arquivos ou timeouts não entram
no loop de recepção. Ela aceita um snapshot JSON local (`--input-file`) ou um
endpoint JSON verificado (`--url`). Não habilita HTTP, não reinicia serviços e
não consulta Elasticsearch automaticamente. Se for usado o endpoint HTTP do
provedor, sua disponibilidade e ativação dependem da configuração desse serviço.

O arquivo `--mapping` associa campos a JSON Pointers. Exemplo **sintético**
(não representa o schema de um provedor específico):

```json
{
  "clock": "/clock",
  "state": "/state",
  "observed_at": "/measurement_time",
  "offset": "/offset_ns",
  "offset_multiplier_to_ns": 1,
  "gm": "/grandmaster",
  "domain": "/domain",
  "scale": "/scale",
  "tai_offset": "/tai_utc_offset",
  "states": {"LOCKED": "synced", "HOLDOVER": "holdover", "UNLOCKED": "unsynced"}
}
```

`observed_at` deve ser a hora UTC **da medição**, em segundos Unix ou ISO 8601
com timezone, e não a hora da requisição HTTP. Um snapshot em cache não pode
renovar a validade. O offset deve ser do PHC capturado em relação à referência,
não offset bruto da rede ou de uma fonte em modo monitor-only. O estado mapeado
para `synced` deve confirmar que essa referência está disciplinando o relógio.
Valores sem correspondência viram `unknown`. Não mapear apenas "processo ativo"
ou "pacotes PTP recebidos" para `synced`.

Se a escala e o offset não vierem na telemetria, somente esses dois campos
podem ser declarados explicitamente, por exemplo `"scale": {"literal": "utc"}`
e `"tai_offset": {"literal": 0}`. Isso é uma declaração do operador, não
autodetecção. O identificador, estado, hora da medição, offset, GM e domínio
devem vir de telemetria real. Amostras antigas/futuras e identidades divergentes
são rejeitadas. A comparação de idade no provedor usa o relógio UTC do host;
um salto nesse relógio pode invalidar amostras temporariamente.

Depois de validar o mapeamento e a origem do snapshot:

```bash
python3 tools/ptp_status_bridge.py \
  --input-file /run/clock-snapshot.json \
  --mapping /etc/exanic-capture/clock-mapping.json \
  --socket /run/exanic-capture-ptp.sock \
  --clock-id exanic0 --expected-source-clock eth0
```

`exanic0` e `eth0` são exemplos: use o identificador configurado na captura e a
identidade exata do mesmo relógio no JSON do provedor, respectivamente.

O snapshot acima não é criado automaticamente por este comando: precisa ser
obtido da telemetria real. Não usar exemplos estáticos como
evidência de sincronismo. A ponte exige Python 3.9+ e apenas a biblioteca padrão.
Execute-a com o mesmo usuário da captura ou root, pois o socket é privado.

### Protocolo local

Uma mensagem ASCII por datagrama Unix, até 511 bytes:

```text
v1 CLOCK_ID STATE OFFSET_NS SCALE GM DOMAIN TAI_UTC_SECONDS OBSERVED_MONOTONIC_NS
```

`STATE`: `synced`, `unsynced`, `holdover` ou `unknown`.
`OFFSET_NS`: inteiro assinado ou `unknown`. `SCALE`: `utc` ou `tai`.
`GM`: identificador ou `unknown`. Domínio: 0–255. Offset TAI−UTC: 0–1000 s
(0 quando não aplicável à entrada UTC). Identificadores: até 64 caracteres
alfanuméricos ou `_.:-`. A observação usa `CLOCK_MONOTONIC` do mesmo host/namespace
da captura. A ponte preserva a idade real da medição ao fazer essa tradução.

O caminho do socket deve estar em diretório local controlado pelo usuário/root.
Um caminho existente nunca é removido no início. No encerramento normal o
capturador remove somente o socket criado por ele; após crash, o operador deve
confirmar que não existe captura ativa antes de remover o socket residual.

## Referências

- [Timebeat: comandos da CLI](https://community.timebeat.app/timebeat-sync-software-guides-ijbrdkl6/post/what-commands-are-available-in-the-timebeat-cli-xfdK0jYbrrrRnx3)
- [Timebeat: configuração de PHC](https://timebeat.app/community/platform/linux-phc-configuration)
- [Timebeat: CLI e status HTTP](https://timebeat.app/community/platform/cli-and-http-access)
- [Cisco: sincronização ExaNIC](https://www.cisco.com/c/en/us/td/docs/dcn/nexus3550/smartnic/sw/user-guide/cisco-nexus-smartnic-user-guide/clock-sync.html)
