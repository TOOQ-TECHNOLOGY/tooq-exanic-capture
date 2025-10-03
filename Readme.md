# Tooq-Exanic-Capture

Este código é uma versão modificada do famoso [exanic-capture](https://github.com/cisco/exanic-software/blob/master/util/exanic-capture.c).

## Diferenças
- O **tooq-exanic-capture** salva os arquivos PCAP em **pastas organizadas por dia**.  
- Antes de salvar na pasta do dia, o PCAP é gerado dentro de um diretório chamado **temp** e, em seguida, movido para a pasta do dia correspondente.  
- Os arquivos PCAP são salvos **por tempo**, e não por tamanho.  
- Não existe mais a sequência `.pcap`, `.pcap1`, `.pcap2`. Agora os arquivos seguem o formato:
  - Primeiro em `temp/<nome_pcap>`  
  - Depois em `nome_da_pasta/<nome_passado + iterador(int)>.pcap`

- **Obs:** `temp/` **não é** `/tmp/`.  
  `temp/` é uma pasta criada na partição local para salvar os PCAPs temporários enquanto estão sendo construídos.
## Comando de uso

Exemplo:
```bash
sudo ./build/exanic-capture -i enp23s0 -G 60 -w teste -R "/mnt/var/datafix/"
```

Sendo:
- `-i` → interface  
- `-G` → tempo em segundos para gerar cada arquivo pcap  
- `-w` → prefixo do nome do arquivo  
- `-R` → diretório onde o pcap será salvo após `temp/`  

## Erros de driver

Caso ocorra algum erro de driver, vá no repositório [exanic](https://github.com/cisco/exanic-software/blob/master/Makefile) e rode:
make modules
make install-modules

## Demais comandos
```bash
- `-i` : especifica interface Linux (ex: eth0) ou porta ExaNIC (ex: exanic0:0)  
- `-w` : salva pacotes no arquivo indicado (ou stdout com `-`)  
- `-s` : tamanho máximo de dados a capturar  
- `-C` : tamanho de arquivo para rotação (em milhões de bytes)  
- `-F` : formato do arquivo `[pcap|erf]` (default: pcap)  
- `-p` : não tenta colocar a interface em modo promíscuo  
- `-H` : usa timestamps de hardware (ver documentação para sync de clock)  
- `-N` : grava formato pcap com resolução de nanossegundos  
- `-G` : rotaciona para novo arquivo a cada N segundos (rotação por tempo)  
```
## OBS
Não julguem o dev 😅 — estou sem o **Conan**.  
Ele apresentava um erro de compatibilidade com meu kernel.  
Edit: *apresentava*, mas sem tempo para trocar.
