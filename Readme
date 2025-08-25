# Tooq-Exanic-Capture

Este código é uma versão modificada do famoso [exanic-capture](https://github.com/cisco/exanic-software/blob/master/util/exanic-capture.c).

## Diferenças

- O **tooq-exanic-capture** salva os arquivos PCAP em **pastas organizadas por dia**.  
- Antes de salvar na pasta do dia, o PCAP é gerado dentro de um diretório chamado **`temp`** e, em seguida, movido para a pasta do dia correspondente.  
- Os arquivos PCAP são salvos **por tempo**, e não por tamanho.  
- Não existe mais a sequência `.pcap`, `.pcap1`, `.pcap2`.  
  Agora, os arquivos seguem o formato:  <pasta_do_dia>/<nome_passado>_<timestamp>.pcap

## OBS

Não julguem o dev 😅 — estou sem o **Conan**.  
Ele apresenta um erro de compatibilidade com meu kernel.