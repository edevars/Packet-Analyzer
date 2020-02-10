# Packet Analyzer (Sniffer)

## Objetivo

Identificar la funcionalidad de un sniffer para realizar un análisis de tráfico en una red de datos.

## Desarrollo

Utilizando lenguaje C para Linux, implemente un sniffer que capture los paquetes que están viajando en la red, específicamente se deben capturar tramas Ethernet. Se debe analizar la trama capturada y determinar si es una trama IEEE 802.3 (0x0000 a 0x05DC) o una trama Ethernet II (mayor o igual a 0x0600). Si la trama es IEEE 802.3 se debe indicar que dicha trama no puede ser analizada, por el contrario, si la trama es de tipo Ethernet II, se debe determinar el protocolo de capa superior al que pertenece:

- (IPv4) Protocolo de Internet versión 4(0x0800)
- (IPv6) Protocolo de Internet versión 6(0x86DD)
- (ARP) Protocolo de resolución de direccione (0x0806)
- Control de flujo Ethernet (0x8808)
- Seguridad MAC (0x88E5)

Además, para las tramas Ethernet II se debe extraer la siguiente información:

- Dirección MAC fuente
- Dirección MAC destino
- Longitud de la trama
- Longitud de carga útil (datos y relleno)
- Determinar si la dirección de destino es una dirección de unidifusión, difusión o multidifusión.

### Condiciones

1. El número de paquetes que se van a capturar y el nombre de la tarjeta de red debe ser introducido como un dato de entrada dentro del programa o en línea de comandos, no con valores predeterminados dentro del código.

2. Se deben manejar dos procesos: capturador y analizador (manejo de hilos).

3. Toda la información de las tramas capturadas se debe guardar en un archivo de texto, separando claramente la información de cada una de tramas analizadas.

4. En el archivo se debe incluir una línea que indique el número de tramas capturadas, el número de tramas Ethernet II analizadas y el número de tramas 802.3 que no fueron analizadas.

5. Una línea que indique cuantas de las tramas analizadas pertenecen a cada uno de los protocolos de capa superior descritos.

6. Además, se deberá identificar si hay más de una trama perteneciente a una misma dirección origen y dirección destino y mostrar el número de tramas correspondientes.

## Como ejecutar

```bash
gcc -pthread main.c -o sniffer
sudo ./sniffer
```
