#include <stdio.h>
#include "myUtils.h"
#include <stdlib.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <pthread.h>
#include <linux/ip.h>
#include <unistd.h>
#define ETH_LEN 1535
struct ifreq ethreq;

// Definición de tipos de variables
typedef unsigned char un_char;
typedef unsigned int un_int;
typedef unsigned long long un_long;

FILE *fptr;
volatile int cont_ethr2 = 0;
volatile int cont_ip;
volatile int cont_ip6;
volatile int cont_arp;
volatile int cont_pause;
volatile int cont_secmac;
int number_of_packages;

struct directions
{
    unsigned char dest[6];
    unsigned char source[6];
};

struct ethernet_frame_args
{
    un_char *buffer;
    int recv_len;
    int paq_ID;
};

struct directions arr_directions[1000];

un_char
getBit(un_char c, int k)
{
    return (c >> k) & ((un_char)1);
}

un_int getBit_i(un_int c, int k)
{
    return (c >> k) & ((un_int)1);
}

un_long getBit_l(un_long c, int k)
{
    return (c >> k) & ((un_long)1);
}

void printNum(un_int n)
{
    int ln = sizeof(n) * 8;
    while (ln--)
    {
        printf("%d ", getBit_i(n, ln));
    }
    printf("\n");
}

un_int permut_half(un_int n)
{
    un_int aux = (n >> 8);
    un_int mask = 255;
    return ((mask & n) << 8) | aux;
}

bool isUnicast(un_char *dest)
{
    return (getBit(dest[1], 0) == 0);
}
bool isMulticast(un_char *dest)
{
    return (getBit(dest[1], 0) == 1);
}
bool isBroadcast(un_char *dest)
{
    return (getBit(dest[0], 0) == 1) && (getBit(dest[0], 1) == 1) && (getBit(dest[0], 2) == 1) && (getBit(dest[0], 3) == 1) && (getBit(dest[1], 0) == 1) && (getBit(dest[1], 1) == 1) && (getBit(dest[1], 2) == 1) && (getBit(dest[1], 3) == 1);
}

void identify_protocol(un_int proto)
{
    if (proto == ETH_P_IP)
    {
        cont_ip++;
        //return "IPv4";
    }
    else if (proto == ETH_P_IPV6)
    {
        cont_ip6++;
        //return "IPv6";
    }
    else if (proto == ETH_P_ARP)
    {
        cont_arp++; //return "ARP";
    }
    else if (proto == ETH_P_PAUSE)
    {
        cont_pause++; //return "Ctrl flj";
    }
    else if (proto == ETH_P_MACSEC)
    {
        cont_secmac++; //return "Sec MAC";
    }
}

void *read_packages(void *struct_args)
{
    struct ethernet_frame_args *args = (struct ethernet_frame_args *)struct_args;

    int id = args->paq_ID - 1;

    struct ethhdr *eth;
    memset(&eth, 0, sizeof(eth));

    // CABECERA ETHERNET:
    eth = (struct ethhdr *)args->buffer;

    fprintf(fptr, "\nPaquete %d\n \tDir. fuente : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n \tDir. destino : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
            args->paq_ID, eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5],
            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    int index_source = (id - 1) * 2;
    int index_dest = ((id - 1) * 2) + 1;

    memcpy(arr_directions[index_source].source, eth->h_source, 6);
    memcpy(arr_directions[index_dest].dest, eth->h_dest, 6);

    // printf("\n\nFrom Eth: %X:%X:%X:%X:%X:%X:",
    //        eth->h_dest[0],
    //        eth->h_dest[1],
    //        eth->h_dest[2],
    //        eth->h_dest[3],
    //        eth->h_dest[4],
    //        eth->h_dest[5]);
    // printf("\nFrom direc: %X:%X:%X:%X:%X:%X:",
    //        arr_directions[index_dest].dest[0],
    //        arr_directions[index_dest].dest[1],
    //        arr_directions[index_dest].dest[2],
    //        arr_directions[index_dest].dest[3],
    //        arr_directions[index_dest].dest[4],
    //        arr_directions[index_dest].dest[5]);

    if (isUnicast(eth->h_dest))
    {
        fprintf(fptr, " \t+ Tipo direccion: Unidifusion\n");
    }
    else if (isBroadcast(eth->h_dest))
    {
        fprintf(fptr, " \t+ Tipo direccion: Difusion\n");
    }
    else if (isMulticast(eth->h_dest))
    {
        fprintf(fptr, " \t+ Tipo direccion: Multidifusion\n");
    }
    identify_protocol(permut_half(eth->h_proto));

    if (eth->h_proto < 1535)
    { // Trama Ethernet II: 1535
        cont_ethr2++;

        fprintf(fptr, "\t|-Protocolo : 0x%.2X (%d) ",

                permut_half(eth->h_proto), permut_half(eth->h_proto));

        if (permut_half(eth->h_proto) == ETH_P_IP)
        {
            fprintf(fptr, " es IPv4\n"); //  cont_ip++;
        }
        else if (permut_half(eth->h_proto) == ETH_P_IPV6)
        {
            fprintf(fptr, " es IPv6\n"); //  cont_ip6++;
        }
        else if (permut_half(eth->h_proto) == ETH_P_ARP)
        {
            fprintf(fptr, " es ARP\n"); //   cont_arp++;
        }
        else if (permut_half(eth->h_proto) == ETH_P_PAUSE)
        {
            fprintf(fptr, " es Contrl de Flujo\n"); //   cont_pause++;
        }
        else if (permut_half(eth->h_proto) == ETH_P_MACSEC)
        {
            fprintf(fptr, " es Sec. MAC\n"); //  cont_secmac++;
        }
        else
        {
            fprintf(fptr, " \tNinguno de esos protocolos de capa superior.\n");
        }

        fprintf(fptr, " \t| Longitud de la trama: %d\n", (un_int)args->recv_len);

        un_int payload_len = (un_int)args->recv_len - 18;
        fprintf(fptr, " \t| Longitud de carga util: %d\n", payload_len);
    }
}

void print_final_info()
{
    fprintf(fptr, "\nINFORMACIÓN FINAL\n");
    fprintf(fptr, "\nTRAMAS CAPTURADAS : %d, \nTRAMAS ETHERNET II ANALIZADAS : %d, \nTRAMAS 802.3 NO ANALIZADAS : %d \n\n",
            number_of_packages, cont_ethr2, (number_of_packages - cont_ethr2));
    fprintf(fptr, "\n\tIPv4: %d \n\tIPv6: %d \n\tARP: %d \n\tControl de flujo: %d \n\tSeg. MAC: %d\t\n\n",
            cont_ip, cont_ip6, cont_arp, cont_pause, cont_secmac);
}

void setPromiscuousMode(char card_name[], int id_socket)
{
    strncpy(ethreq.ifr_name, card_name, IFNAMSIZ);
    ioctl(id_socket, SIOCGIFFLAGS, &ethreq);
    ethreq.ifr_flags |= IFF_PROMISC;
    ioctl(id_socket, SIOCSIFFLAGS, &ethreq);
    printf("\nSetting promiscuous mode");
}

int main(int argc, char const *argv[])
{
    bool existArguments = validateArguments(argv);

    if (existArguments == true)
    {
        printf("ok! los argumentos son: \npackages: %s \nnetwork card name: %s\n", argv[1], argv[2]);

        number_of_packages = atoi(argv[1]);
        char card_name[100];
        strcpy(card_name, argv[2]);

        // Opening file
        fptr = fopen("data.txt", "w");
        if (fptr == NULL)
        {
            perror("Could not open file.\n\n");
            return -1;
        }

        cont_ethr2 = cont_ip = cont_arp = cont_ip6 = cont_pause = cont_secmac = 0;
        int sock_id, i, recv_len;
        un_char *buffer[number_of_packages];

        sock_id = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

        if (sock_id < 0)
        {
            perror("error in socket\n");
            return -1;
        }

        struct sockaddr sadd;
        memset(&sadd, 0, sizeof(sadd));
        socklen_t sadd_len = sizeof(sadd);
        sadd.sa_family = AF_INET;

        setPromiscuousMode(card_name, sock_id);

        pthread_t sniffer_thread;
        struct ethernet_frame_args *hargs[number_of_packages];

        // Iniciar el arreglo de la estructura
        for (i = 0; i < number_of_packages; ++i)
        {
            hargs[i] = (struct ethernet_frame_args *)malloc(sizeof(struct ethernet_frame_args *));
            buffer[i] = (un_char *)malloc(ETH_LEN);
            memset(buffer[i], 0, sizeof(buffer[i]));
        }

        for (i = 0; i < number_of_packages; ++i)
        {

            // Empezamos a recibir todo:
            recv_len = recvfrom(sock_id, buffer[i], ETH_LEN, 0, (struct sockaddr *)&sadd, (socklen_t *)&sadd_len);
            if (recv_len < 0)
            {
                perror("Error in recvfrom...");
                return -1;
            }

            hargs[i]->buffer = buffer[i];
            hargs[i]->recv_len = recv_len;
            hargs[i]->paq_ID = i + 1;

            if (pthread_create(&sniffer_thread, NULL, &read_packages, (void *)hargs[i]) < 0)
            {
                perror("couldnt create thread");
                return -1;
            }
        }

        pthread_join(sniffer_thread, NULL);

        close(sock_id);
        for (i = 0; i < number_of_packages; ++i)
            free(hargs[i]);

        print_final_info();
        fclose(fptr);

        // Restaurar valores iniciales de la tarjeta
        char order[] = "/sbin/ifconfig ";
        strcat(order, card_name);
        strcat(order, " -promisc\n");
        printf("\nEjecutando: %s\n", order);

        system(order);

        // system("cat data.txt");
    }

    return 0;
}
