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
#define ETH_LEN 1600
struct ifreq ethreq;

// Definición de tipos de variables
typedef unsigned char un_char;
typedef unsigned int un_int;
typedef unsigned long long un_long;

FILE *fptr;
volatile int cont_ethr2;
volatile int cont_ip;
volatile int cont_ip6;
volatile int cont_arp;
volatile int cont_pause;
volatile int cont_secmac;
int number_of_packages;
un_long *array_hash;

struct ethernet_frame_args
{
    un_char *buffer;
    int recv_len;
    int paq_ID;
};

un_char getBit(un_char c, int k)
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

un_long hash(un_char *str)
{
    un_long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    //printf("%llu\n", hash);
    return hash;
}

void addHash(un_char *esource, un_char *edest, int paq_ID)
{
    un_char str[12];
    int i_;
    for (i_ = 0; i_ < 6; i_++)
    {
        str[i_] = esource[i_];
        str[i_ + 6] = edest[i_];
    }
    array_hash[paq_ID] = hash(str);
}

void print_reps()
{
    int i, j;
    int array_reps[number_of_packages];
    for (i = 0; i < number_of_packages; i++)
        array_reps[i] = 0;
    //memset(&array_reps, 0, sizeof(array_reps));
    un_long mask_repetidos = 0;
    for (i = 0; i < number_of_packages; i++)
    {
        mask_repetidos |= ((un_long)1) << i;
        for (j = 0; j < number_of_packages; j++)
        {
            if (i != j && getBit_l(mask_repetidos, j) == 0)
            {
                // Si aun no contado como repetido:
                if (array_hash[i] == array_hash[j])
                {
                    array_reps[i]++;
                    // Actualizamos mascara
                    mask_repetidos |= ((un_long)1) << j;
                }
            }
        }
        if (array_reps[i] > 0)
        {
            fprintf(fptr, " *****\tLa dupla de direcciones MAC de %d tuvo %d apariciones\n", i + 1, array_reps[i] + 1);
        }
    }
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

    struct ethhdr *eth;
    memset(&eth, 0, sizeof(eth));

    // CABECERA ETHERNET:
    eth = (struct ethhdr *)args->buffer;
    addHash(eth->h_source, eth->h_dest, args->paq_ID);

    fprintf(fptr, "\n[%d] Cabecera Ethernet --------------------\n \t|-Dir. fuente : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n \t|-Dir. destino : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
            args->paq_ID, eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5],
            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

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
    // CABECERA IP:
    if (eth->h_proto > 1535)
    { // Trama Ethernet II: 1535
        cont_ethr2++;

        struct iphdr *ip = (struct iphdr *)(args->buffer + sizeof(struct ethhdr));
        struct sockaddr_in source, dest;
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = ip->saddr;
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = ip->daddr;

        fprintf(fptr, "\t|-Protocolo : 0x%.2X (%d) ",
                permut_half(eth->h_proto), permut_half(eth->h_proto));
        //printNum(eth->h_proto);
        //fprintf(fptr, " \t| %s\n", identifica_protocolo(eth->h_proto));
        if (permut_half(eth->h_proto) == ETH_P_IP)
        {
            fprintf(fptr, " *** IPv4\n"); //  cont_ip++;
        }
        else if (permut_half(eth->h_proto) == ETH_P_IPV6)
        {
            fprintf(fptr, " *** IPv6\n"); //  cont_ip6++;
        }
        else if (permut_half(eth->h_proto) == ETH_P_ARP)
        {
            fprintf(fptr, " *** ARP\n"); //   cont_arp++;
        }
        else if (permut_half(eth->h_proto) == ETH_P_PAUSE)
        {
            fprintf(fptr, " *** Contrl de Flujo\n"); //   cont_pause++;
        }
        else if (permut_half(eth->h_proto) == 0x88E5)
        {
            fprintf(fptr, " *** Sec. MAC\n"); //  cont_secmac++;
        }
        else
        {
            fprintf(fptr, " \t*** Ninguno de esos protocolos de capa superior.\n");
        }

        un_int payload_len = (un_int)args->recv_len - 18; // 6 & 6 Bytes MAc, 2B Type, 4B CRC
        fprintf(fptr, " \t| Longitud de carga util: %d\n", payload_len);

        fprintf(fptr, "    Cabecera IP\n \t|-Version : %d\n", (un_int)ip->version);
        //fprintf(fptr, "%\t|-Internet Header Length : %d DWORDS or %d Bytes\n\t|-Tipo de Servicio : %d\n", (ui)ip->ihl,((ui)(ip->ihl))*4,  (ui)ip->tos);
        //fprintf(fptr , "\t|-Longitud total : %d Bytes (%d)\n",ntohs(ip->tot_len), args->recv_len);
        fprintf(fptr, "\t|-Identificacion : %d\n", ntohs(ip->id));
        //fprintf(fptr , "\t|-Tiempo de vida : %d\n",(ui)ip->ttl);
        //fprintf(fptr , "\t|-Protocolo : 0x%.2X (%d)\n", ip->protocol, (ui)ip->protocol);
        //fprintf(fptr , "\t|-Header Checksum : %d\n",ntohs(ip->check));
        fprintf(fptr, "\t|-IP fuente : %s\n", inet_ntoa(source.sin_addr));
        fprintf(fptr, "\t|-IP destino : %s\n", inet_ntoa(dest.sin_addr));
    }
    //fclose(fptr);
}

void print_final_info()
{
    fprintf(fptr, "\n***** TRAMAS CAPTURADAS : %d, \tTRAMAS ETHERNET II ANALIZADAS : %d, \tTRAMAS 802.3 NO ANALIZADAS : %d *****\n\n",
            number_of_packages, cont_ethr2, (number_of_packages - cont_ethr2));
    fprintf(fptr, "*****\tIPv4: %d\tIPv6: %d\tARP: %d\tControl de flujo: %d\tSeg. MAC: %d\t*****\n\n",
            cont_ip, cont_ip6, cont_arp, cont_pause, cont_secmac);
    print_reps();
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
        printf("All is ok! the arguments are: \npackages: %s \nnetwork card name: %s\n", argv[1], argv[2]);

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
        array_hash = (un_long *)malloc(sizeof(un_long) * number_of_packages);

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
        for (i = 0; i < number_of_packages; ++i)
        {
            hargs[i] = (struct ethernet_frame_args *)malloc(sizeof(struct ethernet_frame_args *));
            buffer[i] = (un_char *)malloc(ETH_LEN);
            memset(buffer[i], 0, sizeof(buffer[i]));
        }
        for (i = 0; i < number_of_packages; ++i)
        {

            // Empezamos a recibir de todo:
            recv_len = recvfrom(sock_id, buffer[i], ETH_LEN, 0, (struct sockaddr *)&sadd, (socklen_t *)&sadd_len);
            if (recv_len < 0)
            {
                perror("Error in recvfrom...");
                return -1;
            }
            //printf("\nSomething received. \n");
            //buffer[recv_len] = '\0';
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

        // Restore to initial settings the network card
        char order[] = "/sbin/ifconfig ";
        strcat(order, card_name);
        strcat(order, " -promisc\n");
        printf("\nEjecutando: %s\n", order);

        system(order);

        system("cat data.txt");
    }

    return 0;
}
