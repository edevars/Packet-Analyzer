#include <stdio.h>
#include "myUtils.h"
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

struct ifreq ethreq;

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

        int number_of_packages = atoi(argv[1]);
        char card_name[100];
        strcpy(card_name, argv[2]);

        //Creating RAW socket
        int sock_id;
        sock_id = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

        if (sock_id < 0)
        {
            perror("error in socket\n");
            return -1;
        }

        setPromiscuousMode(card_name, sock_id);

        // Restore to initial settings the network card
        char order[] = "/sbin/ifconfig ";
        strcat(order, card_name);
        strcat(order, " -promisc\n");
        printf("\nEjecutando: %s\n", order);

        system(order);
    }

    return 0;
}
