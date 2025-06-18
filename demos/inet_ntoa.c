#define _BSD_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    struct in_addr addr;
    char input[50];
    
    scanf("%[^\n]%*c", input);

   if (inet_aton(input, &addr) == 0) {
        fprintf(stderr, "Invalid address\n");
        exit(EXIT_FAILURE);
    }

   printf("%s\n", inet_ntoa(addr));
    exit(EXIT_SUCCESS);
}