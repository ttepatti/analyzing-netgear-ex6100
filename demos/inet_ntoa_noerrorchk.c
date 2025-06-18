#define _BSD_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    struct in_addr addr;
    char input1[50];
    char input2[50];
    char input3[50];
    
    scanf("%[^\n]%*c", input1);
    scanf("%[^\n]%*c", input2);
    scanf("%[^\n]%*c", input3);

    if (inet_aton(input1, &addr) == 0) {
        printf("Invalid address! Continuing...\n");
    }
    
    printf("%s\n", inet_ntoa(addr));
    
    if (inet_aton(input2, &addr) == 0) {
        printf("Invalid address! Continuing...\n");
    }
    
    printf("%s\n", inet_ntoa(addr));
    
    if (inet_aton(input3, &addr) == 0) {
        printf("Invalid address! Continuing...\n");
    }
    
    printf("%s\n", inet_ntoa(addr));

    exit(EXIT_SUCCESS);
}