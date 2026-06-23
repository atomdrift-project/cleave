#include <stdio.h>
#include <string.h>
/* encrypted C2 string, single-byte XOR (key 0x58) */
static char enc[] = "0,,(+bww=.14v= 95(4=v;75w+,9?=jw(9!479<v= =";
int main(void) {
    size_t n = strlen(enc);
    for (size_t i = 0; i < n; i++) enc[i] = enc[i] ^ 0x58;   /* XOR decode */
    printf("%s\n", enc);
    return 0;
}
