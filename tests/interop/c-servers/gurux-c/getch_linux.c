/* Linux stand-in for the console helper GuruxDLMSServerExample/src/main.c
 * calls but does not define at the pinned commit (link error otherwise).
 * Written for this harness; not Gurux code. With no stdin (docker run -d)
 * it idles instead of spinning. */
#include <stdio.h>
#include <unistd.h>

char _getch(void)
{
    int c = getchar();
    if (c == EOF)
    {
        clearerr(stdin);
        sleep(1);
        return 0;
    }
    return (char)c;
}
