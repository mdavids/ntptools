#include <stdio.h>
#include <time.h> // Voor tijdgerelateerde functies
#include <unistd.h> // Voor usleep

int main() {
    struct timespec ts; // Structuur om tijd in te slaan (seconden en nanoseconden)

    for (int i = 0; i < 10; i++) {
        // Haal de huidige tijd op met nanoseconden-precisie
        // CLOCK_REALTIME is de absolute real-time klok
        if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
            perror("clock_gettime"); // Print foutmelding als er iets misgaat
            return 1; // Sluit het programma af met een foutcode
        }

        // Print het nanoseconden-deel (ts.tv_nsec)
        printf("%ld\n", ts.tv_nsec);

        // Pauzeer voor 10 milliseconden (10 * 1000 microseconden)
        usleep(10 * 1000);
    }

    return 0; // Geen fouten, programma succesvol afgesloten
}

// gcc -o nanoseconds-c nanoseconds.c 
//
// Altijd drie '000' aan het einde op MacOS
// Maar niet op Linux
//
