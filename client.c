/********************************************************************************
 * Program:    Klient pre zabezpeceny prenos suborov
 * Subor:      client.c
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      2024
 * 
 * Popis: 
 *     Klientska cast aplikacie pre zabezpeceny prenos suborov. Program
 *     implementuje nasledovne funkcie:
 *     - Sifrovanie dat pomocou ChaCha20-Poly1305
 *     - Generovanie kryptografickej soli a nonce hodnot
 *     - Odvodenie sifrovacieho kluca z hesla (Argon2)
 *     - Zabezpecena komunikacia cez TCP protokol
 *     - Podpora pre Windows aj Linux systemy
 * 
 * Zavislosti:
 *     - Monocypher 4.0.2 (sifrovacie algoritmy)
 *     - Standardne C kniznice
 *     - siete.h (deklaracie sietovych funkcii)
 *     - constants.h (definicie konstant pre program)
 *     - crypto_utils.h (deklaracie kryptografickych funkcii)
 ******************************************************************************/

#include <stdio.h>        // Kniznica pre standardny vstup a vystup (nacitanie zo suborov, vypis na obrazovku)
#include <stdlib.h>       // Kniznica pre vseobecne funkcie (sprava pamate, konverzie, nahodne cisla)
#include <string.h>       // Kniznica pre pracu s retazcami (kopirovanie, porovnavanie, spajanie)
#include <unistd.h>       // Kniznica pre systemove volania UNIX (procesy, subory, sokety)

#ifdef _WIN32
#include <winsock2.h>     // Windows: Zakladna sietova kniznica
#include <ws2tcpip.h>     // Windows: Rozsirene sietove funkcie
#include <windows.h>      // Windows: Zakladne systemove funkcie
#include <bcrypt.h>       // Windows: Kryptograficke funkcie
#include <conio.h>        // Windows: Konzolovy vstup/vystup (implementacia getpass())

#else
#include <sys/random.h>   // Linux: Generovanie kryptograficky bezpecnych nahodnych cisel
#include <arpa/inet.h>    // Linux: Sietove funkcie (konverzia adries, sokety)
#include <dirent.h>       // Linux: Operacie s adresarmi
#include <sys/stat.h>     // Linux: Operacie so subormi
#include <fcntl.h>        // Linux: Nastavenia kontroly suborov
#include <sys/time.h>     // Linux: Struktura pre cas (struct timeval)
#include <errno.h>        // Linux: Sprava a hlasenie chyb
#endif

#include "monocypher.h"  // Pre Monocypher kryptograficke funkcie
#include "siete.h"        // Pre sietove funkcie
#include "constants.h"    // Shared constants
#include "crypto_utils.h" // Pre kryptograficke funkcie


// Globalne premenne pre kryptograficke operacie
// Tieto premenne sa pouzivaju v celom programe pre sifrovacie operacie
uint8_t key[KEY_SIZE];          // Hlavny sifrovaci kluc
uint8_t nonce[NONCE_SIZE];      // Jednorazova hodnota pre kazdy blok
uint8_t salt[SALT_SIZE];        // Sol pre derivaciu kluca
uint8_t work_area[WORK_AREA_SIZE]; // Pracovna oblast pre Argon2

#ifdef _WIN32
// Implementacia getpass() pre Windows platformu
// Dovod: Windows nema nativnu implementaciu tejto funkcie
// Parametre:
//   - prompt: Text, ktory sa zobrazi uzivatelovi
// Navratova hodnota:
//   - Ukazovatel na zadane heslo (staticky buffer)
char *getpass(const char *prompt) {
    static char password[PASSWORD_BUFFER_SIZE]; // Pevna velkost pola pre heslo
    size_t i = 0;
    
    printf("%s", prompt); // Vypis vyzvy pre zadanie hesla
    
    // Nacitavanie znakov po jednom bez ich zobrazenia
    while (i < sizeof(password) - 1) {
        char ch = getch();
        if (ch == '\r' || ch == '\n') { // Enter ukonci zadavanie
            break;
        } else if (ch == '\b') { // Backspace pre mazanie
            if (i > 0) {
                i--;
                printf("\b \b"); // Odstranenie znaku z obrazovky
            }
        } else {
            password[i++] = ch;
            printf("*"); // Zobrazenie hviezdicky namiesto znaku
        }
    }
    password[i] = '\0'; // Ukoncenie retazca nulovym znakom
    printf("\n");
    
    return password;
}
#endif

int main() {
    // KROK 1: Inicializacia spojenia so serverom
    // - Vytvorenie TCP socketu
    // - Pripojenie na server (127.0.0.1)
    // - Overenie uspesnosti pripojenia
    int sock;

    // Inicializacia sietovej kniznice pre Windows
    initialize_network();

    // Vytvorenie TCP spojenia so serverom
    // - vytvori socket
    // - pripoji sa na lokalny server (127.0.0.1)
    // - port je definovany v constants.h
    if ((sock = connect_to_server("127.0.0.1")) < 0) {
        fprintf(stderr, "Error: Failed to connect to server (%s)\n", strerror(errno));
        return -1;
    }

    // Pocka na signal pripravenosti od servera
    // Zabezpeci synchronizaciu medzi klientom a serverom
    if (wait_for_ready(sock) < 0) {
        fprintf(stderr, "Error: Server not responding - connection timeout\n");
        cleanup_socket(sock);
        return -1;
    }

    // KROK 2: Priprava kryptografickych materialov
    // - Generovanie nahodnej soli (32 bajtov)
    // - Nacitanie hesla od uzivatela
    // - Odvodenie kluca pomocou Argon2
    // - Odoslanie soli serveru
    char *password = getpass("Zadajte heslo: ");
    if (derive_key_client(password, key, salt) != 0) {
        fprintf(stderr, "Error: Key derivation failed - memory allocation or internal error\n");
        cleanup_socket(sock);
        return -1;
    }

    // Posle salt serveru, aby mohol odvodi rovnaky kluc
    if (send_salt_to_server(sock, salt) < 0) {
        fprintf(stderr, "Error: Failed to send salt to server (%s)\n", strerror(errno));
        cleanup_socket(sock);
        return -1;
    }

    // Cakanie na 'KEYOK' potvrdenie od servera
    if (wait_for_key_acknowledgment(sock) < 0) {
        fprintf(stderr, "Error: Failed to receive key acknowledgment from server\n");
        cleanup_socket(sock);
        return -1;
    }

    // KROK 3: Spracovanie vstupneho suboru
    // - Zobrazenie dostupnych suborov
    // - Nacitanie nazvu suboru od uzivatela
    // - Kontrola existencie a pristupnosti suboru
    printf("Files in the project directory:\n");
    #ifdef _WIN32
    // Windows-specificky kod na zobrazenie suborov
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile("./*", &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                printf("%s\n", findFileData.cFileName);
            }
        } while (FindNextFile(hFind, &findFileData));
        FindClose(hFind);
    }
    #else
    // Linux-specificky kod na zobrazenie suborov
    DIR *d;
    struct dirent *dir;
    struct stat st;
    d = opendir(".");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (stat(dir->d_name, &st) == 0 && S_ISREG(st.st_mode)) {
                printf("%s\n", dir->d_name);
            }
        }
        closedir(d);
    }
    #endif

    // Nacitanie nazvu suboru od uzivatela
    printf("Zadajte nazov suboru na odoslanie (max 239 znakov): ");
    char file_name[FILE_NAME_BUFFER_SIZE];
    if (fgets(file_name, sizeof(file_name), stdin) == NULL) {
        fprintf(stderr, "Error: Failed to read file name from input\n");
        cleanup_socket(sock);
        return -1;
    }

    // Odstanenie koncoveho znaku noveho riadku
    size_t name_len = strlen(file_name);
    if (name_len > 0 && file_name[name_len - 1] == '\n') {
        file_name[name_len - 1] = '\0';
        name_len--;
    }

    // Overenie dlzky nazvu suboru
    if (name_len > (FILE_NAME_BUFFER_SIZE-1)) {
        fprintf(stderr, "Error: File name exceeds maximum length of 239 characters\n");
        cleanup_socket(sock);
        return -1;
    }

    // Premenna pre spravu suborov, NULL znamena ze ziadny subor nie je otvoreny
    FILE *file = fopen(file_name, "rb");  // 'rb' znamena otvorit subor na citanie v binarnom mode
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s' (%s)\n", file_name, strerror(errno));
        cleanup_socket(sock);
        return -1;
    }

    if (send_file_name(sock, file_name) < 0) {
        fprintf(stderr, "Error: Failed to send file name to server (%s)\n", strerror(errno));
        cleanup_socket(sock);
        return -1;
    }

    // KROK 4: Hlavny cyklus prenosu dat
    // - Citanie suboru po blokoch (max TRANSFER_BUFFER_SIZE)
    // - Generovanie noveho nonce pre kazdy blok
    // - Sifrovanie dat pomocou ChaCha20-Poly1305
    // - Odoslanie zasifrovanych dat na server
    uint64_t total_bytes = 0;
    printf("Starting file transfer...\n");

    // Vytvorenie bufferov pre prenos - docasne ulozisko pre data
    uint8_t buffer[TRANSFER_BUFFER_SIZE];        // Buffer pre necifrovane data
    uint8_t ciphertext[TRANSFER_BUFFER_SIZE];    // Buffer pre zasifrovane data
    uint8_t tag[TAG_SIZE];                       // Buffer pre overovaci kod (ako digitalny podpis)

    // Citame subor po kusoch (chunk), pretoze cely subor sa nemusi zmestit do pamate
    // bytes_read obsahuje pocet precitanych bajtov, 0 znamena koniec suboru
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // Pre kazdy blok vygeneruje novy nahodny nonce
        // Nonce musi byt vzdy nove pre kazdy blok dat
        // Ak by sme pouzili rovnake nonce, utocnik by mohol zistit informacie o datach
        generate_random_bytes(nonce, NONCE_SIZE);
        
        // Zasifrovanie dat a vytvorenie autentifikacneho tagu
        // Sifrovanie dat:
        // 1. buffer obsahuje povodne data
        // 2. ciphertext bude obsahovat zasifrovane data
        // 3. tag je kontrolny sucet na overenie, ze data neboli zmenene
        // 4. key je sifrovaci kluc
        // 5. nonce je jednorazove cislo
        crypto_aead_lock(ciphertext, tag, key, nonce, NULL, 0, buffer, bytes_read);

        // Odoslanie zasifrovanych dat serveru
        if (send_chunk_size(sock, bytes_read) < 0 ||
            send_encrypted_chunk(sock, nonce, tag, ciphertext, bytes_read) < 0) {
            fprintf(stderr, "Error: Failed to send encrypted chunk (%s)\n", strerror(errno));
            cleanup_socket(sock);
            return -1;
        }

        total_bytes += bytes_read;
        printf("Sent chunk of %u bytes (total: %llu)\n", 
               (unsigned int)bytes_read, (unsigned long long)total_bytes);
    }

    // KROK 5: Ukoncenie prenosu
    // - Odoslanie signalu konca suboru (chunk_size = 0)
    // - Cakanie na potvrdenie od servera
    // - Cistenie a ukoncenie programu
    printf("Sending end of file marker...\n");
    if (send_chunk_size(sock, 0) < 0) {
        fprintf(stderr, "Error: Failed to send end-of-file marker (%s)\n", strerror(errno));
        cleanup_socket(sock);
        return -1;
    }

    // Cakanie na potvrdenie od servera
    if (wait_for_transfer_ack(sock) < 0) {
        fprintf(stderr, "Error: Failed to receive transfer acknowledgment from server\n");
        cleanup_socket(sock);
        return -1;
    }

    // Sprava pre uzivatela o prijati potvrdenia
    printf("Received acknowledgment from server.\n");

    printf("Success: File transfer completed successfully. Total bytes sent: %llu\n",
           (unsigned long long)total_bytes);

    printf("File transfer completed successfully\n");

    // Upratanie a ukoncenie
    // - zatvorenie suboru
    // - uvolnenie sietovych prostriedkov
    // - navratova hodnota indikuje uspesnost prenosu
    if (file != NULL) {
        fclose(file);
    }
    cleanup_socket(sock);
    cleanup_network();
    return (total_bytes > 0) ? 0 : -1;  // Return success only if we transferred data
}
