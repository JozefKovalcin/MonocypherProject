/********************************************************************************
 * Program:    Server pre zabezpeceny prenos suborov
 * Subor:      server.c
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      2024
 * 
 * Popis: 
 *     Serverova cast aplikacie pre zabezpeceny prenos suborov. Program
 *     implementuje nasledujuce funkcie:
 *     - Desifrovanie dat prichadzajucich od klienta (ChaCha20-Poly1305)
 *     - Overenie integrity prijatych dat pomocou autentifikacneho tagu
 *     - Odvodenie sifrovacieho kluca z hesla (Argon2)
 *     - Zabezpecenu komunikaciu cez TCP protokol
 *     - Podporu pre Windows aj Linux systemy
 * 
 * Zavislosti:
 *     - Monocypher 4.0.2 (implementacia sifrovania)
 *     - Standardne C kniznice
 *     - siete.h (deklaracie sietovych funkcii)
 *     - constants.h (definicie konstant pre program)
 *     - crypto_utils.h (deklaracie kryptografickych funkcii)
 *******************************************************************************/

// Systemove kniznice
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
#include <fcntl.h>        // Linux: Ovladanie vlastnosti suborov a socketov
#include <sys/stat.h>     // Linux: Operacie so subormi a ich atributmi
#include <errno.h>        // Linux: Sprava a hlasenie chyb
#endif

#include "monocypher.h"  // Pre Monocypher kryptograficke funkcie
#include "siete.h"        // Pre sietove funkcie
#include "constants.h"    // Definicie konstant pre program
#include "crypto_utils.h" // Pre kryptograficke funkcie

// Globalne premenne pre kryptograficke operacie
// Tieto premenne sa pouzivaju v celom programe pre desifrovacie operacie
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
    // Inicializacia sietovych prvkov
    // Deskriptory socketov pre server a klienta
    int server_fd, client_socket;
    struct sockaddr_in client_addr;

    // Inicializacia Winsock pre Windows platformu
    initialize_network();

    // KROK 1: Vytvorenie a konfiguracia servera
    // - Vytvori TCP socket
    // - Nastavi potrebne vlastnosti socketu
    // - Naviaze socket na port (definovany v constants.h)
    if ((server_fd = setup_server()) < 0) {
        fprintf(stderr, "Error: Failed to set up server socket (%s)\n", strerror(errno));
        cleanup_network();
        return -1;
    }

    printf("Server is running. Waiting for client connection...\n");  // Add status message

    // KROK 2: Cakanie na pripojenie klienta
    // - Blokujuce cakanie na prichadzajuce spojenie
    // - Vytvorenie noveho socketu pre komunikaciu
    // - Ulozenie informacii o klientovi
    if ((client_socket = accept_client_connection(server_fd, &client_addr)) < 0) {
        fprintf(stderr, "Error: Failed to accept client connection (%s)\n", strerror(errno));
        cleanup_socket(server_fd);
        cleanup_network();
        return -1;
    }

    // KROK 3: Inicializacia zabezpeceneho spojenia
    // - Odoslanie signalu READY klientovi
    // - Prijem kryptografickej soli (32 bajtov)
    // - Kontrola prijatych dat
    if (send_ready_signal(client_socket) < 0 ||
        receive_salt(client_socket, salt) < 0) {
        fprintf(stderr, "Error: Failed during initial handshake - check network connection\n");
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // KROK 4: Priprava sifrovacieho kluca
    // - Nacita heslo od uzivatela (rovnake ako na klientovi)
    // - Pouzije Argon2 na vytvorenie kluca z hesla a soli
    char *password = getpass("Zadajte heslo pre desifrovanie: ");
    if (derive_key_server(password, salt, key, salt) != 0) {
        fprintf(stderr, "Error: Key derivation failed - memory allocation or internal error\n");
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Posle potvrdenie o prijati kluca klientovi
    if (send_key_acknowledgment(client_socket) < 0) {
        fprintf(stderr, "Error: Failed to send key acknowledgment to client (%s)\n", strerror(errno));
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // KROK 5: Priprava na prijem suboru
    // - Vytvorenie noveho nazvu suboru s prefixom 'received_'
    // - Otvorenie suboru pre binarny zapis
    char file_name[FILE_NAME_BUFFER_SIZE];
    if (receive_file_name(client_socket, file_name, sizeof(file_name)) < 0) {
        fprintf(stderr, "Error: Failed to receive file name from client (%s)\n", strerror(errno));
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Spracovanie novo prijateho suboru
    // Vytvori novy nazov suboru pridanim predpony 'received_'
    char new_file_name[NEW_FILE_NAME_BUFFER_SIZE];
    snprintf(new_file_name, sizeof(new_file_name), "received_%s", file_name);

    // Otvorenie noveho suboru pre binarny zapis
    // Kontrola uspesnosti vytvorenia suboru
    FILE *file = fopen(new_file_name, "wb");
    if (!file) {
        fprintf(stderr, "Error: Failed to create file '%s' (%s)\n", new_file_name, strerror(errno));
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Inicializacia premennych pre sledovanie prenosu
    uint64_t total_bytes = 0;        // Celkovy pocet prijatych bajtov
    int transfer_complete = 0;       // Stav prenosu (0 = prebieha, 1 = uspesne dokonceny, -1 = chyba)

    printf("Waiting for file transfer...\n");

    // Buffers pre prenos dat
    // ciphertext: Zasifrovane data z klienta
    // plaintext: Desifrovane data pre zapis
    // tag: Autentifikacny tag pre overenie integrity
    uint8_t ciphertext[TRANSFER_BUFFER_SIZE];  // Buffer pre zasifrovane data
    uint8_t plaintext[TRANSFER_BUFFER_SIZE];   // Buffer pre desifrovane data
    uint8_t tag[TAG_SIZE];                     // Buffer pre autentifikacny tag

    // KROK 6: Hlavny cyklus prijmu dat
    // - Prijem velkosti nasledujuceho bloku
    // - Prijem zasifrovanych dat, nonce a tagu
    // - Desifrovanie pomocou ChaCha20-Poly1305
    // - Overenie integrity pomocou Poly1305
    // - Zapis desifrovanych dat do suboru
    while (!transfer_complete) {
        // Prijatie velkosti nasledujuceho bloku dat
        // chunk_size == 0 znamena koniec suboru
        uint32_t chunk_size;
        if (receive_chunk_size(client_socket, &chunk_size) < 0) {
            fprintf(stderr, "Error: Failed to receive chunk size - connection might be broken\n");
            break;
        }

        if (chunk_size == 0) {  // Koniec suboru
            printf("End of file marker received.\n");
            if (send_transfer_ack(client_socket) == 0) {
                printf("Sent acknowledgment to client\n");
                transfer_complete = 1;
            } else {
                fprintf(stderr, "Error: Failed to send acknowledgment\n");
                transfer_complete = -1;
            }
            break;
        }
        // Kontrola velkosti prijatych dat
        if (chunk_size > TRANSFER_BUFFER_SIZE) {
            fprintf(stderr, "Error: Invalid chunk size received (%u bytes) - exceeds maximum buffer size\n", chunk_size);
            transfer_complete = -1;
            break;
        }

        // Spracovanie prijatych dat
        // 1. Prijme zasifrovane data, nonce a autentifikacny tag
        // 2. Overi integritu dat a desifruje ich
        // 3. Zapise desifrovane data do suboru
        if (receive_encrypted_chunk(client_socket, nonce, tag, ciphertext, chunk_size) < 0) {
            fprintf(stderr, "Error: Failed to receive encrypted data chunk (%s)\n", strerror(errno));
            break;
        }

        // Kontrola integrity a desifrovanie:
        // 1. Overi, ci data neboli zmenene (pomocou tagu)
        // 2. Ak su data v poriadku, desifruje ich
        // 3. Ak boli data zmenene, vrati chybu
        if (crypto_aead_unlock(plaintext, tag, key, nonce, NULL, 0, ciphertext, chunk_size) != 0) {
            fprintf(stderr, "Error: Failed to decrypt chunk - authentication failed or corrupted data\n");
            break;
        }

        if (fwrite(plaintext, 1, chunk_size, file) != chunk_size) {
            fprintf(stderr, "Error: Failed to write to file (%s)\n", strerror(errno));
            break;
        }

        total_bytes += chunk_size;
        printf("Received and wrote chunk of %u bytes (total: %llu)\n", 
               chunk_size, (unsigned long long)total_bytes);

        if (transfer_complete == -1) {
            fprintf(stderr, "Error: File transfer failed - incomplete or corrupted file\n");
            break;
        }
    }
    
    if (transfer_complete == 1) {
        printf("Success: File transfer completed. Total bytes received: %llu\n", 
               (unsigned long long)total_bytes);
    } else {
        fprintf(stderr, "Error: File transfer failed or was interrupted prematurely\n");
    }

    // KROK 7: Ukoncenie a cistenie
    // - Zatvorenie vystupneho suboru
    // - Uvolnenie sietovych prostriedkov
    // - Navrat s kodom podla uspesnosti prenosu
    if (file != NULL) {
        fclose(file);
    }
    cleanup_sockets(client_socket, server_fd);
    cleanup_network();
    return (transfer_complete == 1) ? 0 : -1;
}
