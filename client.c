/********************************************************************************
 * Program:    Klient pre zabezpeceny prenos suborov
 * Subor:      client.c
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      2024
 * 
 * Popis: 
 *     Implementacia klienta pre zabezpeceny prenos suborov. Program zabezpecuje:
 *     - Vytvorenie TCP spojenia so serverom
 *     - Generovanie a odoslanie kryptografickych materialov
 *     - Sifrovanie a odosielanie suborov
 *     - Automaticku rotaciu klucov pocas prenosu
 *     - Forward secrecy pomocou ephemeral klucov
 * 
 * Zavislosti:
 *     - Monocypher 4.0.2 (sifrovacie algoritmy)
 *     - siete.h (sietova komunikacia)
 *     - crypto_utils.h (kryptograficke operacie)
 *     - constants.h (konstanty programu)
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
uint8_t salt[SALT_SIZE];        // Sol pre odvodenie kluca

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
    if ((sock = connect_to_server(DEFAULT_SERVER_ADDRESS)) < 0) {
        fprintf(stderr, ERR_SOCKET_SETUP, strerror(errno));
        return -1;
    }

    // Pocka na signal pripravenosti od servera
    // Zabezpeci synchronizaciu medzi klientom a serverom
    if (wait_for_ready(sock) < 0) {
        fprintf(stderr, ERR_HANDSHAKE);
        cleanup_socket(sock);
        return -1;
    }

    // KROK 2: Priprava kryptografickych materialov
    // - Generovanie nahodnej soli (32 bajtov)
    // - Nacitanie hesla od uzivatela
    // - Odvodenie kluca pomocou Argon2
    // - Odoslanie soli serveru

    // Nacitanie hesla od uzivatela a odvodenie hlavneho kluca pomocou Argon2
    // Heslo sa pouzije na generovanie kluca, ktory sa pouzije na sifrovanie dat
    char *password = getpass(PASSWORD_PROMPT);
    if (derive_key_client(password, key, salt) != 0) {
        fprintf(stderr, ERR_KEY_DERIVATION);
        cleanup_socket(sock);
        return -1;
    }

    // Posle salt serveru, aby mohol odvodi rovnaky kluc
    if (send_salt_to_server(sock, salt) < 0) {
        fprintf(stderr, ERR_SALT_RECEIVE);
        cleanup_socket(sock);
        return -1;
    }

    // Cakanie na 'KEYOK' potvrdenie od servera
    if (wait_for_key_acknowledgment(sock) < 0) {
        fprintf(stderr, ERR_KEY_ACK);
        cleanup_socket(sock);
        return -1;
    }

    // Premenne pre vymenu klucov
    uint8_t ephemeral_secret[KEY_SIZE]; // Docasny tajny kluc
    uint8_t ephemeral_public[KEY_SIZE]; // Docasny verejny kluc
    uint8_t peer_public[KEY_SIZE]; // Verejny kluc od servera
    uint8_t shared_secret[KEY_SIZE]; // Spolocny tajny kluc
    uint8_t session_key[SESSION_KEY_SIZE]; // Kluc pre danu relaciu
    uint8_t session_nonce[NONCE_SIZE]; // Nonce pre danu relaciu
    
    printf(LOG_SESSION_START);

    // Inicializacia relacie s serverom
    if (send_chunk_size_reliable(sock, SESSION_SETUP_START) < 0) {
        fprintf(stderr, ERR_SESSION_SETUP);
        cleanup_socket(sock);
        return -1;
    }

    // Generovanie docasneho klucoveho paru (verejny a tajny kluc)
    // Tieto kluce sa pouziju na zabezpecenie forward secrecy
    generate_ephemeral_keypair(ephemeral_public, ephemeral_secret);
    
    // Nastavenie casovaceho limitu pre vymenu klucov
    set_socket_timeout(sock, KEY_EXCHANGE_TIMEOUT_MS);
    
    if (recv_all(sock, peer_public, KEY_SIZE) != KEY_SIZE ||
        send_all(sock, ephemeral_public, KEY_SIZE) != KEY_SIZE) {
        fprintf(stderr, ERR_KEY_EXCHANGE);
        cleanup_socket(sock);
        return -1;
    }
    
    // Vypocet spolocneho tajneho kluca pomocou Diffie-Hellman
    // Tento kluc sa pouzije na zabezpecenie komunikacie medzi klientom a serverom
    compute_shared_secret(shared_secret, ephemeral_secret, peer_public);
    generate_random_bytes(session_nonce, NONCE_SIZE);
    
    // Odoslanie session nonce
    if (send_all(sock, session_nonce, NONCE_SIZE) != NONCE_SIZE) {
        fprintf(stderr, ERR_SESSION_NONCE);
        cleanup_socket(sock);
        return -1;
    }
    
    // Nastavenie relacneho kluca
    setup_session(session_key, key, shared_secret, session_nonce);
    
    // Bezpecne vymazanie citlivych dat
    secure_wipe(ephemeral_secret, KEY_SIZE);
    secure_wipe(shared_secret, KEY_SIZE);
    
    // Cakanie na potvrdenie relacie
    uint32_t setup_status;
    if (receive_chunk_size_reliable(sock, &setup_status) < 0 ||
        setup_status != SESSION_SETUP_DONE) {
        fprintf(stderr, ERR_SESSION_CONFIRM);
        cleanup_socket(sock);
        return -1;
    }

    printf(LOG_SESSION_COMPLETE);

    // KROK 3: Spracovanie vstupneho suboru
    // - Zobrazenie dostupnych suborov
    // - Nacitanie nazvu suboru od uzivatela
    // - Kontrola existencie a pristupnosti suboru
    printf(MSG_FILE_LIST);
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
    printf(MSG_ENTER_FILENAME);
    char file_name[FILE_NAME_BUFFER_SIZE];
    if (fgets(file_name, sizeof(file_name), stdin) == NULL) {
        fprintf(stderr, ERR_FILENAME_READ);
        cleanup_socket(sock);
        return -1;
    }

    // Odstranenie koncoveho znaku noveho riadku
    size_t name_len = strlen(file_name);
    if (name_len > 0 && file_name[name_len - 1] == '\n') {
        file_name[name_len - 1] = '\0';
        name_len--;
    }

    // Overenie dlzky nazvu suboru
    if (name_len > (FILE_NAME_BUFFER_SIZE-1)) {
        fprintf(stderr, ERR_FILENAME_LENGTH);
        cleanup_socket(sock);
        return -1;
    }

    // Premenna pre spravu suborov, NULL znamena ze ziadny subor nie je otvoreny
    FILE *file = fopen(file_name, FILE_MODE_READ);  // 'rb' znamena otvorit subor na citanie v binarnom mode
    if (!file) {
        fprintf(stderr, ERR_FILE_OPEN, file_name, strerror(errno));
        cleanup_socket(sock);
        return -1;
    }

    if (send_file_name(sock, file_name) < 0) {
        fprintf(stderr, ERR_FILENAME_SEND, strerror(errno));
        cleanup_socket(sock);
        return -1;
    }

    // KROK 4: Hlavny cyklus prenosu dat
    // - Citanie suboru po blokoch (max TRANSFER_BUFFER_SIZE)
    // - Generovanie noveho nonce pre kazdy blok
    // - Sifrovanie dat pomocou ChaCha20-Poly1305
    // - Odoslanie zasifrovanych dat na server
    uint64_t total_bytes = 0;
    uint64_t block_count = 0;
    printf(LOG_TRANSFER_START);

    // Vytvorenie bufferov pre prenos - docasne ulozisko pre data
    uint8_t buffer[TRANSFER_BUFFER_SIZE];        // Buffer pre necifrovane data
    uint8_t ciphertext[TRANSFER_BUFFER_SIZE];    // Buffer pre zasifrovane data
    uint8_t tag[TAG_SIZE];                       // Buffer pre overovaci kod (ako digitalny podpis)
    
    // Premenna pre sledovanie progresu
    uint64_t last_progress_update = 0;
    
    // Citanie suboru po blokoch (chunk) a ich sifrovanie
    // Kazdy blok je sifrovany samostatne, aby sa zabranilo preteceniu pamate pri velkych suboroch
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, TRANSFER_BUFFER_SIZE, file)) > 0) {
        // Rotacia kluca po kazdych KEY_ROTATION_BLOCKS blokoch
        // Rotacia kluca zvysuje bezpecnost komunikacie tym, ze obmedzuje mnozstvo dat sifrovanych jednym klucom
        if (block_count > 0 && block_count % KEY_ROTATION_BLOCKS == 0) {
            printf(MSG_KEY_ROTATION, (unsigned long long)block_count);
            
            // Signalizacia rotacie kluca serveru
            if (send_chunk_size_reliable(sock, KEY_ROTATION_MARKER) < 0) {
                fprintf(stderr, ERR_KEY_ROTATION_ACK);
                break;
            }

            // Cakanie na potvrdenie od servera
            uint32_t ack;
            if (receive_chunk_size_reliable(sock, &ack) < 0 || ack != KEY_ROTATION_ACK) {
                fprintf(stderr, ERR_KEY_ROTATION_ACK);
                break;
            }

            // Odoslanie validacneho signalu
            if (send_chunk_size_reliable(sock, KEY_ROTATION_VALIDATE) < 0) {
                fprintf(stderr, ERR_KEY_VALIDATE_SIGNAL);
                break;
            }

            // Vykonanie rotacie kluca
            uint8_t previous_key[KEY_SIZE];
            memcpy(previous_key, session_key, KEY_SIZE);
            rotate_key(session_key, previous_key);

            // Generovanie a odoslanie validacie kluca
            uint8_t validation[VALIDATION_SIZE];
            generate_key_validation(validation, session_key);
            if (send_all(sock, validation, VALIDATION_SIZE) != VALIDATION_SIZE) {
                fprintf(stderr, ERR_KEY_VALIDATE_SIGNAL);
                break;
            }

            // Cakanie na signal pripravenosti od servera
            if (receive_chunk_size_reliable(sock, &ack) < 0 || ack != KEY_ROTATION_READY) {
                fprintf(stderr, ERR_KEY_ROTATION_READY);
                break;
            }

            secure_wipe(previous_key, KEY_SIZE);
            wait();
        }

        // Spracovanie bloku s aktualnym klucom
        generate_random_bytes(nonce, NONCE_SIZE);

        // Sifrovanie dat pomocou algoritmu ChaCha20-Poly1305
        // ciphertext: Zasifrovane data
        // tag: Overovaci kod pre integritu dat
        // session_key: Kluc pouzity na sifrovanie
        // nonce: Jednorazova hodnota pre zabezpecenie jedinecnosti sifrovania
        crypto_aead_lock(ciphertext, tag, session_key, nonce, NULL, 0, buffer, bytes_read);

        // Odoslanie velkosti bloku a zasifrovanych dat
        int retry_count = MAX_RETRIES;
        while (retry_count > 0) {
            if (send_chunk_size_reliable(sock, (uint32_t)bytes_read) == 0 &&
                send_encrypted_chunk(sock, nonce, tag, ciphertext, bytes_read) == 0) {
                break;  // Uspesne odoslanie
            }
            retry_count--;
            if (retry_count > 0) {
                fprintf(stderr, MSG_RETRY_FAILED, retry_count);
                usleep(RETRY_DELAY_MS * 1000);
            }
        }

        // Ak sa nepodari odoslat blok dat po maximalnom pocte pokusov, program sa ukonci
        if (retry_count == 0) {
            fprintf(stderr, MSG_CHUNK_FAILED);
            break;
        }

        total_bytes += bytes_read;
        block_count++;

        // Vypis progresu v intervaloch
        if (total_bytes - last_progress_update >= PROGRESS_UPDATE_INTERVAL) {
            printf(LOG_PROGRESS_FORMAT, "Sent", (float)total_bytes / PROGRESS_UPDATE_INTERVAL);
            fflush(stdout);
            last_progress_update = total_bytes;
        }
    }
    printf("\n"); // Novy riadok po vypise progresu

    // Odoslanie EOF markera a upratanie
    if (send_chunk_size_reliable(sock, 0) < 0) {
        fprintf(stderr, MSG_EOF_FAILED);
    }

    printf(LOG_TRANSFER_COMPLETE);
   

    // Upratanie a ukoncenie
    // Zatvorenie suboru
    // Uvolnenie sietovych prostriedkov
    // Navratova hodnota indikuje uspesnost prenosu

    // Sprava pre uzivatela o prijati potvrdenia
    printf(MSG_ACK_RECEIVED);
    printf(LOG_SUCCESS_FORMAT, "sent", (float)total_bytes / PROGRESS_UPDATE_INTERVAL);
 
    if (file != NULL) {
        fclose(file);
    }

    // Uvolnenie sietovych prostriedkov
    cleanup_socket(sock);
    cleanup_network();

    // Bezpecne vymazanie citlivych dat z pamate
    // Zabranuje utoku typu "memory dump", kedy by utocnik mohol ziskat citlive informacie z pamate
    secure_wipe(key, KEY_SIZE);
    secure_wipe(session_key, KEY_SIZE);
    secure_wipe(buffer, TRANSFER_BUFFER_SIZE);
    secure_wipe(ciphertext, TRANSFER_BUFFER_SIZE);
    secure_wipe(tag, TAG_SIZE);

    return (total_bytes > 0) ? 0 : -1; 
}
