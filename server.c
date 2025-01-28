/********************************************************************************
 * Program:    Server pre zabezpeceny prenos suborov
 * Subor:      server.c
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      2024
 * 
 * Popis: 
 *     Implementacia servera pre zabezpeceny prenos suborov. Program zabezpecuje:
 *     - Vytvorenie TCP servera a prijimanie spojeni
 *     - Bezpecnu vymenu klucov s klientom
 *     - Prijimanie a desifrovanie suborov
 *     - Overovanie integrity prijatych dat
 *     - Synchronizaciu rotacie klucov s klientom
 * 
 * Zavislosti:
 *     - Monocypher 4.0.2 (sifrovacie algoritmy)
 *     - siete.h (sietova komunikacia)
 *     - crypto_utils.h (kryptograficke operacie)
 *     - constants.h (konstanty programu)
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
    int server_fd, client_socket;
    struct sockaddr_in client_addr;

    // Inicializacia Winsock pre Windows platformu
    initialize_network();

    // Vytvorenie a konfiguracia servera
    if ((server_fd = setup_server()) < 0) {
        fprintf(stderr, ERR_SOCKET_SETUP, strerror(errno));
        cleanup_network();
        return -1;
    }

    printf(LOG_SERVER_START);

    if ((client_socket = accept_client_connection(server_fd, &client_addr)) < 0) {
        fprintf(stderr, ERR_CLIENT_ACCEPT, strerror(errno));
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Inicializacia bezpecneho spojenia
    if (send_ready_signal(client_socket) < 0) {
        fprintf(stderr, ERR_HANDSHAKE);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Prijatie soli od klienta
    uint8_t salt[SALT_SIZE];
    if (receive_salt(client_socket, salt) < 0) {
        fprintf(stderr, ERR_SALT_RECEIVE);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Nacitanie hesla od uzivatela a odvodenie hlavneho kluca pomocou Argon2
    // Heslo sa pouzije na generovanie kluca, ktory sa pouzije na sifrovanie dat
    char *password = getpass(PASSWORD_PROMPT_SERVER);
    if (derive_key_server(password, salt, key, salt) != 0) {
        fprintf(stderr, ERR_KEY_DERIVATION);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Premenne pre vymenu klucov
    uint8_t ephemeral_secret[KEY_SIZE]; // Docasny tajny kluc
    uint8_t ephemeral_public[KEY_SIZE]; // Docasny verejny kluc
    uint8_t peer_public[KEY_SIZE]; // Verejny kluc od servera
    uint8_t shared_secret[KEY_SIZE]; // Spolocny tajny kluc
    uint8_t session_key[SESSION_KEY_SIZE]; // Kluc pre danu relaciu
    uint8_t session_nonce[NONCE_SIZE]; // Nonce pre danu relaciu

    // Odoslanie potvrdenia kluca klientovi
    if (send_key_acknowledgment(client_socket) < 0) {
        fprintf(stderr, ERR_KEY_ACK);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Cakanie na inicializaciu relacie
    uint32_t setup_status;
    if (receive_chunk_size_reliable(client_socket, &setup_status) < 0 ||
        setup_status != SESSION_SETUP_START) {
        fprintf(stderr, ERR_SESSION_SETUP);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    printf(LOG_SESSION_START);

    // Generovanie docasneho klucoveho paru (verejny a tajny kluc)
    // Tieto kluce sa pouziju na zabezpecenie forward secrecy
    generate_ephemeral_keypair(ephemeral_public, ephemeral_secret);
    
    // Nastavenie casovaceho limitu pre vymenu klucov
    set_socket_timeout(client_socket, KEY_EXCHANGE_TIMEOUT_MS);
    
    if (send_all(client_socket, ephemeral_public, KEY_SIZE) != KEY_SIZE ||
        recv_all(client_socket, peer_public, KEY_SIZE) != KEY_SIZE) {
        fprintf(stderr, ERR_KEY_EXCHANGE);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Vypocet spolocneho tajneho kluca pomocou Diffie-Hellman
    // Tento kluc sa pouzije na zabezpecenie komunikacie medzi klientom a serverom
    compute_shared_secret(shared_secret, ephemeral_secret, peer_public);
    
    // Prijatie session nonce od klienta
    if (recv_all(client_socket, session_nonce, NONCE_SIZE) != NONCE_SIZE) {
        fprintf(stderr, ERR_SESSION_NONCE);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Nastavenie relacneho kluca
    setup_session(session_key, key, shared_secret, session_nonce);
    
    // Bezpecne vymazanie citlivych dat
    secure_wipe(ephemeral_secret, KEY_SIZE);
    secure_wipe(shared_secret, KEY_SIZE);

    // Potvrdenie nastavenia relacie
    if (send_chunk_size_reliable(client_socket, SESSION_SETUP_DONE) < 0) {
        fprintf(stderr, ERR_SESSION_CONFIRM);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    printf(LOG_SESSION_COMPLETE);

    // Nastavenie casovaceho limitu pre prijem nazvu suboru
    set_socket_timeout(client_socket, WAIT_FILE_NAME); 
    
    char file_name[FILE_NAME_BUFFER_SIZE];
    if (receive_file_name(client_socket, file_name, sizeof(file_name)) < 0) {
        fprintf(stderr, ERR_FILENAME_RECEIVE, strerror(errno));
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Resetovanie casovaceho limitu na mensiu hodnotu pre prenos dat
    set_socket_timeout(client_socket, SOCKET_TIMEOUT_MS);

    // Spracovanie novo prijateho suboru
    // Vytvorenie noveho nazvu suboru pridanim predpony 'received_'
    char new_file_name[NEW_FILE_NAME_BUFFER_SIZE];
    snprintf(new_file_name, sizeof(new_file_name), "%s%s", FILE_PREFIX, file_name);

    // Otvorenie noveho suboru pre binarny zapis
    // Kontrola uspesnosti vytvorenia suboru
    FILE *file = fopen(new_file_name, FILE_MODE_WRITE);
    if (!file) {
        fprintf(stderr, ERR_FILE_CREATE, new_file_name, strerror(errno));
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Inicializacia premennych pre sledovanie prenosu
    uint64_t total_bytes = 0;        // Celkovy pocet prijatych bajtov
    int transfer_complete = 0;       // Stav prenosu (0 = prebieha, 1 = uspesne dokonceny, -1 = chyba)

    printf(LOG_TRANSFER_START);

    // Buffers pre prenos dat
    // ciphertext: Zasifrovane data z klienta
    // plaintext: Desifrovane data pre zapis
    // tag: Autentifikacny tag pre overenie integrity
    uint8_t ciphertext[TRANSFER_BUFFER_SIZE];  // Buffer pre zasifrovane data
    uint8_t plaintext[TRANSFER_BUFFER_SIZE];   // Buffer pre desifrovane data
    uint8_t tag[TAG_SIZE];                     // Buffer pre autentifikacny tag

    // Prenos suboru s rotaciou klucov
    uint64_t block_count = 0;
    uint8_t buffer[TRANSFER_BUFFER_SIZE];
    uint8_t previous_key[KEY_SIZE];

    // Premenna pre sledovanie postupu
    uint64_t last_progress_update = 0;

    // Hlavny cyklus prenosu dat
    while (!transfer_complete) {
        uint32_t chunk_size;
        if (receive_chunk_size_reliable(client_socket, &chunk_size) < 0) {
            fprintf(stderr, ERR_CHUNK_SIZE);
            transfer_complete = -1;
            break;
        }

        // Spracovanie markera rotacie kluca
        if (chunk_size == KEY_ROTATION_MARKER) {
            printf(MSG_KEY_ROTATION, (unsigned long long)block_count);
            
            if (send_chunk_size_reliable(client_socket, KEY_ROTATION_ACK) < 0) {
                fprintf(stderr, ERR_KEY_ROTATION_ACK);
                transfer_complete = -1;
                break;
            }

            // Validacia rotacie kluca
            uint32_t signal;
            if (receive_chunk_size_reliable(client_socket, &signal) < 0 || 
                signal != KEY_ROTATION_VALIDATE) {
                fprintf(stderr, ERR_KEY_VALIDATE_SIGNAL);
                transfer_complete = -1;
                break;
            }

            memcpy(previous_key, session_key, KEY_SIZE);
            rotate_key(session_key, previous_key);

            // Kontrola validacie kluca
            uint8_t client_validation[VALIDATION_SIZE];
            uint8_t our_validation[VALIDATION_SIZE];
            
            if (recv_all(client_socket, client_validation, VALIDATION_SIZE) != VALIDATION_SIZE) {
                fprintf(stderr, ERR_KEY_VALIDATE_RECEIVE);
                transfer_complete = -1;
                break;
            }
            
            generate_key_validation(our_validation, session_key);
            if (memcmp(client_validation, our_validation, VALIDATION_SIZE) != 0) {
                fprintf(stderr, ERR_KEY_VALIDATE_MISMATCH);
                transfer_complete = -1;
                break;
            }

            secure_wipe(previous_key, KEY_SIZE);
            
            if (send_chunk_size_reliable(client_socket, KEY_ROTATION_READY) < 0) {
                fprintf(stderr, ERR_KEY_ROTATION_READY);
                transfer_complete = -1;
                break;
            }

            
            wait();
            continue;
        }

        // Spracovanie markera konca suboru (EOF)
        if (chunk_size == 0) {
            printf("\n");
            printf(LOG_TRANSFER_COMPLETE);
            if (send_transfer_ack(client_socket) == 0) {
                transfer_complete = 1;
            }
            break;
        }

        // Spracovanie bloku dat a aktualizacia postupu
        if (receive_encrypted_chunk(client_socket, nonce, tag, ciphertext, chunk_size) < 0 ||
            crypto_aead_unlock(plaintext, tag, session_key, nonce, NULL, 0, ciphertext, chunk_size) != 0 ||
            fwrite(plaintext, 1, chunk_size, file) != chunk_size) {
            fprintf(stderr, ERR_CHUNK_PROCESS);
            break;
        }

        total_bytes += chunk_size;
        block_count++;

        // Aktualizacia postupu 
        if (total_bytes - last_progress_update >= PROGRESS_UPDATE_INTERVAL) {
            printf(LOG_PROGRESS_FORMAT, "Received", (float)total_bytes / PROGRESS_UPDATE_INTERVAL);
            fflush(stdout);
            last_progress_update = total_bytes;
        }
    }

    // Finalna sprava o stave prenosu
    if (transfer_complete == 1) {
        printf(LOG_SUCCESS_FORMAT, "received", (float)total_bytes / PROGRESS_UPDATE_INTERVAL);
    } else {
        fprintf(stderr, ERR_TRANSFER_INTERRUPTED);
    }

    // Ukoncenie a cistenie
    // - Zatvorenie vystupneho suboru
    // - Uvolnenie sietovych prostriedkov
    // - Navrat s kodom podla uspesnosti prenosu
    if (file != NULL) {
        fclose(file);
    }
    cleanup_sockets(client_socket, server_fd);
    cleanup_network();

    // Bezpecne vymazanie citlivych dat
    secure_wipe(key, KEY_SIZE);
    secure_wipe(session_key, KEY_SIZE);
    secure_wipe(buffer, TRANSFER_BUFFER_SIZE);
    secure_wipe(plaintext, TRANSFER_BUFFER_SIZE);
    secure_wipe(tag, TAG_SIZE);

    return (transfer_complete == 1) ? 0 : -1;
}
