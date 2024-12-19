/********************************************************************************
 * Program:    Konstanty pre zabezpeceny prenos suborov
 * Subor:      constants.h
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * 
 * Popis: 
 *     Definicie konstant pouzivanych v celom programe:
 *     - Sietove nastavenia (porty, timeouty)
 *     - Velkosti bufferov pre data
 *     - Kryptograficke parametre
 *     - Konfiguracia Argon2
 *******************************************************************************/

#ifndef CONSTANTS_H
#define CONSTANTS_H

// Sietove konstanty
// Zakladne nastavenia pre sietovu komunikaciu
#define PORT 8080                    // Standardny port pre aplikaciu (nezabezpeceny port > 1024)
#define MAX_PENDING_CONNECTIONS 3    // Maximalne 3 cakajuce spojenia v rade
#define TIMEOUT_SEC 5               // Timeout pre operacie v sekundach

// Casove konstanty
// Nastavenia cakacich intervalov pre rozne operacie
#define SOCKET_SHUTDOWN_DELAY_MS 1000    // Cas cakania po ukonceni socketu v milisekundach
#define WAIT_DELAY_MS 250               // Cas cakania medzi opakovanymi pokusmi v milisekundach
#define SOCKET_TIMEOUT_MS 10000         // Dlzka timeoutu pre socket v milisekundach

// Konstanty pre klienta
// Nastavenia pre opakovane pokusy a potvrdenia
#define MAX_RETRIES 3               // Pocet pokusov pre potvrdenia
#define RETRY_DELAY_MS 1000         // Oneskorenie medzi pokusmi v milisekundach
#define ACK_SIZE 4                  // Velkost potvrdzujucej spravy (TACK)

// Kryptograficke konstanty
// Velkosti klucov a parametrov pre sifrovanie
#define KEY_SIZE 32                 // Dlzka kluca (256 bitov, odporucana pre ChaCha20)
#define NONCE_SIZE 24              // Dlzka nonce (192 bitov, odporucana pre ChaCha20)
#define TAG_SIZE 16                // Dlzka autentifikacneho tagu (128 bitov, Poly1305)
#define SALT_SIZE 16               // Dlzka soli (128 bitov, minimum pre Argon2)
#define WORK_AREA_SIZE (1 << 16)   // Velkost pracovnej oblasti (64 MB)

// Velkosti bufferov
// Definicie velkosti roznych datovych struktur
#define PASSWORD_BUFFER_SIZE 128    // Maximum pre dlzku hesla
#define FILE_NAME_BUFFER_SIZE 240   // Maximum pre nazov suboru
#define NEW_FILE_NAME_BUFFER_SIZE 256  // Maximum pre novy nazov suboru
#define TRANSFER_BUFFER_SIZE 4096   // Velkost bloku pre prenos (4 KB, kompromis medzi rychlostou a pamatou)
#define SIGNAL_SIZE 5  // Velkost pre signalizacne spravy (READY, KEYOK)

// Konfiguracia Argon2
// Parametre pre derivaciu kluca
#define ARGON2_MEMORY_BLOCKS 65536  // Pamatove bloky (64 MB)
#define ARGON2_ITERATIONS 3         // Pocet iteracii algoritmu
#define ARGON2_LANES 1              // Pocet paralelnych vlakien

#endif // CONSTANTS_H