/********************************************************************************
 * Program:    Implementácia kryptografických utilít pre zabezpečený prenos
 * Subor:      crypto_utils.c
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      2024
 * 
 * Popis: 
 *     Implementuje kryptografické funkcie pre zabezpečený prenos súborov:
 *     - Generovanie náhodných čísel s využitím systémových funkcií
 *     - Deriváciu kľúča z hesla pomocou Argon2
 *     - Pomocné funkcie pre výpis a správu kryptografických dát
 * 
 * Zavislosti:
 *     - Monocypher 4.0.2 (implementacia sifrovania)
 *     - Standardné C knižnice
 *     - crypto_utils.h (deklaracie kryptografickych funkcii)
 *     - constants.h (definicie konstant pre program)
 *******************************************************************************/

// Systemove kniznice
#include <stdio.h>        // Kniznica pre standardny vstup a vystup (nacitanie zo suborov, vypis na obrazovku)
#include <stdlib.h>       // Kniznica pre vseobecne funkcie (sprava pamate, konverzie, nahodne cisla)
#include <string.h>       // Kniznica pre pracu s retazcami (kopirovanie, porovnavanie, spajanie)

#ifdef _WIN32
#include <winsock2.h>     // Windows: Zakladna sietova kniznica
#include <bcrypt.h>       // Windows: Kryptograficke funkcie
#else
#include <sys/stat.h>     // Linux: Operacie so subormi a ich atributmi
#endif

#include "crypto_utils.h" // Pre kryptograficke funkcie

// Pomocna funkcia pre vypis kryptografickych dat
// Pouziva sa pri ladeni a kontrole
void print_hex(const char *label, uint8_t *data, int len) {
    // Kazdy bajt je zobrazeny ako dve hexadecimalne cislice
    printf("%s", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);  // %02x zobrazi cislo ako 2 hexadecimalne znaky s nulou na zaciatku
    }
    printf("\n");
}

// Generovanie kryptograficky bezpecnych nahodnych cisel
// Pouziva systemove generatory (BCrypt na Windows, getrandom na Linuxe)
void generate_random_bytes(uint8_t *buffer, size_t size) {
#ifdef __linux__
    if (getrandom(buffer, size, 0) == -1) {
        fprintf(stderr, "Error: Failed to generate random bytes (%s)\n", strerror(errno));
        exit(1);
    }
#elif defined(_WIN32)
    if (BCryptGenRandom(NULL, buffer, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        fprintf(stderr, "Error: Failed to generate random bytes (BCrypt error)\n");
        exit(1);
    }
#else
    #error "Unsupported platform for random number generation"
#endif
}

// Interna implementacia derivacie kluca
// Zdielana medzi klientom a serverom
// Parametre:
//   - password: heslo od uzivatela
//   - salt_input: existujuca sol (server) alebo NULL (klient)
//   - key: vystupny buffer pre kluc
//   - salt: vystupny buffer pre sol
//   - generate_salt: true pre klienta, false pre server
static int derive_key_internal(const char *password, const uint8_t *salt_input, 
                             uint8_t *key, uint8_t *salt, int generate_salt) {
    // Kontrola ci mame vsetky potrebne vstupy
    // Ak chyba heslo, kluc alebo sol, funkcia nemoze pokracovat
    if (!password || !key || !salt) {
        fprintf(stderr, "Error: Invalid parameters for key derivation\n");
        return -1;
    }

    // Bud vytvorime novu sol (pre klienta) alebo pouzijeme existujucu (pre server)
    // Sol pre heslo - robi ho tazsie uhadnutelnym
    if (generate_salt) {
        generate_random_bytes(salt, SALT_SIZE);  // Generujeme novu nahodnu sol
    } else if (salt_input) {
        memcpy(salt, salt_input, SALT_SIZE);    // Pouzijeme existujucu sol
    } else {
        return -1;  // Nemame ziadnu sol, nemoze pokracovat
    }

    // Argon2 je funkcia na hashovanie hesiel, ktora:
    // - Potrebuje vela pamate (stazuje pouzitie specializovaneho hardveru na lamanie hesiel)
    // - Je pomala (chrani proti uhadnutiu hesla skusanim)
    // - Umoznuje paralelne spracovanie (moznost nastavit rychlost podla potreby)
    crypto_argon2_config config = {
        .algorithm = CRYPTO_ARGON2_I,           // Vyberie verziu algoritmu (I = Argon2i, D = Argon2d)
        .nb_blocks = ARGON2_MEMORY_BLOCKS,      // Kolko pamate sa pouzije (viac = bezpecnejsie)
        .nb_passes = ARGON2_ITERATIONS,         // Kolkokrat sa data prepocitaju (viac = bezpecnejsie)
        .nb_lanes = ARGON2_LANES               // Kolko jadier procesora sa moze vyuzit
    };
    
    crypto_argon2_inputs inputs = {
        .pass = (const uint8_t *)password,
        .pass_size = strlen(password),         // Dlzka hesla v bajtoch
        .salt = salt,
        .salt_size = SALT_SIZE                // Velkost soli (16 bajtov)
    };

    void *work_area = malloc(config.nb_blocks * 1024);    // Alokovanie pracovnej pamate (65536 * 1024 = 64 MB)
    if (!work_area) {
        fprintf(stderr, "Error: Failed to allocate memory for key derivation\n");
        return -1;
    }

    crypto_argon2(key, KEY_SIZE, work_area, config, inputs, crypto_argon2_no_extras);
    
    // Po dokonceni vymazeme heslo z pamate
    // Zabranuje to jeho odcitaniu z pamate po ukonceni programu
    crypto_wipe((uint8_t *)password, strlen(password));    // Prepise pamat nulami
    
    free(work_area);

    print_hex(generate_salt ? "Generated salt: " : "Using salt: ", salt, SALT_SIZE);
    print_hex("Derived key: ", key, KEY_SIZE);

    return 0;
}

// Serverova implementacia derivacie kluca
// Pouziva prijatu sol od klienta
int derive_key_server(const char *password, const uint8_t *received_salt, 
                     uint8_t *key, uint8_t *salt) {
    return derive_key_internal(password, received_salt, key, salt, 0);
}

// Klientska implementacia derivacie kluca
// Generuje novu sol a odvodi kluc
int derive_key_client(const char *password, uint8_t *key, uint8_t *salt) {
    return derive_key_internal(password, NULL, key, salt, 1);
}