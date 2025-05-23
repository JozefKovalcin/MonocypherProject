/********************************************************************************
 * Program:    Kryptograficke nastroje pre zabezpeceny prenos
 * Subor:      crypto_utils.c
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.1
 * Datum:      11-03-2025
 *
 * Popis:
 *     Hlavickovy subor pre kryptograficke operacie:
 *     - Bezpecne generovanie nahodnych cisel pre nonce a salt
 *     - Bezpecne odvodenie klucov pomocou Argon2
 *     - Rotacia a validacia klucov
 *     - Ephemeral kryptografia pre forward secrecy pomocou X25519
 *     - Vytvaranie a sprava relacii
 *
 * Zavislosti:
 *     - Monocypher 4.0.2 (sifrovacie algoritmy)
 *     - crypto_utils.h (deklaracie funkcii)
 *     - constants.h (konstanty programu)
 *     - platform.h (platform-specificke funkcie)
 *******************************************************************************/

// Systemove kniznice
#include <stdio.h>  // Kniznica pre standardny vstup a vystup (nacitanie zo suborov, vypis na obrazovku)
#include <stdlib.h> // Kniznica pre vseobecne funkcie (sprava pamate, konverzie, nahodne cisla)
#include <string.h> // Kniznica pre pracu s retazcami (kopirovanie, porovnavanie, spajanie)

#include "crypto_utils.h" // Pre kryptograficke funkcie
#include "constants.h"    // Add this include for constants
#include "platform.h"     // Pre funkcie specificke pre operacny system

// Pomocna funkcia pre vypis kryptografickych dat
// Pouziva sa pri ladeni a kontrole
void print_hex(const char *label, uint8_t *data, int len)
{
    // Kazdy bajt je zobrazeny ako dve hexadecimalne cislice
    printf("%s", label);
    for (int i = 0; i < len; i++)
    {
        printf("%02x", data[i]); // %02x zobrazi cislo ako 2 hexadecimalne znaky s nulou na zaciatku
    }
    printf("\n");
}

// Generovanie kryptograficky bezpecnych nahodnych cisel
// Pouziva systemove generatory (BCrypt na Windows, getrandom na Linuxe)
void generate_random_bytes(uint8_t *buffer, size_t size)
{
    if (platform_generate_random_bytes(buffer, size) != 0)
    {
        exit(1); // Error pri generovani nahodnych cisel
    }
}

// Interna implementacia odvodenia kluca
// Zdielana medzi klientom a serverom
// Parametre:
//   - password: heslo od uzivatela
//   - salt_input: existujuca sol (server) alebo NULL (klient)
//   - key: vystupny buffer pre kluc
//   - salt: vystupny buffer pre sol
//   - generate_salt: true pre klienta, false pre server
static int derive_key_internal(const char *password, const uint8_t *salt_input,
                               uint8_t *key, uint8_t *salt, int generate_salt)
{
    // Kontrola ci mame vsetky potrebne vstupy
    // Ak chyba heslo, kluc alebo sol, funkcia nemoze pokracovat
    if (!password || !key || !salt)
    {
        fprintf(stderr, ERR_KEY_DERIVE_PARAMS);
        return -1;
    }

    // Bud vytvorime novu sol (pre klienta) alebo pouzijeme existujucu (pre server)
    // Sol pre heslo - robi ho tazsie uhadnutelnym
    if (generate_salt)
    {
        generate_random_bytes(salt, SALT_SIZE); // Generujeme novu nahodnu sol
    }
    else if (salt_input)
    {
        memcpy(salt, salt_input, SALT_SIZE); // Pouzijeme existujucu sol
    }
    else
    {
        return -1; // Nemame ziadnu sol, nemoze pokracovat
    }

    // Argon2 je funkcia na hashovanie hesiel, ktora:
    // - Potrebuje vela pamate (stazuje pouzitie specializovaneho hardveru na lamanie hesiel)
    // - Je pomala (chrani proti uhadnutiu hesla skusanim)
    // - Umoznuje paralelne spracovanie (moznost nastavit rychlost podla potreby)
    crypto_argon2_config config = {
        .algorithm = CRYPTO_ARGON2_I,      // Vyberie verziu algoritmu (I = Argon2i, D = Argon2d)
        .nb_blocks = ARGON2_MEMORY_BLOCKS, // Kolko pamate sa pouzije (viac = bezpecnejsie)
        .nb_passes = ARGON2_ITERATIONS,    // Kolkokrat sa data prepocitaju (viac = bezpecnejsie)
        .nb_lanes = ARGON2_LANES           // Kolko jadier procesora sa moze vyuzit
    };

    crypto_argon2_inputs inputs = {
        .pass = (const uint8_t *)password,
        .pass_size = strlen(password), // Dlzka hesla v bajtoch
        .salt = salt,
        .salt_size = SALT_SIZE // Velkost soli (16 bajtov)
    };

    void *work_area = malloc(config.nb_blocks * 1024); // Alokovanie pracovnej pamate (65536 * 1024 = 64 MB)
    if (!work_area)
    {
        fprintf(stderr, ERR_KEY_DERIVE_MEMORY);
        return -1;
    }

    crypto_argon2(key, KEY_SIZE, work_area, config, inputs, crypto_argon2_no_extras);

    // Po dokonceni vymazeme heslo z pamate
    // Zabranuje to jeho odcitaniu z pamate po ukonceni programu
    crypto_wipe((uint8_t *)password, strlen(password)); // Prepise pamat nulami

    free(work_area);

    print_hex(generate_salt ? "Generated salt: " : "Using salt: ", salt, SALT_SIZE);
    print_hex("Derived key: ", key, KEY_SIZE);

    return 0;
}

// Serverova implementacia odvodenia kluca
// Pouziva prijatu sol od klienta
int derive_key_server(const char *password, const uint8_t *received_salt,
                      uint8_t *key, uint8_t *salt)
{
    return derive_key_internal(password, received_salt, key, salt, 0);
}

// Klientska implementacia odvodenia kluca
// Generuje novu sol a odvodi kluc
int derive_key_client(const char *password, uint8_t *key, uint8_t *salt)
{
    return derive_key_internal(password, NULL, key, salt, 1);
}

// Rotacia aktualneho kluca pre vytvorenie noveho
// Pouziva sa na pravidelnu obmenu klucov pre lepsiu bezpecnost
void rotate_key(uint8_t *current_key, const uint8_t *previous_key, const uint8_t *nonce)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, KEY_SIZE);
    crypto_blake2b_update(&ctx, previous_key, KEY_SIZE);
    crypto_blake2b_update(&ctx, nonce, NONCE_SIZE);
    crypto_blake2b_final(&ctx, current_key);

    // Bezpecne vymazanie citlivych dat z pamate
    crypto_wipe(&ctx, sizeof(ctx));
}

// Bezpecne vymazanie citlivych dat z pamate
// Volatile zabranuje optimalizatoru odstranit mazanie
void secure_wipe(void *data, size_t size)
{
    volatile uint8_t *p = (volatile uint8_t *)data;
    while (size--)
    {
        *p++ = 0;
    }
}

// Vytvorenie validacneho kodu pre overenie spravnosti kluca
// Pouziva sa na kontrolu ci obe strany maju rovnaky kluc
void generate_key_validation(uint8_t *validation, const uint8_t *key)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, VALIDATION_SIZE); // Vzdy pouzijeme 16 bajtov pre validaciu
    crypto_blake2b_update(&ctx, key, KEY_SIZE);
    crypto_blake2b_final(&ctx, validation);
    crypto_wipe(&ctx, sizeof(ctx));
}

// Generovanie docasneho paru klucov pre Diffie-Hellman vymenu
// Zabezpecuje forward secrecy - aj pri kompromitacii dlhodobeho kluca su predchadzajuce spravy chranene
void generate_ephemeral_keypair(uint8_t public_key[KEY_SIZE], uint8_t secret_key[KEY_SIZE])
{
    generate_random_bytes(secret_key, KEY_SIZE);
    crypto_x25519_public_key(public_key, secret_key);
}

// Vypocet zdielaneho tajomstva pomocou Diffie-Hellman vymeny
// Kombinuje nas sukromny kluc s verejnym klucom protistrany
void compute_shared_secret(uint8_t shared_secret[KEY_SIZE],
                           const uint8_t secret_key[KEY_SIZE],
                           const uint8_t peer_public[KEY_SIZE])
{
    crypto_x25519(shared_secret, secret_key, peer_public);
}

// Vytvorenie relacie kombinaciou hlavneho kluca a zdielaneho tajomstva
// Pridava dodatocnu vrstvu zabezpecenia pomocou session_nonce
void setup_session(uint8_t session_key[KEY_SIZE],
                   const uint8_t master_key[KEY_SIZE],
                   const uint8_t shared_key[KEY_SIZE],
                   const uint8_t session_nonce[NONCE_SIZE])
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, KEY_SIZE);
    crypto_blake2b_update(&ctx, master_key, KEY_SIZE);
    crypto_blake2b_update(&ctx, shared_key, KEY_SIZE);
    crypto_blake2b_update(&ctx, session_nonce, NONCE_SIZE);
    crypto_blake2b_final(&ctx, session_key);
    crypto_wipe(&ctx, sizeof(ctx));
}

// Vytvorenie kontrolneho kodu pre overenie relacie
// Pouziva sa na kontrolu integrity spojenia
void generate_session_verification(uint8_t *out, const uint8_t *session_key)
{
    const char *msg = "SESSION-VERIFY";
    // Správne poradie a typy argumentov podľa Monocypher
    crypto_blake2b_keyed(
        out,                  // výstup
        32,                   // veľkosť výstupu
        session_key,          // kľúč
        32,                   // veľkosť kľúča
        (const uint8_t *)msg, // správa
        strlen(msg)           // veľkosť správy
    );
}

// Overenie kontrolneho kodu pre relaciu
// Porovnava prijaty kod s vypocitanym kodom
int verify_session_verification(const uint8_t *received, const uint8_t *session_key)
{
    uint8_t expected[32];
    generate_session_verification(expected, session_key);
    // Pouzi Monocypher funkciu pre konštantný čas porovnania
    return crypto_verify32(received, expected) == 0;
}
