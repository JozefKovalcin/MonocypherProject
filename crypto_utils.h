/*******************************************************************************
 * Program:    Kryptograficke nastroje pre zabezpeceny prenos
 * Subor:      crypto_utils.h
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.1
 * Datum:      11-03-2025
 *
 * Popis:
 *     Tento subor obsahuje funkcie pre:
 *     - Vytvaranie nahodnych cisel pre bezpecne sifrovanie
 *     - Vytvaranie klucov z hesiel pomocou Argon2
 *     - Pravidelnu vymenu klucov pocas prenosu
 *     - Zabezpecenu vymenu klucov pomocou X25519
 *     - Spravovanie sifrovanych spojeni
 * Zavislosti:
 *     - Monocypher 4.0.2 (sifrovacie algoritmy)
 *     - constants.h (konstanty programu)
 *     - platform.h (platform-specificke funkcie)
 *******************************************************
 ******************************************************************************/

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h> // Kniznica pre datove typy (uint8_t, uint32_t)

#include "monocypher.h" // Pre Monocypher kryptograficke funkcie
#include "constants.h"  // Definicie konstant pre program
#include "platform.h"   // Pre funkcie specificke pre operacny system

// Pomocne funkcie
void print_hex(const char *label, uint8_t *data, int len); // Vypise data v citatelnej forme pre kontrolu

// Zakladne kryptograficke funkcie
void generate_random_bytes(uint8_t *buffer, size_t size); // Vytvori bezpecne nahodne cisla

// Funkcie pre pracu s heslami
int derive_key_server(const char *password, const uint8_t *received_salt, // Server: Vytvori kluc z hesla a prijatej soli
                      uint8_t *key, uint8_t *salt);

int derive_key_client(const char *password, uint8_t *key, uint8_t *salt); // Klient: Vytvori kluc z hesla a novej soli

// Funkcie pre bezpecnost spojenia
void rotate_key(uint8_t *current_key, // Vytvori novy kluc z existujuceho pre lepsiu bezpecnost
                const uint8_t *previous_key,
                const uint8_t *nonce); // Nahodny nonce pre rotaciu kluca

void secure_wipe(void *data, size_t size); // Bezpecne vymaze citlive data z pamate

// Overovanie klucov
void generate_key_validation(uint8_t *validation, // Vytvori kontrolny kod pre overenie kluca
                             const uint8_t *key);

// Funkcie pre bezpecnu vymenu klucov
void generate_ephemeral_keypair(uint8_t public_key[32], // Vytvori docasny par klucov pre jedno spojenie
                                uint8_t secret_key[32]);

void compute_shared_secret(uint8_t shared_secret[32], // Vypocita spolocny tajny kluc medzi klientom a serverom
                           const uint8_t secret_key[32],
                           const uint8_t peer_public[32]);

void setup_session(uint8_t session_key[32], // Pripravi sifrovane spojenie s novymi klucmi
                   const uint8_t master_key[32],
                   const uint8_t shared_key[32],
                   const uint8_t session_nonce[24]);

#endif // CRYPTO_UTILS_H