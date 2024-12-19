/********************************************************************************
 * Program:    Kryptografické utility pre zabezpečený prenos
 * Subor:      crypto_utils.h
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      2024
 * 
 * Popis: 
 *     Hlavickový súbor obsahujúci deklarácie pomocných kryptografických funkcií:
 *     - Generovanie náhodných čísel pre nonce a salt
 *     - Deriváciu kľúča z hesla pomocou Argon2
 *     - Pomocné funkcie pre prácu s kryptografickými dátami
 * 
 * Zavislosti:
 *     - Monocypher 4.0.2 (implementacia sifrovania)
 *     - constants.h (definicie konstant pre program)
 *******************************************************************************/

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h> // Kniznica pre datove typy (uint8_t, uint32_t)

#include "monocypher.h"  // Pre Monocypher kryptograficke funkcie
#include "constants.h"    // Definicie konstant pre program

// Pomocne funkcie
void print_hex(const char *label, uint8_t *data, int len);  // Vypis hexadecimalnych dat

// Kryptograficke funkcie
// Generuje kryptograficky bezpecne nahodne cisla pre pouzitie v sifrovani
void generate_random_bytes(uint8_t *buffer, size_t size);

// Serverova verzia derivacie kluca
// Pouziva prijatu sol na vytvorenie rovnakeho kluca ako klient
int derive_key_server(const char *password, const uint8_t *received_salt, uint8_t *key, uint8_t *salt);

// Klientska verzia derivacie kluca
// Generuje novu sol a odvodi kluc z hesla
int derive_key_client(const char *password, uint8_t *key, uint8_t *salt);

#endif // CRYPTO_UTILS_H