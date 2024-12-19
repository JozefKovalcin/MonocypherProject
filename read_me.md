# Zabezpeceny prenos suborov cez TCP

Tento projekt implementuje zabezpeceny system pre prenos suborov cez TCP/IP siet s vyuzitim sifrovania ChaCha20-Poly1305 a derivaciou klucov pomocou Argon2.

## Hlavne komponenty

### Server (`server.c`)
- Caka na pripojenie klienta na porte 8080
- Prijima sifrovane subory od klienta
- Desifruje data pomocou zdielaneho kluca
- Uklada desifrovane subory s prefixom "received_"

### Klient (`client.c`) 
- Pripaja sa na server
- Zobrazuje dostupne subory v aktualnom adresari
- Sifruje vybrany subor pomocou ChaCha20-Poly1305
- Posiela zasifrovane data na server

### Sietova vrstva (`siete.c`, `siete.h`)
- Sprava TCP spojeni a socketov
- Implementacia prenosu dat
- Synchronizacia komunikacie
- Obsluha timeoutov a chybovych stavov

### Kryptograficke funkcie (`crypto_utils.c`, `crypto_utils.h`)
- Generovanie nahodnych hodnot (nonce, sol)
- Derivacia klucov pomocou Argon2
- Sifrovanie/desifrovanie pomocou ChaCha20-Poly1305
- Sprava kryptografickych materialov

## Poziadavky

- C kompilator (GCC/MinGW)
- Kniznica Monocypher 4.0.2
- Make utilita

## Kompilacia

```bash
# Windows (MinGW)
mingw32-make all

# Linux
make all
```

## Pouzitie

1. Spustenie servera:
```bash
./server
```

2. Spustenie klienta:
```bash
./client
```

3. Zadanie hesla:
- Klient vygeneruje kryptograficku sol
- Pouzivatel zada heslo
- Klient odvodi kluc pomocou Argon2 a posle sol serveru
- Server poziada o rovnake heslo
- Server odvodi rovnaky kluc pomocou prijatej soli

4. Prenos suboru:
- Klient zobrazi dostupne subory
- Pouzivatel vyberie subor na prenos
- Subor je zasifrovany a posielany po blokoch
- Server desifruje bloky a ulozi subor s prefixom "received_"

## Bezpecnostne prvky

- ChaCha20-Poly1305 pre sifrovanie s autentifikaciou
- Argon2 pre bezpecnu derivaciu klucov
- Unikatny nonce pre kazdy blok dat
- Kontrola integrity pomocou Poly1305
- Timeouty pre sietove operacie
- Detekcia odpojenia pomocou keepalive

## Vycistenie projektu

```bash
# Windows
mingw32-make clean

# Linux  
make clean
```

## Implementovane funkcie

### Sietove funkcie (`siete.c`)
- `setup_server()`: Vytvara a konfiguruje TCP server
- `accept_client_connection()`: Prijima nove spojenie od klienta
- `connect_to_server()`: Vytvara spojenie so serverom
- `send_ready_signal()`: Posiela signal pripravenosti
- `wait_for_ready()`: Caka na signal pripravenosti
- `send_file_name()`: Posiela nazov suboru
- `receive_file_name()`: Prijima nazov suboru
- `send_chunk_size()`: Posiela velkost bloku dat
- `receive_chunk_size()`: Prijima velkost bloku dat
- `send_encrypted_chunk()`: Posiela zasifrovany blok dat
- `receive_encrypted_chunk()`: Prijima zasifrovany blok dat

### Kryptograficke funkcie (`crypto_utils.c`)
- `generate_random_bytes()`: Generuje kryptograficky bezpecne nahodne cisla
- `derive_key_client()`: Odvodzuje sifrovaci kluc na strane klienta
- `derive_key_server()`: Odvodzuje sifrovaci kluc na strane servera
- `print_hex()`: Zobrazuje kryptograficke data v citatelnej forme

### Monocypher funkcie
- `crypto_aead_lock()`: Sifruje data pomocou ChaCha20-Poly1305
- `crypto_aead_unlock()`: Desifruje data pomocou ChaCha20-Poly1305
- `crypto_argon2()`: Derivuje kluc z hesla pomocou Argon2
- `crypto_wipe()`: Bezpecne maze citlive data z pamate

### Windows-specificke funkcie
- `getpass()`: Implementacia bezpecneho nacitania hesla pre Windows
- `initialize_network()`: Inicializacia Winsock pre sietovu komunikaciu
- `cleanup_network()`: Ukoncenie a cistenie Winsock

### Pomocne funkcie
- `cleanup_socket()`: Zatvara jeden socket
- `cleanup_sockets()`: Zatvara viacero socketov
- `wait()`: Implementacia casoveho oneskorenia
- `set_timeout_options()`: Nastavuje timeouty pre sockety

## Datove struktury

### Konstanty (`constants.h`)
- `PORT`: Cislo portu pre komunikaciu (predvolene 8080)
- `KEY_SIZE`: Velkost sifrovacieho kluca (32 bajtov)
- `SALT_SIZE`: Velkost kryptografickej soli (32 bajtov)
- `NONCE_SIZE`: Velkost nonce hodnoty (24 bajtov)
- `TAG_SIZE`: Velkost autentifikacneho tagu (16 bajtov)
- `TRANSFER_BUFFER_SIZE`: Velkost bufferu pre prenos (4096 bajtov)

### Premenne
- `key[]`: Hlavny sifrovaci kluc
- `nonce[]`: Jednorazova hodnota pre kazdy blok
- `salt[]`: Kryptograficka sol pre derivaciu kluca
- `work_area[]`: Pracovna pamat pre Argon2

## Bezpecnostne opatrenia
- Vsetky citlive data su okamzite vymazane z pamate
- Hesla sa nikdy neukladaju na disk
- Kazdy blok dat ma unikatny nonce
- Overenie integrity pomocou MAC (Message Authentication Code)
- Kontrola velkosti blokov proti preteceniu
- Timeouty pre vsetky sietove operacie
