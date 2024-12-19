
# Systém zabezpečenej TCP komunikácie

Tento projekt obsahuje implementáciu zabezpečeného klient-server systému pre prenos súborov cez TCP. Na šifrovanie používa algoritmus ChaCha20-Poly1305 a deriváciu kľúčov pomocou Argon2.

## Popis

Projekt poskytuje implementáciu servera a klienta pre bezpečný prenos súborov:
- **Server**: Prijíma šifrované súbory a dešifruje ich pomocou odvodených kľúčov.
- **Klient**: Odosiela šifrované súbory na server po ich zabezpečení pomocou odvodených kľúčov.

Obe implementácie podporujú systémy Windows a Linux.

## Požiadavky

- GCC kompilátor alebo ekvivalent (napr. MinGW pre Windows)
- Knižnica `Monocypher` (verzia 4.0.2)
- Štandardné knižnice jazyka C

## Inštrukcie na spustenie

1. Stiahnite si projekt a prejdite do jeho hlavného adresára.
2. Programy skompilujte pomocou priloženého `Makefile`:
   ```bash
   mingw32-make all # Pre Windows s MinGW
   make all         # Pre Linux
   ```

   Po spustení príkazu sa vytvoria nasledujúce súbory:
   - `server.exe` (Windows) alebo `server` (Linux)
   - `client.exe` (Windows) alebo `client` (Linux)

## Použitie

### 1. Spustite server

   Spustite server v termináli. Server bude počúvať prichádzajúce pripojenia na porte 8080.
   ```bash
   ./server
   ```

### 2. Spustite klienta

   Otvorte iný terminál a spustite klienta. Klient sa pripojí k serveru a vyzve vás na zadanie hesla pre zabezpečenie komunikácie.
   ```bash
   ./client
   ```
### 3. Zadanie hesla

   Klient požiada o heslo a následne zašle potrebné údaje serveru. Server príme zaslané údaje a po zadaní rovnakého hesla potvrdí spojenie. 

### 3. Prenos súborov

   Klient zobrazí zoznam súborov v aktuálnom adresári. Zadajte názov súboru, ktorý chcete odoslať. Server prijme, dešifruje a uloží súbor s predponou `received_`.

## Čistenie

Na odstránenie vygenerovaných súborov použite nasledujúci príkaz:
```bash
mingw32-make clean # Pre Windows
make clean         # Pre Linux
```

## Poznámky

- Uistite sa, že otvárate port, na ktorom aktuálne nebeží žiaden proces. 
