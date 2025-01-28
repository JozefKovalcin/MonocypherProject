# Zabezpeceny prenos suborov cez TCP

Tento projekt implementuje system pre zabezpeceny prenos suborov cez TCP/IP siet s vyuzitim modernej kryptografie 
a pokrocilych bezpecnostnych prvkov. Program zabezpecuje end-to-end sifrovanie s autentifikaciou, perfect forward secrecy, 
a rotaciu klucov pocas prenosu.

## Bezpecnostne prvky

### Sifrovanie a autentifikacia
- ChaCha20-Poly1305 pre sifrovanie s autentifikaciou
- Unikatny nonce pre kazdy blok dat
- MAC (Message Authentication Code) pre integritu dat
- Kontrola podvrhnutia alebo upravy dat

### Manazment klucov
- Argon2id pre bezpecnu derivaciu klucov z hesiel
- Ephemeral Diffie-Hellman (X25519) pre perfect forward secrecy
- Automaticka rotacia klucov pocas dlhych prenosov
- Validacia synchronizacie klucov medzi klientom a serverom

### Sietova bezpecnost
- Timeouty pre vsetky sietove operacie
- Detekcia odpojenia pomocou keepalive
- Kontrola velkosti blokov proti preteceniu
- Spolahlivy prenos s retransmisiou

## Hlavne komponenty

### Server (`server.c`)
- Pocuva na TCP porte 8080
- Autentifikuje prichadzajuce spojenia
- Desifruje a overuje prijate data
- Uklada subory s prefixom "received_"

### Klient (`client.c`) 
- Zobrazuje dostupne lokalne subory
- Sifruje a fragmentuje subory na bloky
- Synchronizuje rotaciu klucov so serverom
- Zobrazuje progres prenosu

### Sietova vrstva (`siete.c`, `siete.h`)
- Sprava TCP spojeni
- Synchronizacia komunikacie
- Obsluha timeoutov a chyb
- Platformovo nezavisla implementacia

### Kryptograficke funkcie (`crypto_utils.c`, `crypto_utils.h`)
- Generovanie nahodnych hodnot
- Derivacia a rotacia klucov  
- X25519 key exchange
- Validacia klucov

## Poziadavky

- C kompilator (GCC/MinGW)
- Monocypher 4.0.2
- Make 

## Kompilacia

```bash
# Linux
make all

# Windows (MinGW)
mingw32-make all
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

3. Priebeh komunikacie:

a) Vytvorenie zabezpeceneho spojenia:
- Klient a server si vymenia ephemeral kluce
- Vygeneruje sa spolocne tajomstvo pomocou X25519
- Vytvori sa session kluc pre dane spojenie

b) Autentifikacia:
- Klient vygeneruje nahodnu sol
- Uzivatelia zadaju heslo na oboch stranach
- Obe strany odvodia rovnaky kluc pomocou Argon2
- Prebehne validacia zhody klucov

c) Prenos suboru:
- Klient zobrazi dostupne lokalne subory
- Pouzivatel vyberie subor na prenos
- Subor je fragmentovany na bloky
- Kazdy blok je samostatne sifrovany s unikatnym nonce
- Server overuje integritu a desifruje bloky
- Prijaty subor je ulozeny s prefixom "received_"

d) Rotacia klucov:
- Po stanovenom pocte blokov sa iniciuje rotacia
- Obe strany synchronne odvodia novy kluc
- Prebehne validacia spravnosti rotacie
- Prenos pokracuje s novym klucom

## Chybove stavy

Program obsahuje robustnu detekciu a spracovanie chyb:
- Timeout pri sietovych operaciach
- Neuspesna autentifikacia
- Corrupted alebo manipulovane data
- Neuspesna synchronizacia klucov
- Chyby pri praci so subormi

## Bezpecnostne poznamky

1. Vsetky citlive data su okamzite vymazane z pamate po pouziti

2. Perfect forward secrecy zabezpecuje ze:
   - Kompromitacia dlhodobeho kluca neohrozuje minule prenosy
   - Kazde spojenie pouziva nove nahodne kluce
   - Historia komunikacie je chranena aj pri ziskani aktualnych klucov

3. Pravidelna rotacia klucov:
   - Limituje mnozstvo dat sifrovanych jednym klucom
   - Poskytuje post-compromise security
   - Synchronne prebieha na oboch stranach

4. Ochrana proti MitM utokom:
   - Autentifikacia pomocou zdielaneho hesla
   - Validacia integrity pomocou MAC
   - Overovanie synchronizacie klucov

## Vycistenie projektu

```bash
# Linux
make clean

# Windows
mingw32-make clean
```

## Limity a mozne vylepsenia

- Implementacia threadov pre paralelne spracovanie
- Podpora pre viacero sucasnych klientov
- Komprimacia pred sifrovanim
- Obnovenie prerusenych prenosov
- GUI rozhranie
