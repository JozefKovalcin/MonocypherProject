# Zabezpeceny prenos suborov cez TCP

Tento projekt implementuje system pre zabezpeceny prenos suborov cez TCP/IP siet s vyuzitim modernej kryptografie a pokrocilych bezpecnostnych prvkov. Program zabezpecuje end-to-end sifrovanie s autentifikaciou, perfect forward secrecy, a rotaciu klucov pocas prenosu.

## Bezpecnostne prvky

### Sifrovanie a autentifikacia
- ChaCha20-Poly1305 pre sifrovanie s autentifikaciou
- Unikatny nonce pre kazdy blok dat
- MAC (Message Authentication Code) pre integritu dat
- Kontrola podvrhnutia alebo upravy dat

### Manazment klucov
- Argon2id pre bezpecne odvodenie klucov z hesiel
- Ephemeral Diffie-Hellman (X25519) pre perfect forward secrecy
- Automaticka rotacia klucov pocas dlhych prenosov
- Validacia synchronizacie klucov medzi klientom a serverom

### Sietova bezpecnost
- Timeouty pre vsetky sietove operacie
- Detekcia odpojenia pomocou keepalive
- Kontrola velkosti blokov proti preteceniu
- Spolahlivy prenos s retransmisiou
- Synchronizacia a potvrdenia prenosov pomocou custom protokolu

## Architektura systemu

### Client-Server Model
- Klient iniciuje spojenie a autentifikaciu
- Server overuje identitu klienta a prijima sifrovane subory
- Obe strany spolupracuju na zabezpeceni komunikacie

### Hlavne komponenty

#### Server (`server.c`)
- Pocuva na TCP porte 8080
- Autentifikuje prichadzajuce spojenia
- Desifruje a overuje prijate data
- Uklada subory s prefixom "received_"
- Synchronizuje rotaciu klucov s klientom

#### Klient (`client.c`)
- Zobrazuje dostupne lokalne subory
- Sifruje a fragmentuje subory na bloky
- Synchronizuje rotaciu klucov so serverom
- Zobrazuje progres prenosu

#### Sietova vrstva (`siete.c`, `siete.h`)
- Sprava TCP spojeni
- Synchronizacia komunikacie
- Obsluha timeoutov a chyb
- Platformovo nezavisla implementacia

#### Kryptograficke funkcie (`crypto_utils.c`, `crypto_utils.h`)
- Generovanie nahodnych hodnot
- Derivacia a rotacia klucov
- X25519 key exchange
- Validacia klucov
- Generovanie a verifikacia MAC tagov

## Poziadavky

- C kompilator (GCC/MinGW)
- Monocypher 4.0.2
- Make

## Kompilacia

```bash
# Linux
make all

# Windows (MinGW)
mingw32-make all alebo .\build.bat
```

## Pouzitie

### Spustenie servera:
```bash
./server
```

### Spustenie klienta:
```bash
./client
```

## Priebeh komunikacie:

1. **Vytvorenie zabezpeceneho spojenia**:
   - Klient a server si vymenia ephemeral kluce
   - Vygeneruje sa spolocne tajomstvo pomocou X25519
   - Vytvori sa session kluc pre dane spojenie

2. **Autentifikacia**:
   - Klient vygeneruje nahodnu sol
   - Uzivatelia zadaju heslo na oboch stranach
   - Obe strany odvodia rovnaky kluc pomocou Argon2
   - Prebehne validacia zhody klucov

3. **Prenos suboru**:
   - Klient zobrazi dostupne lokalne subory
   - Pouzivatel vyberie subor na prenos
   - Subor je fragmentovany na bloky
   - Kazdy blok je samostatne sifrovany s unikatnym nonce
   - Server overuje integritu a desifruje bloky
   - Prijaty subor je ulozeny s prefixom "received_"

4. **Rotacia klucov**:
   - Po stanovenom pocte blokov sa iniciuje rotacia
   - Obe strany synchronne odvodia novy kluc
   - Prebehne validacia spravnosti rotacie
   - Prenos pokracuje s novym klucom

## Bezpecnostne vlastnosti

### Perfect Forward Secrecy
- Kompromitacia dlhodobeho kluca neohrozuje minule prenosy
- Kazde spojenie pouziva nove nahodne kluce
- Historia komunikacie je chranena aj pri ziskani aktualnych klucov

### Ochrana integrity dat
- Autentifikacia pomocou zdielaneho hesla
- Validacia integrity pomocou MAC
- Overovanie synchronizacie klucov

## Chybove stavy

Program obsahuje robustnu detekciu a spracovanie chyb:
- Timeout pri sietovych operaciach
- Neuspesna autentifikacia
- Corrupted alebo manipulovane data
- Neuspesna synchronizacia klucov
- Chyby pri praci so subormi

## Bezpecnostne poznamky

1. Vsetky citlive data su okamzite vymazane z pamate po pouziti

2. Pravidelna rotacia klucov:
   - Limituje mnozstvo dat sifrovanych jednym klucom
   - Poskytuje post-compromise security
   - Synchronne prebieha na oboch stranach

## Vycistenie projektu

```bash
# Linux
make clean

# Windows
mingw32-make clean
```

