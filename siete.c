/********************************************************************************
 * Program:    Implementacia sietovych funkcii pre zabezpeceny prenos suborov
 * Subor:      siete.c
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      2024
 * 
 * Popis: 
 *     Implementuje sietove funkcie pre klienta a server, vrátane:
 *     - Vytvorenia a konfiguracie socketov
 *     - Prijimania a odosielania spojení
 *     - Prenosu dat a synchronizacie komunikacie
 * 
 * Zavislosti:
 *     - siete.h (deklaracie sietovych funkcii)
 *     - constants.h (definicie konstant pre program)
 *******************************************************************************/

#include <stdio.h>        // Kniznica pre standardny vstup a vystup (nacitanie zo suborov, vypis na obrazovku)
#include <stdlib.h>       // Kniznica pre vseobecne funkcie (sprava pamate, konverzie, nahodne cisla)

#ifdef _WIN32
#include <winsock2.h>     // Windows: Zakladna sietova kniznica
#include <ws2tcpip.h>     // Windows: Rozsirene sietove funkcie
#include <windows.h>      // Windows: Zakladne systemove funkcie
#else
#include <sys/socket.h> // Linux: Sietove funkcie (socket, bind, listen, accept)
#include <sys/time.h>  // Linux: Struktura pre cas (struct timeval)
#include <unistd.h>  // Linux: Kniznica pre systemove volania (close, read, write)
#endif

#include "siete.h"        // Pre sietove funkcie

// Implementacia funkcii pre spravu socketov
// Rozdielna implementacia pre Windows a Linux

// Uvolnenie Winsock pre Windows platformu
void cleanup_network(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Bezpecne zatvorenie socketu
// Rozdielna implementacia pre Windows (closesocket) a Linux (close)
void cleanup_socket(int sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

// Zatvorenie oboch socketov (klient + server)
// Pouzivane pri ukonceni spojenia alebo chybe
void cleanup_sockets(int new_socket, int server_fd) {
#ifdef _WIN32
    closesocket(new_socket);
    closesocket(server_fd);
#else
    close(new_socket);
    close(server_fd);
#endif
}

// Inicializacia sietovej kniznice pre Windows
// Na Linuxe nie je potrebna
void initialize_network(void) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Error: Winsock initialization failed\n");
        exit(-1);
    }
#endif
}

// Bezpecne ukoncenie socketu
// Zaistuje korektne ukoncenie spojenia
void shutdown_socket(int sock) {
#ifdef _WIN32
    shutdown(sock, SD_BOTH);
    Sleep(SOCKET_SHUTDOWN_DELAY_MS);    // Cakanie na ukoncenie vsetkych prenosov
#else
    shutdown(sock, SHUT_RDWR);
    sleep(SOCKET_SHUTDOWN_DELAY_MS / 1000);  // Prevod na sekundy pre Linux
#endif
}

// Cakacia funkcia s platformovo nezavislou implementaciou
void wait(void) {
#ifdef _WIN32
    Sleep(WAIT_DELAY_MS);    // Pauza pre synchronizaciu komunikacie
#else
    usleep(WAIT_DELAY_MS * 1000);    // Prevod na mikrosekundy pre Linux
#endif
}

// Nastavenie timeoutov pre socket
// Zaistuje, ze operacie nebudu blokovat program donekonecna
void set_timeout_options(int sock) {
#ifdef _WIN32
    // Windows pouziva DWORD (milisekundy) pre timeout
    DWORD timeout = SOCKET_TIMEOUT_MS;
    // Nastavenie pre prijimanie aj odosielanie
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != 0) {
        fprintf(stderr, "Error: Failed to set receive timeout (error: %d)\n", WSAGetLastError());
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) != 0) {
        fprintf(stderr, "Error: Failed to set send timeout (error: %d)\n", WSAGetLastError());
    }
    
    // Pridane: Nastavenie keepalive pre detekciu odpojenia
    BOOL keepalive = TRUE;
    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepalive, sizeof(keepalive)) != 0) {
        fprintf(stderr, "Warning: Failed to set keepalive\n");
    }
#else
    // Linux pouziva struct timeval (sekundy a mikrosekundy) pre timeout
    struct timeval timeout;
    timeout.tv_sec = SOCKET_TIMEOUT_MS / 1000;     // Prevod milisekund na sekundy
    timeout.tv_usec = (SOCKET_TIMEOUT_MS % 1000) * 1000;  // Zvysok v mikrosekundach
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const void *)&timeout, sizeof(timeout)) != 0) {
        fprintf(stderr, "Error: Failed to set receive timeout (%s)\n", strerror(errno));
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const void *)&timeout, sizeof(timeout)) != 0) {
        fprintf(stderr, "Error: Failed to set send timeout (%s)\n", strerror(errno));
    }
#endif
}

// Serverove funkcie

// Vytvorenie a konfiguracia servera
// - Vytvori socket
// - Nastavi adresu a port
// - Zacne pocuvat na porte
int setup_server(void) {
    // Server socket, ktory pocuva na urcitej adrese
    int server_fd;
    // Struktura address obsahuje informacie o tom, kde ma server pocuvat
    struct sockaddr_in address;

    // Vytvorenie novej "schranky" (socketu)
    // AF_INET znamena ze pouzivame IPv4 adresy
    // SOCK_STREAM znamena ze chceme spolahlivy prenos (TCP)
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Error: Socket creation failed\n");
        return -1;
    }

    // Nastavenie adresy servera:
    // - sin_family: pouzivame IPv4
    // - sin_addr.s_addr: server bude pocuvat na vsetkych dostupnych adresach
    // - sin_port: cislo portu, na ktorom bude server pocuvat
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;   // 0.0.0.0 - vsetky dostupne adresy
    address.sin_port = htons(PORT);         // Prevedieme cislo portu do sietoveho formatu

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fprintf(stderr, "Error: Bind failed (%s)\n", strerror(errno));
        return -1;
    }

    if (listen(server_fd, MAX_PENDING_CONNECTIONS) < 0) {
        fprintf(stderr, "Error: Listen failed (%s)\n", strerror(errno));
        return -1;
    }

    return server_fd;
}

// Prijatie spojenia od klienta
// - Prijme prichadzajuce spojenie
// - Vypise informacie o klientovi
int accept_client_connection(int server_fd, struct sockaddr_in *client_addr) {
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int new_socket = accept(server_fd, (struct sockaddr *)client_addr, &addrlen);
    
    if (new_socket < 0) {
        fprintf(stderr, "Error: Accept failed\n");
        return -1;
    }
    
    // Nastavenie pre formatovanie IP adresy zo sietoveho formatu do textoveho
    // Priklad: Z binarneho formatu vytvori retazec "192.168.1.1"
    printf("Connection accepted from %s:%d\n", 
           inet_ntoa(client_addr->sin_addr),  // Prevedie IP adresu na citatelny text
           ntohs(client_addr->sin_port));     // Prevedie cislo portu zo sietoveho formatu
    
    return new_socket;
}

// Funkcie pre prenos dat

// Odoslanie signalu pripravenosti klientovi
int send_ready_signal(int socket) {
    if (send(socket, "READY", SIGNAL_SIZE, 0) != SIGNAL_SIZE) {
        fprintf(stderr, "Error: Failed to send ready signal\n");
        return -1;
    }
    return 0;
}

// Vytvorenie spojenia so serverom
// - Vytvori socket
// - Pripoji sa na zadanu adresu
int connect_to_server(const char *address) {
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Error: Socket creation error\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, address, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Error: Invalid address\n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Error: Connection failed\n");
        return -1;
    }

    return sock;
}

// Funkcie pre prenos kryptografickych materialov

// Prijatie kryptografickej soli od klienta
int receive_salt(int socket, uint8_t *salt) {
    #ifdef _WIN32
    return (recv(socket, (char *)salt, SALT_SIZE, 0) == SALT_SIZE) ? 0 : -1;
    #else
    return (read(socket, salt, SALT_SIZE) == SALT_SIZE) ? 0 : -1;
    #endif
}

// Odoslanie kryptografickej soli serveru
int send_salt_to_server(int socket, const uint8_t *salt) {
    return (send(socket, (const char *)salt, SALT_SIZE, 0) == SALT_SIZE) ? 0 : -1;
}

// Funkcie pre synchronizaciu

// Cakanie na signal pripravenosti
int wait_for_ready(int socket) {
    char buffer[SIGNAL_SIZE + 1] = {0};
    if (recv(socket, buffer, SIGNAL_SIZE, 0) <= 0 || strcmp(buffer, "READY") != 0) {
        fprintf(stderr, "Error: Failed to receive ready signal\n");
        return -1;
    }
    return 0;
}

// Cakanie na potvrdenie kluca
int wait_for_key_acknowledgment(int socket) {
    char buffer[SIGNAL_SIZE + 1] = {0};
    int received = recv(socket, buffer, SIGNAL_SIZE, MSG_WAITALL);
    if (received != SIGNAL_SIZE) {
        fprintf(stderr, "Error: Failed to receive key acknowledgment (received %d bytes)\n", received);
        return -1;
    }
    if (memcmp(buffer, "KEYOK", SIGNAL_SIZE) != 0) {
        fprintf(stderr, "Error: Invalid key acknowledgment received ('%.*s')\n", received, buffer);
        return -1;
    }
    printf("Received key acknowledgment from server\n");
    return 0;
}

int send_key_acknowledgment(int socket) {
    const char ack[] = "KEYOK";
    int result = send(socket, ack, SIGNAL_SIZE, 0);
    if (result != SIGNAL_SIZE) {
        fprintf(stderr, "Error: Failed to send key acknowledgment (sent %d bytes)\n", result);
        return -1;
    }
    return 0;
}

// Funkcie pre prenos suborov

// Odoslanie nazvu suboru
int send_file_name(int socket, const char *file_name) {
    return (send(socket, file_name, strlen(file_name) + 1, 0) > 0) ? 0 : -1;
}

// Prijatie nazvu suboru
int receive_file_name(int socket, char *file_name, size_t max_len) {
    memset(file_name, 0, max_len);
    #ifdef _WIN32
    return (recv(socket, file_name, max_len, 0) > 0) ? 0 : -1;
    #else
    return (read(socket, file_name, max_len) > 0) ? 0 : -1;
    #endif
}

// Odoslanie velkosti bloku dat
int send_chunk_size(int socket, uint32_t size) {
    // Prevedie cislo zo standardneho formatu do sietoveho
    // Je to potrebne, pretoze rozne pocitace ukladaju cisla rozdielne
    uint32_t net_size = htonl(size);  // 'h' - host, 'to' - konverzia, 'n' - network, 'l' - long
    return (send(socket, (const char *)&net_size, sizeof(net_size), 0) == sizeof(net_size)) ? 0 : -1;
}

// Prijatie velkosti bloku dat
int receive_chunk_size(int socket, uint32_t *size) {
    uint32_t net_size;
    // MSG_WAITALL znamena, ze funkcia pocka, kym neprijme vsetky pozadovane data
    // Bez tohto by mohla vratit menej dat, nez potrebujeme
    int received = recv(socket, (char *)&net_size, sizeof(net_size), MSG_WAITALL);
    if (received != sizeof(net_size)) {
        return -1;
    }
    *size = ntohl(net_size);
    return 0;
}

// Odoslanie zasifrovaneho bloku dat
int send_encrypted_chunk(int socket, const uint8_t *nonce, const uint8_t *tag,
                        const uint8_t *data, size_t data_len) {
    if (send(socket, (const char *)nonce, NONCE_SIZE, 0) != NONCE_SIZE ||
        send(socket, (const char *)tag, TAG_SIZE, 0) != TAG_SIZE ||
        send(socket, (const char *)data, data_len, 0) != (ssize_t)data_len) {
        return -1;
    }
    return 0;
}

// Prijatie zasifrovaneho bloku dat
int receive_encrypted_chunk(int socket, uint8_t *nonce, uint8_t *tag,
                          uint8_t *data, size_t data_len) {
    // Najprv prijme nonce (24 bajtov) a tag (16 bajtov)
    if (recv(socket, (char *)nonce, NONCE_SIZE, 0) != NONCE_SIZE ||
        recv(socket, (char *)tag, TAG_SIZE, 0) != TAG_SIZE) {
        return -1;
    }

    // Prijimanie zasifrovanych dat po castiach
    // Pokracuje, kym neprijme vsetky data alebo nenastane chyba
    size_t total_received = 0;
    while (total_received < data_len) {
        int bytes = recv(socket, (char *)(data + total_received),
                        data_len - total_received, 0);
        if (bytes <= 0) {    // Spojenie bolo ukoncene alebo nastala chyba
            return -1;
        }
        total_received += bytes;    // Pripocita prijate bajty k celkovemu poctu
    }
    return 0;
}

// Funkcie pre potvrdenia prenosu

int send_transfer_ack(int socket) {
    // Pridane opakovane pokusy o odoslanie potvrdenia
    int retries = MAX_RETRIES;
    // Pouzijeme jednotny format pre vsetky potvrdenia
    const char ack[] = "TACK";  // Transfer ACKnowledgment
    
    while (retries > 0) {
        printf("Sending acknowledgment (attempt %d/%d)...\n", MAX_RETRIES - retries + 1, MAX_RETRIES);
        
        #ifdef _WIN32
        int result = send(socket, ack, ACK_SIZE, 0);
        #else
        int result = send(socket, ack, ACK_SIZE, MSG_NOSIGNAL);
        #endif
        
        if (result == ACK_SIZE) {
            // Pridana pauza pre stabilizaciu spojenia
            wait();
            return 0;
        }
        
        retries--;
        if (retries > 0) {
            printf("Failed to send acknowledgment, retrying in %d ms...\n", WAIT_DELAY_MS);
            wait();
        }
    }
    return -1;
}

int wait_for_transfer_ack(int socket) {
    int retries = MAX_RETRIES;
    char ack_buffer[ACK_SIZE + 1] = {0};
    const char expected_ack[] = "TACK";
    
    while (retries > 0) {
        printf("Waiting for acknowledgment (attempt %d/%d)...\n", MAX_RETRIES - retries + 1, MAX_RETRIES);
        
        // Pouzijeme MSG_WAITALL pre zabezpecenie prijatia vsetkych dat naraz
        int received = recv(socket, ack_buffer, ACK_SIZE, MSG_WAITALL);
        
        if (received == ACK_SIZE && memcmp(ack_buffer, expected_ack, ACK_SIZE) == 0) {
            return 0;
        }
        
        retries--;
        if (retries > 0) {
            printf("Failed to receive acknowledgment (received %d bytes), retrying in %d ms...\n", 
                   received, WAIT_DELAY_MS);
            wait();
        }
    }
    return -1;
}