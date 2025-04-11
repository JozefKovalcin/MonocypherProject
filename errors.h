#ifndef ERRORS_H
#define ERRORS_H

// Zakladne chybove spravy
#define ERR_SOCKET_SETUP "Error: Failed to set up server socket (%s)\n"                         // Chyba pri nastaveni socketu servera
#define ERR_CLIENT_ACCEPT "Error: Failed to accept client connection (%s)\n"                    // Chyba pri prijimani klientskeho spojenia
#define ERR_HANDSHAKE "Error: Failed during initial handshake - check network connection\n"     // Chyba pri pociatocnej synchronizacii
#define ERR_SALT_RECEIVE "Error: Failed to receive salt from client\n"                          // Chyba pri prijimani kryptografickej soli
#define ERR_KEY_DERIVATION "Error: Key derivation failed\n"                                     // Chyba pri odvodzovani kluca
#define ERR_KEY_ACK "Error: Failed to send key acknowledgment\n"                                // Chyba pri potvrdzovani kluca
#define ERR_SESSION_SETUP "Error: Failed to start session setup\n"                              // Chyba pri vytvarani spojenia
#define ERR_KEY_EXCHANGE "Error: Key exchange failed\n"                                         // Chyba pri vymene klucov
#define ERR_SESSION_NONCE "Error: Failed to receive session nonce\n"                            // Chyba pri prijimani nonce pre spojenie
#define ERR_SESSION_NONCE_SEND "Error: Failed to send session nonce\n"                          // Chyba pri odosielani nonce pre spojenie
#define ERR_SESSION_CONFIRM "Error: Failed to confirm session setup\n"                          // Chyba pri potvrdzovani spojenia
#define ERR_FILENAME_RECEIVE "Error: Failed to receive file name from client (%s)\n"            // Chyba pri prijimani nazvu suboru
#define ERR_FILE_CREATE "Error: Failed to create file '%s' (%s)\n"                              // Chyba pri vytvarani suboru
#define ERR_CHUNK_SIZE "Error: Failed to read chunk size\n"                                     // Chyba pri citani velkosti bloku dat
#define ERR_CHUNK_PROCESS "Error: Failed to process chunk\n"                                    // Chyba pri spracovani bloku dat
#define ERR_TRANSFER_INTERRUPTED "Error: File transfer failed or was interrupted prematurely\n" // Chyba pri preruseni prenosu

// Chybove spravy pre sietove operacie
#define ERR_WINSOCK_INIT "Error: Winsock initialization failed\n"                               // Chyba pri inicializacii Winsock
#define ERR_SOCKET_CREATE "Error: Socket creation error\n"                                      // Chyba pri vytvarani socketu
#define ERR_SOCKET_BIND "Error: Bind failed (%s)\n"                                             // Chyba pri bind operacii
#define ERR_SOCKET_LISTEN "Error: Listen failed (%s)\n"                                         // Chyba pri listen operacii
#define ERR_SOCKET_ACCEPT "Error: Accept failed\n"                                              // Chyba pri prijimani spojenia
#define ERR_INVALID_ADDRESS "Error: Invalid address\n"                                          // Neplatna adresa
#define ERR_CONNECTION_FAILED "Error: Connection failed\n"                                      // Chyba pri pripojeni
#define ERR_READY_SIGNAL "Error: Failed to send ready signal\n"                                 // Chyba pri odosielani signalu pripravenosti
#define ERR_READY_RECEIVE "Error: Failed to receive ready signal\n"                             // Chyba pri prijimani signalu pripravenosti
#define ERR_KEY_ACK_SEND "Error: Failed to send key acknowledgment (sent %d bytes)\n"           // Chyba pri odosielani potvrdenia kluca
#define ERR_KEY_ACK_RECEIVE "Error: Failed to receive key acknowledgment (received %d bytes)\n" // Chyba pri prijimani potvrdenia kluca
#define ERR_KEY_ACK_INVALID "Error: Invalid key acknowledgment received ('%.*s')\n"             // Neplatne potvrdenie kluca
#define ERR_SYNC_SEND "Failed to send sync message\n"                                           // Chyba pri odosielani synchronizacnej spravy
#define ERR_SYNC_INVALID "Invalid sync acknowledgment\n"                                        // Neplatne potvrdenie synchronizacie
#define ERR_SYNC_MESSAGE "Invalid sync message\n"                                               // Neplatna synchronizacna sprava
#define ERR_SYNC_ACK_SEND "Failed to send sync acknowledgment\n"                                // Chyba pri odosielani potvrdenia synchronizacie

// Chybove spravy pre rotaciu klucov
#define ERR_KEY_VALIDATE_SIGNAL "Error: Failed to receive validation marker\n"         // Chyba pri prijimani validacneho markera
#define ERR_KEY_VALIDATE_RECEIVE "Error: Failed to receive key validation\n"           // Chyba pri prijimani validacie kluca
#define ERR_KEY_VALIDATE_MISMATCH "Error: Key validation failed - keys do not match\n" // Kluce sa nezhoduju pri validacii
#define ERR_KEY_ROTATION_READY "Error: Failed to confirm key rotation\n"               // Chyba pri potvrdeni pripravenosti na novy kluc

// Chybove spravy pre validaciu hlavneho kluca
#define ERR_KEY_VALIDATION_SEND "Error: Failed to send master key validation\n"            // Chyba pri odosielani validacie hlavneho kluca
#define ERR_KEY_VALIDATION_RECEIVE "Error: Failed to receive master key validation\n"      // Chyba pri prijimani validacie hlavneho kluca
#define ERR_MASTER_KEY_MISMATCH "Error: Master keys do not match! Connection terminated\n" // Kluce sa nezhoduju - rozdielne hesla

// Chybove spravy pre casove limity
#define ERR_TIMEOUT_RECV "Error: Failed to set receive timeout (%s)\n" // Chyba pri nastaveni timeoutu pre prijem
#define ERR_TIMEOUT_SEND "Error: Failed to set send timeout (%s)\n"    // Chyba pri nastaveni timeoutu pre odosielanie
#define ERR_KEEPALIVE "Warning: Failed to set keepalive\n"             // Chyba pri nastaveni keepalive spojenia

// Chybove spravy pre kryptograficke operacie
#define ERR_RANDOM_LINUX "Error: Failed to generate random bytes (%s)\n"              // Chyba pri generovani nahodnych cisel na Linuxe
#define ERR_RANDOM_WINDOWS "Error: Failed to generate random bytes (BCrypt error)\n"  // Chyba pri generovani nahodnych cisel na Windows
#define ERR_KEY_DERIVE_PARAMS "Error: Invalid parameters for key derivation\n"        // Neplatne parametre pre derivaciu kluca
#define ERR_KEY_DERIVE_MEMORY "Error: Failed to allocate memory for key derivation\n" // Nedostatok pamate pre derivaciu kluca

// Chybove spravy pre nastavenia klienta
#define ERR_IP_ADDRESS_READ "Error: Failed to read IP address\n"                                   // Chyba pri citani IP adresy
#define ERR_PORT_READ "Error: Failed to read port number\n"                                        // Chyba pri citani cisla portu
#define ERR_PORT_INVALID "Error: Invalid port number. Please enter a value between 1 and 65535.\n" // Chyba neplatneho cisla portu

// Chybove spravy pre odosielanie suborov
#define ERR_FILENAME_LENGTH "Error: File name exceeds maximum length of 239 characters\n" // Chyba pri prekroceni max dlzky nazvu suboru
#define ERR_FILENAME_READ "Error: Failed to read file name from input\n"                  // Chyba pri citani nazvu suboru
#define ERR_FILE_OPEN "Error: Cannot open file '%s' (%s)\n"                               // Chyba pri otvarani suboru
#define ERR_FILENAME_SEND "Error: Failed to send file name to server (%s)\n"              // Chyba pri odosielani nazvu suboru
#define ERR_KEY_ROTATION_ACK "Error: Failed to acknowledge key rotation\n"                // Chyba pri potvrdeni rotacie kluca

#endif // ERRORS_H
