#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <time.h>

#define BUFFER_SIZE 1024
#define LEADING_ZEROS 20  // Number of leading zero bits required in the hash
#define CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// Replace newline and tab characters in the message with spaces
void sanitize_message(char *message, int length) {
    for (int i = 0; i < length; i++) {
        if (message[i] == '\n' || message[i] == '\t') {
            message[i] = ' ';
        }
    }
}

// Check if the hash has the required leading zero bits
int validate_hash(const unsigned char *hash) {
    int zero_bits = 0;

    for (int i = 0; i < SHA256_DIGEST_LENGTH && zero_bits < LEADING_ZEROS; i++) {
        unsigned char byte = hash[i];

        // Count the number of leading zero bits in the current byte
        for (int j = 7; j >= 0; j--) {
            if (byte & (1 << j)) {
                return zero_bits >= LEADING_ZEROS; // Stop if we find a non-zero bit
            }
            zero_bits++;
        }
    }
    return zero_bits >= LEADING_ZEROS;
}

// Generate a random alphanumeric string as proof-of-work
void random_pow_string(char *pow, size_t length) {
    for (size_t i = 0; i < length; i++) {
        pow[i] = CHARSET[rand() % (sizeof(CHARSET) - 1)];
    }
    pow[length] = '\0';
}

void print_hash(const unsigned char *hash) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// Generate the proof-of-work string
void generate_pow(char *pow, const char *message) {
    char combined_msg[BUFFER_SIZE];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    size_t pow_length = 4;  // Start with a small length and increase if necessary

    srand(time(NULL));  // Seed for random number generation

    while (1) {
        // Generate a random proof-of-work string
        random_pow_string(pow, pow_length);
        snprintf(combined_msg, sizeof(combined_msg), "%s:%s", pow, message);

        // Compute the SHA-256 hash
        SHA256((unsigned char *)combined_msg, strlen(combined_msg), hash);

        // Check if the hash meets the criteria of 20 leading zero bits
        if (validate_hash(hash)) {
            break;
        }

        // Increment the length of the proof-of-work string if needed
        if (++pow_length >= BUFFER_SIZE / 2) {
            pow_length = 4;  // Reset length if it gets too large
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <port> <message>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    char *message = argv[2];

    // Sanitize the message
    sanitize_message(message, strlen(message));

    // Generate proof-of-work
    char pow[BUFFER_SIZE];
    generate_pow(pow, message);

    // Hash the combined message (proof-of-work + message) before sending
    char combined_msg[BUFFER_SIZE];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    snprintf(combined_msg, sizeof(combined_msg), "%s:%s", pow, message);

    char buffer[BUFFER_SIZE];

    // Set up the client socket and server address
    int client_socket;
    struct sockaddr_in server_addr;

    // Create a socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Could not create socket");
        exit(EXIT_FAILURE);
    }

    // Set up the server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the server
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // Send the message with proof-of-work
    if (send(client_socket, combined_msg, strlen(combined_msg), 0) < 0) {
        perror("Send failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // Receive the server's response
    ssize_t num_bytes = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (num_bytes < 0) {
        perror("Error receiving data from server");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // Null-terminate and print the response
    buffer[num_bytes] = '\0';
    printf("Server response: %s", buffer);

    close(client_socket);
    return 0;
}
