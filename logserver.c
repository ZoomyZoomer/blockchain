#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <time.h>

#define MAX_MSG 1024
#define LOG_FILE "log.txt"
#define LOGHEAD_FILE "loghead.txt"
#define LEADING_ZEROS 20

// Function to validate proof-of-work (20 leading zero bits)
int validate_pow(const unsigned char *hash) {
    int zero_bits = 0;
    
    // Loop through each byte of the hash until we reach 20 zero bits or a non-zero bit
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

// Function to get the current timestamp
void get_timestamp(char *timestamp, size_t size) {
    time_t now = time(NULL);
    strftime(timestamp, size, "%Y-%m-%d %H:%M:%S", localtime(&now));
}

// Function to read the last hash from loghead.txt
int read_last_hash(char *last_hash, size_t size) {
    FILE *file = fopen(LOGHEAD_FILE, "r");
    if (!file) return 0;  // File doesn't exist
    fgets(last_hash, size, file);
    fclose(file);
    return 1;
}

// Function to write the new hash to loghead.txt
void write_new_hash(const char *hash) {
    FILE *file = fopen(LOGHEAD_FILE, "w");
    if (file) {
        fprintf(file, "%s", hash);
        fclose(file);
    }
}

void print_hash(unsigned char *hash) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);  // Print each byte in hexadecimal format
    }
    printf("\n");
}

// Function to encode a hash to base64 and return the last 24 characters
void base64_encode_last_24(unsigned char *hash, char *encoded) {
    unsigned char base64_encoded[EVP_ENCODE_LENGTH(SHA256_DIGEST_LENGTH)];
    EVP_EncodeBlock(base64_encoded, hash, SHA256_DIGEST_LENGTH);
    
    // Copy the last 24 characters of the base64-encoded string
    strncpy(encoded, (char*)base64_encoded + strlen((char*)base64_encoded) - 24, 24);
    encoded[24] = '\0';  // Null-terminate the string
}

void handle_client(int client_socket) {
    char msg[MAX_MSG], log_entry[MAX_MSG], last_hash[64];
    char *pow_sep, *log_message;
    FILE *log_file;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char hash_base64[25];  // To store the shortened base64 hash
    char timestamp[32];

    // Read data from the client
    ssize_t num_bytes = recv(client_socket, msg, MAX_MSG - 1, 0);
    if (num_bytes < 0) {
        perror("Error reading from socket");
        close(client_socket);
        return;
    }
    msg[num_bytes] = '\0';  // Null-terminate the string

    // Hash the message for PoW validation and check if it’s valid
    SHA256((unsigned char *)msg, strlen(msg), hash);
    if (!validate_pow(hash)) {  // Validate the proof-of-work using the hash
        const char *error_msg = "Invalid proof-of-work\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
        close(client_socket);
        return;
    }

    // Split the message to get PoW and log message
    pow_sep = strchr(msg, ':');
    if (!pow_sep) {
        perror("Invalid message format");
        close(client_socket);
        return;
    }
    *pow_sep = '\0';
    log_message = pow_sep + 1;

    // Handle missing loghead.txt and log.txt based on rules
    if (access(LOG_FILE, F_OK) == -1) {
        // If log.txt doesn't exist, create it and set the hash to 'start'
        strcpy(last_hash, "start");

        // Create or overwrite log.txt with this entry
        log_file = fopen(LOG_FILE, "w");
        if (!log_file) {
            perror("Error creating log file");
            close(client_socket);
            return;
        }
        // Create the first log entry
        get_timestamp(timestamp, sizeof(timestamp));
        snprintf(log_entry, sizeof(log_entry), "%s - %s %s", timestamp, last_hash, log_message);
        fprintf(log_file, "%s\n", log_entry);
        fclose(log_file);

        unsigned char encodeHash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char *)log_entry, strlen(log_entry), encodeHash);
        
        base64_encode_last_24(encodeHash, hash_base64); // Using the fixed func
        write_new_hash(hash_base64); 

        const char *response_msg = "ok\n";
        send(client_socket, response_msg, strlen(response_msg), 0);
        close(client_socket);
        return;
    } else {
        // log.txt exists, check for loghead.txt
        if (!read_last_hash(last_hash, sizeof(last_hash))) {
            const char *error_msg = "Error: Missing loghead.txt\n";
            send(client_socket, error_msg, strlen(error_msg), 0);
            close(client_socket);
            return;
        }
    }

    // For subsequent log entries, create the log entry with a new hash
    get_timestamp(timestamp, sizeof(timestamp));
    snprintf(log_entry, sizeof(log_entry), "%s - %s %s", timestamp, last_hash, log_message);

    // Compute the new base64-encoded hash for the log entry (without newline)
    unsigned char encodeHash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)log_entry, strlen(log_entry), encodeHash);

    base64_encode_last_24(encodeHash, hash_base64); // Using the fixed function for base64 encoding
    write_new_hash(hash_base64);  // Update loghead.txt with the new hash

    // Append the log entry to log.txt
    log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        perror("Error opening log file");
        close(client_socket);
        return;
    }
    fprintf(log_file, "%s\n", log_entry);
    fclose(log_file);

    // Send confirmation message back to the client
    const char *response_msg = "ok\n";
    send(client_socket, response_msg, strlen(response_msg), 0);
    close(client_socket);
}


int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // Create the server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Could not create socket");
        exit(EXIT_FAILURE);
    }

    // Bind the server to an available port
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = 0;  // System assigns any available port

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Get the assigned port number and print it
    socklen_t len = sizeof(server_addr);
    if (getsockname(server_socket, (struct sockaddr*)&server_addr, &len) == -1) {
        perror("getsockname failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    int port = ntohs(server_addr.sin_port);
    printf("Server listening on port: %d\n", port);

    // Start listening for connections
    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Continuously accept and handle clients
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }

        printf("Client connected\n");
        handle_client(client_socket);
    }

    close(server_socket);
    return 0;
}
