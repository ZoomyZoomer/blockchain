#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <time.h>

#define MAX_LINE 1024
#define LOG_FILE "log.txt"
#define LOGHEAD_FILE "loghead.txt"

// Function to base64 encode the last 24 characters of a hash
void base64_encode_last_24(unsigned char *hash, char *encoded) {
    unsigned char base64_encoded[EVP_ENCODE_LENGTH(SHA256_DIGEST_LENGTH)];
    EVP_EncodeBlock(base64_encoded, hash, SHA256_DIGEST_LENGTH);
    
    // Copy the last 24 characters of the base64-encoded string
    strncpy(encoded, (char*)base64_encoded + strlen((char*)base64_encoded) - 24, 24);
    encoded[24] = '\0';  // Null-terminate the string
}

// Function to extract hash from the line after the third hyphen
char* extract_hash(char* line) {
    int hyphen_count = 0;
    char* token = strtok(line, "-");
    
    // We need to find the third hyphen, which will have the hash after it
    while (token != NULL) {
        hyphen_count++;
        if (hyphen_count == 3) {
            // The hash is after the third hyphen and right before the space
            return strtok(NULL, " ");  // Get the string before the next space
        }
        token = strtok(NULL, "-");
    }


    return NULL;  // If there are less than 3 hyphens
}

void remove_newline(char* line) {
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';  // Replace newline with null terminator
    }
}

// Function to validate the log file integrity
int validate_log() {
    FILE *log_file;
    char line[MAX_LINE], loghead_hash[64];
    
    // Check if the log file exists
    if (access(LOG_FILE, F_OK) == -1) {
        printf("failed: log file is missing\n");
        return 1;
    }
    
    // Check if the head file exists
    if (access(LOGHEAD_FILE, F_OK) == -1) {
        printf("failed: head pointer file is missing\n");
        return 1;
    }
    
    // Read the hash from loghead.txt
    FILE *head_file = fopen(LOGHEAD_FILE, "r");
    if (!head_file) {
        printf("failed: could not read loghead.txt\n");
        return 1;
    }
    fgets(loghead_hash, sizeof(loghead_hash), head_file);
    fclose(head_file);

    
    // Open the log file to validate the entries
    log_file = fopen(LOG_FILE, "r");
    if (!log_file) {
        printf("failed: could not open log file\n");
        return 1;
    }

    int counter = 1;
    unsigned char prev_hash[SHA256_DIGEST_LENGTH];

    while (fgets(line, sizeof(line), log_file)) {

        // Remove the newline character at the end
        remove_newline(line);

        char line_copy[MAX_LINE];
        strcpy(line_copy, line);  // or use strdup(line) for dynamic allocation

        // Reading first line
        if (counter == 1) {

            // Get the base64 of the first line
            unsigned char encodeHash[SHA256_DIGEST_LENGTH];
            SHA256((unsigned char *)line, strlen(line), encodeHash);

            // Store it in prev_hash
            base64_encode_last_24(encodeHash, prev_hash);

            // Check if the hash of the first line is 'start'
            char *hash = extract_hash(line);

            if (!hash) {
                printf("failed: Line %d has been modified!\n", counter);
                fclose(log_file);
                return 1;
            }

            if (strcmp(hash, "start") != 0) {
                printf("failed: first line does not start with expected 'start' hash\n");
                fclose(log_file);
                return 1;
            }

        } else {

            // First check if the extracted hash of this line matches the previous computed hash

            char *hash = extract_hash(line);

            if (!hash) {
                printf("failed: Line %d has been modified!\n", counter);
                fclose(log_file);
                return 1;
            }

            if (strcmp(prev_hash, hash) != 0) {
                printf("failed: Line %d is inconsistent with line %d's hash\n", counter - 1, counter);
                fclose(log_file);
                return 1;
            }

            // Compute the hash of the entire line and store it in prev_hash
            unsigned char encodeHash[SHA256_DIGEST_LENGTH];
            SHA256((unsigned char *)line_copy, strlen(line_copy), encodeHash);

            memset(prev_hash, 0, sizeof(prev_hash));
            base64_encode_last_24(encodeHash, prev_hash);

        }

        counter++;

    }

    // Lastly, compare prev_hash with the value in loghead.txt
    if (strcmp(prev_hash, loghead_hash) != 0) {
        printf("failed: Line %d hash does not match with loghead.txt\n", counter - 1);
        fclose(log_file);
        return 1;
    }
    
    // If we reach here, the log is valid
    printf("valid\n");
    fclose(log_file);
    return 0;
}

int main() {
    return validate_log();
}
