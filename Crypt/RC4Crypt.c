// Uses R4C encryption and outputs file where the 16 first bytes are the key and the rest is the encrypted payload


#include <Windows.h>
#include <ntsecapi.h>
#include <stdio.h>
#include <stdlib.h>

#define KEY_SIZE 16
#define OUTPUT_FILE "r4cToEmbed.bin"

struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} _data, _key;

typedef NTSTATUS(WINAPI* fnSystemFunction033)(
    struct ustring* memoryRegion,
    struct ustring* keyPointer);

BOOL dec(unsigned char* payload, DWORD len_payload, unsigned char* key, DWORD len_key) {


	fnSystemFunction033 SystemFunction033 = (fnSystemFunction033)GetProcAddress(LoadLibrary(L"advapi32"), "SystemFunction033");
	if (!SystemFunction033) {
        printf("[-] Error resolving function\n");
		return FALSE;
	}

	_data.Buffer = (PUCHAR)payload;
	_data.Length = len_payload;

	_key.Buffer = (PUCHAR)key;
	_key.Length = len_key;


	SystemFunction033(&_data, &_key);

    return TRUE;

}


void generate_random_key(unsigned char* key, size_t length) {
    if (!RtlGenRandom(key, length)) {
        fprintf(stderr, "Failed to generate random key.\n");
        exit(EXIT_FAILURE);
    }
}

// Main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input file>\n", argv[0]);
        return 1;
    }


    unsigned char key[KEY_SIZE];
    generate_random_key(key, KEY_SIZE);
    for (int i = 0; i < KEY_SIZE; i++) {

        printf("%x", key[i]);
    }
    printf("\n");

    // Open the input file
    FILE* input_file = fopen(argv[1], "rb");
    if (!input_file) {
        perror("Error opening input file");
        return 1;
    }

    // Find the size of the input file
    fseek(input_file, 0, SEEK_END);
    size_t input_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    unsigned char* input_data = malloc(input_size);
    if (!input_data) {
        perror("Memory allocation failed");
        fclose(input_file);
        return 1;
    }

    // Read input file data into buffer
    fread(input_data, 1, input_size, input_file);
    fclose(input_file);



    // Write key and ciphertext to output file
    FILE* output_file = fopen(OUTPUT_FILE, "wb");
    if (!output_file) {
        perror("Error creating output file");
        free(input_data);
        return 1;
    }

    if (!dec(input_data, input_size, key, KEY_SIZE)) {
        printf("[-] Error encrypting data\n");
        return -1;
    }

    // Write  key
    fwrite(key, 1, KEY_SIZE, output_file);

    // Write encrypted data (ciphertext)
    fwrite(_data.Buffer, 1, _data.Length, output_file);

    // Cleanup
    fclose(output_file);
    free(input_data);

    printf("Encryption successful. Key and ciphertext written to %s\n", OUTPUT_FILE);
    return 0;
}



