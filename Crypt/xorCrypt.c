// XOR file and outputs to xoredToEmbed.bin

#include <stdio.h>
#include <Windows.h>
#define OUTPUT_FILE "xoredToEmbed.bin"


void rdx(PBYTE enc, int sz) {

    for (int i = 0; i < sz; i++) {
        enc[i] = enc[i] - 2;
        enc[i] = enc[i] ^ 0x53;
    }
}

// Main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input file>\n", argv[0]);
        return 1;
    }


 

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

    rdx(input_data, input_size);




    // Write encrypted data (ciphertext)
    fwrite(input_data, 1, input_size, output_file);

    // Cleanup
    fclose(output_file);
    free(input_data);

    printf("Encryption successful. Key and ciphertext written to %s\n", OUTPUT_FILE);
    return 0;
}


