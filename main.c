/*
 * ECE-GY 9453
 * Homework 3 | AES Scan Attack
 * Michael Mattioli (omm226) and Artem Shlepchenko (as14836)
 */

#include <stdio.h>
#include "aes.h"

int main() {
	// Supplied key is combination of Michael's (N18358082) and Artem's (N12747752) N
	// numbers so it's 18358082 12747752 18358082 12747752.
	uchar key[16] = { 0x18,0x35,0x80,0x82,0x12,0x74,0x77,0x52,0x18,0x35,0x80,0x82,0x12,0x74,0x77,0x52 };
	int Nos_of_plaintext = 0;

	Nos_of_plaintext = key_guess(key);
	printf("No. of plaintexts: %d\n", Nos_of_plaintext);

	return 0;
}

/* function to clear the plain text */
void plaintext_clr(uchar plaintext[]) {
	for (int i = 0; i<16; i++) {
		plaintext[i] = 0x00;
	}
}

/* function to calculate the number of ones */
int NOS_ones(uchar x[]) {

	int ones[16] = { 0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4 };
	int sum_ones = 0;
	for (int i = 0; i< 16; i++) {
		sum_ones += ones[x[i] & 0x0f] + ones[(x[i] & 0xf0) >> 4];

	}
	return sum_ones;
}

/* let's find that key! */
int key_guess(uchar key[]) {
	uchar key_stolen[16][2];
	int key_notfound = 0;
	uchar plaintext[16] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	uchar ciphertext[16] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	uchar f1[16] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	uchar f2[16] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	uchar f[16], b1 = 0, b0 = 0, a1 = 0, a0 = 0;
	int Nos_ones = 0, t = 0, nos_of_ones = 0;
	uint key_schedule[60], idx;
	int Nos_of_plaintext = 0;

	// First set of test vectors.
	KeyExpansion(key, key_schedule, 128);
	aes_encrypt(plaintext, ciphertext, key_schedule, 128);
	printf("Original Key\n");
	for (idx = 0; idx < 16; idx++) {
		printf("%02x", key[idx]);
	}
	printf("\n");

	for (int i = 0; i<16; i++) {
		key_notfound = 1;
		plaintext_clr(plaintext);
		t = 0;
		while (key_notfound) {
			a0 = 2 * t; a1 = 2 * t + 1;
			plaintext[i] = a0;

			Nos_of_plaintext++;

            printf("Plaintext for f1: ");
            for (idx = 0; idx < 16; idx++) {
                printf("%02x", plaintext[idx]);
            }
            printf("\n");

			aes_encrypt_round1(plaintext, f1, key_schedule, 128);
			plaintext[i] = a1;

			printf("Plaintext for f2: ");
            for (idx = 0; idx < 16; idx++) {
                printf("%02x", plaintext[idx]);
            }
            printf("\n");

			aes_encrypt_round1(plaintext, f2, key_schedule, 128);

			for (idx = 0; idx < 16; idx++) {
				f[idx] = f1[idx] ^ f2[idx];
			}

			Nos_ones = NOS_ones(f);
			key_notfound = 0;
			if (Nos_ones == 9) { // from table in paper
				b0 = 0xE2; b1 = 0xE3; // 226, 227
			}
			else if (Nos_ones == 12) {
				b0 = 0xF2; b1 = 0xF3; // 242, 243
			}
			else if (Nos_ones == 23) {
				b0 = 0x7A; b1 = 0x7B; // 122, 123
			}
			else if (Nos_ones == 24) {
				b0 = 0x82; b1 = 0x83; // 130, 131
			}
			else {
				key_notfound = 1;
			}

			if (t >= 127) {
				key_notfound = 0;
				printf("key not found :(");
			}
			else {
				t++;
			}

			printf("a0: %02x, a1: %02x, b0: %02x, b1: %02x\n", a0, a1, b0, b1);

		}
		key_stolen[i][0] = a0 ^ b0;
		key_stolen[i][1] = a0 ^ b1;
		printf("RK0,1: %02x, RK0,2: %02x\n", key_stolen[i][0], key_stolen[i][1]);

	}

	key_notfound = 1;

	/* Key guesssing is done? */
	static int inc = 0, inc1;
	int index[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	/* Applies all permutation and combination of the Keys */
	while (key_notfound) {
		inc1 = inc;
		for (int i = 0; i < 16; i++) {
			index[i] = inc1 % 2;
			inc1 = inc1 / 2;
		}
		inc = inc + 1;

		key[0] = key_stolen[0][index[0]];
		key[1] = key_stolen[1][index[1]];
		key[2] = key_stolen[2][index[2]];
		key[3] = key_stolen[3][index[3]];
		key[4] = key_stolen[4][index[4]];
		key[5] = key_stolen[5][index[5]];
		key[6] = key_stolen[6][index[6]];
		key[7] = key_stolen[7][index[7]];
		key[8] = key_stolen[8][index[8]];
		key[9] = key_stolen[9][index[9]];
		key[10] = key_stolen[10][index[10]];
		key[11] = key_stolen[11][index[11]];
		key[12] = key_stolen[12][index[12]];
		key[13] = key_stolen[13][index[13]];
		key[14] = key_stolen[14][index[14]];
		key[15] = key_stolen[15][index[15]];

		printf("Trying key: ");
        for (idx = 0; idx < 16; idx++) {
            printf("%02x", key[idx]);
        }
        printf("\n");

		KeyExpansion(key, key_schedule, 128);
		plaintext_clr(plaintext);
		aes_encrypt(plaintext, f, key_schedule, 128);

		for (idx = 0; idx < 16; idx++) {
			f[idx] = f[idx] ^ ciphertext[idx];
		}
		nos_of_ones = NOS_ones(f);
		if (nos_of_ones == 0) {
			key_notfound = 0;
			printf("Key Found!!!\n");
			for (idx = 0; idx < 16; idx++) {
				printf("%02x", key[idx]);
			}
			printf("\n");
		}
	}
	return Nos_of_plaintext;
}