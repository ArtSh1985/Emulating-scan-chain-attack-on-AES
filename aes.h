/*
 * ECE-GY 9453
 * Homework 3 | AES Scan Attack
 * Michael Mattioli (omm226) and Artem Shlepchenko (as14836)
 */

#include <stdio.h>
#define uchar unsigned char // 8-bit byte
#define uint unsigned long // 32-bit word


#ifndef AES_H
#define AES_H

void KeyExpansion(uchar key[], uint w[], int keysize);
void aes_encrypt_round1(uchar in[], uchar out[], uint key[], int keysize);
void aes_encrypt(uchar in[], uchar out[], uint key[], int keysize);
void plaintext_clr(uchar plaintext[]);
int NOS_ones(uchar x[]);
int key_guess(uchar key[]);


#endif