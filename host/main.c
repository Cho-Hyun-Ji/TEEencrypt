/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>
#define MAX_FILE_SIZE 64
#define MAX_KEY_SIZE 26
#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char buffer[MAX_FILE_SIZE] = {0, };
	char output_buffer[MAX_FILE_SIZE] = {0, };
	char clear[RSA_MAX_PLAIN_LEN_1024] = {0, };
	char ciph[RSA_CIPHER_LEN_1024] = {0, };
	FILE* fp;
		

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = buffer;
	op.params[0].tmpref.size = MAX_FILE_SIZE;
	

	
	// receive encryption input
	if(!strcmp(argv[1], "-e")) {

		// ceasar cipher
		if(!strcmp(argv[3],"Caesar")) {
			fp = fopen(argv[2], "r");
			fread(buffer, 1, MAX_FILE_SIZE, fp);
			memcpy(op.params[0].tmpref.buffer, buffer, MAX_FILE_SIZE);
			fclose(fp);
			
			// make ran_key
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
				 &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);

			// get enc_value
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);
			memcpy(output_buffer, op.params[0].tmpref.buffer, MAX_FILE_SIZE);
			
			// get key
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
				 &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);
			uint32_t enc_key = op.params[1].value.a;


			// write file
			fp = fopen("ciphertext.txt","w");
			fputs(output_buffer, fp);
			fclose(fp);

			fp = fopen("encryptedkey.txt","w");
			fprintf(fp, "%d", enc_key);
			fclose(fp);

		// RSA cipher
		} else if(!strcmp(argv[3],"RSA")) {
			op.params[2].tmpref.buffer = clear;
			op.params[2].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
			op.params[3].tmpref.buffer = ciph;
			op.params[3].tmpref.size = RSA_CIPHER_LEN_1024;

			fp = fopen(argv[2], "r");
			fread(clear, 1, RSA_MAX_PLAIN_LEN_1024, fp);
			memcpy(op.params[2].tmpref.buffer, clear, RSA_MAX_PLAIN_LEN_1024);
			fclose(fp);

			// gen key
			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_GENKEYS, NULL, NULL);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
			// printf("\n=========== Keys already generated. ==========\n");
			
			// rsa encrypt
			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_ENCRYPT, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n", res, err_origin);
			memcpy(ciph, op.params[3].tmpref.buffer, RSA_CIPHER_LEN_1024);
			// printf("\nThe text sent was encrypted: %s\n", ciph);
			// write file
			fp = fopen("RSAciphertext.txt","w");
			fputs(ciph, fp);
			fclose(fp);

		} else {
			printf("Enter the encryption method! Ceasar or RSA");			
		}

	// receive decryption input
	}else if(!strcmp(argv[1], "-d")) {
		// cipherfile read
		fp = fopen(argv[2], "r");
		if(fp != NULL) {
			fread(buffer, 1, MAX_FILE_SIZE, fp);
			memcpy(op.params[0].tmpref.buffer, buffer, MAX_FILE_SIZE);
		}else {
			printf("cipherfile input error!");		
		}
		fclose(fp);
		
		// keyfile read
		uint32_t enc_key = 0;
		fp = fopen(argv[3], "r");
		if(fp != NULL) {
			fscanf(fp, "%d", &enc_key);
			op.params[1].value.a = enc_key;
		}else {
			printf("keyfile input error!");		
		}
		fclose(fp);
		// decrypt
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		
		memcpy(buffer, op.params[0].tmpref.buffer, MAX_FILE_SIZE);
		// write file
		fp = fopen("decryptedtext.txt","w");
		fputs(buffer, fp);
		fclose(fp);
		
	}else {
		printf("input error!\n");	
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
