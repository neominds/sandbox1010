#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define RSA_SERVER_CERT "server3.crt"
#define RSA_SERVER_KEY  "server3.key"
#define SSL_TRACE

/*
   EnvelopedData ::= SEQUENCE {
     version Version,
     recipientInfos RecipientInfos,
     encryptedContentInfo EncryptedContentInfo }

   RecipientInfos ::= SET OF RecipientInfo

   EncryptedContentInfo ::= SEQUENCE {
     contentType ContentType,
     contentEncryptionAlgorithm
       ContentEncryptionAlgorithmIdentifier,
     encryptedContent
       [0] IMPLICIT EncryptedContent OPTIONAL }

   EncryptedContent ::= OCTET STRING

*/


int cve_1790app(int arg0, int arg1, int arg2, int arg3, int arg4, int arg5,
		int arg6, int arg7, int arg8, int arg9, int arg10)
{
	int encrypt,flags_nm=0,out_size=0;
	PKCS7 *pkcs7;
	const EVP_CIPHER *cipher;
	STACK_OF(X509) *certs;
	X509 *cert;
	EVP_PKEY *pkey;
	FILE *fp;
	BIO *pkcs7_bio, *in, *out,*mem,*out_membio;
	X509 *tmp;
	char *out_temp,*nm_data,*nm_temp=NULL;
	int i=0;char buf[100];
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
		

	if (!(out = BIO_new_fp(stdout, BIO_NOCLOSE)))
	{
		fprintf(stderr, "Error creating output BIO objects\n");
		goto err;
	}
	
	//Encrypt first
	{
		/* choose cipher and read in all certificates */
		cipher = EVP_des_ede3_cbc();
		certs = sk_X509_new_null();
		
		if (!(fp = fopen(RSA_SERVER_CERT, "r")) ||!(tmp = PEM_read_X509(fp, NULL, NULL, NULL)))
			{
				printf("Error reading encryption certificate	in %s\n",	RSA_SERVER_CERT);
				goto err;
			}
			sk_X509_push(certs, tmp);
			fclose(fp);			
		}

		mem = BIO_new(BIO_s_mem());
		//nm_data="hi";
		BIO_puts(mem, "Hello World\n");
		//BIO_puts(mem, ""); //for actual test
		if (!(pkcs7 = PKCS7_encrypt(certs, mem, cipher, PKCS7_TEXT))) //text type
		{
			printf("Error making the PKCS#7 object\n");
			goto err;
		}
		
		if (SMIME_write_PKCS7(out, pkcs7, mem, 0) != 1)
		{
			printf("Error writing the S/MIME data\n");
			goto err;
		}
	//}
	//Decrypt next
	{
		if (!(fp = fopen(RSA_SERVER_KEY, "r")) ||!(pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)))
		{
			printf("Error reading private key in %s\n",RSA_SERVER_KEY);
			goto err;
		}
		fclose(fp);
		
		if (!(fp = fopen(RSA_SERVER_CERT, "r")) ||!(cert = PEM_read_X509(fp, NULL, NULL, NULL)))
		{
			printf( "Error reading decryption certificate in %s\n",	RSA_SERVER_CERT);
			goto err;
		}
		fclose(fp);
		
		/*if (!(pkcs7 = SMIME_read_PKCS7(in, &pkcs7_bio)))
		{
			printf("Error reading PKCS#7 object\n");
			goto err;
		}*/
		out_membio = BIO_new(BIO_s_mem());
		
		printf("Invoking PKCS7_decrypt function..\n");
		if (PKCS7_decrypt(pkcs7, pkey, cert, out_membio, flags_nm) != 1)
		//if (PKCS7_decrypt(pkcs7, pkey, cert, out, flags_nm) != 1)
		{
			printf("Error decrypting PKCS#7 object\n");
			goto err;
		}
	}
	//printf("nm_data=%s\n",(char *)0);
		//	nm_temp=(char *)malloc(15);
			i = BIO_read(out_membio, buf, sizeof(buf));
			printf("value of i =%d\n",i);
			//BIO_write(out_membio, buf, i);
			printf("data=%s",buf);
	
	//printf("out_size=%d\n",out_size);
	BIO_free(mem);
	//BIO_free(nm_mem);
	return 0;
err:
	BIO_free(mem);
	//BIO_free(nm_mem);
	return -1;
}
