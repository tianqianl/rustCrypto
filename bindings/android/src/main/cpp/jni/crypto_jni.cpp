#include <jni.h>
#include <string.h>
#include "crypto.h"
#include <android/log.h>

#define LOG_TAG "CryptoLib"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {

JNIEXPORT jobject JNICALL
Java_com_crypto_lib_CryptoLib_generateRSAKeyPair(JNIEnv *env, jobject thiz, jint bits) {
    CKeyPair* cKeyPair = crypto_generate_rsa_keypair(bits);
    
    if (cKeyPair == NULL) {
        LOGE("Failed to generate RSA key pair");
        return NULL;
    }
    
    jclass keyPairClass = env->FindClass("com/crypto/lib/KeyPair");
    if (keyPairClass == NULL) {
        LOGE("Failed to find KeyPair class");
        crypto_free_keypair(cKeyPair);
        return NULL;
    }
    
    jmethodID constructor = env->GetMethodID(keyPairClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;)V");
    if (constructor == NULL) {
        LOGE("Failed to find KeyPair constructor");
        crypto_free_keypair(cKeyPair);
        return NULL;
    }
    
    jstring publicKey = env->NewStringUTF(cKeyPair->public_key);
    jstring privateKey = env->NewStringUTF(cKeyPair->private_key);
    
    jobject result = env->NewObject(keyPairClass, constructor, publicKey, privateKey);
    
    crypto_free_keypair(cKeyPair);
    
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_crypto_lib_CryptoLib_rsaEncrypt(JNIEnv *env, jobject thiz, jstring publicKey, jbyteArray plaintext) {
    if (publicKey == NULL || plaintext == NULL) {
        LOGE("Invalid parameters for RSA encryption");
        return NULL;
    }
    
    const char* publicKeyStr = env->GetStringUTFChars(publicKey, NULL);
    jbyte* plaintextBytes = env->GetByteArrayElements(plaintext, NULL);
    jsize plaintextLen = env->GetArrayLength(plaintext);
    
    size_t outLen = 0;
    CByteArray* cResult = crypto_rsa_encrypt(
        publicKeyStr,
        (unsigned char*)plaintextBytes,
        plaintextLen,
        &outLen
    );
    
    env->ReleaseStringUTFChars(publicKey, publicKeyStr);
    env->ReleaseByteArrayElements(plaintext, plaintextBytes, JNI_ABORT);
    
    if (cResult == NULL) {
        LOGE("RSA encryption failed");
        return NULL;
    }
    
    jbyteArray result = env->NewByteArray(outLen);
    env->SetByteArrayRegion(result, 0, outLen, (jbyte*)cResult->data);
    
    crypto_free_byte_array(cResult);
    
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_crypto_lib_CryptoLib_rsaDecrypt(JNIEnv *env, jobject thiz, jstring privateKey, jbyteArray ciphertext) {
    if (privateKey == NULL || ciphertext == NULL) {
        LOGE("Invalid parameters for RSA decryption");
        return NULL;
    }
    
    const char* privateKeyStr = env->GetStringUTFChars(privateKey, NULL);
    jbyte* ciphertextBytes = env->GetByteArrayElements(ciphertext, NULL);
    jsize ciphertextLen = env->GetArrayLength(ciphertext);
    
    size_t outLen = 0;
    CByteArray* cResult = crypto_rsa_decrypt(
        privateKeyStr,
        (unsigned char*)ciphertextBytes,
        ciphertextLen,
        &outLen
    );
    
    env->ReleaseStringUTFChars(privateKey, privateKeyStr);
    env->ReleaseByteArrayElements(ciphertext, ciphertextBytes, JNI_ABORT);
    
    if (cResult == NULL) {
        LOGE("RSA decryption failed");
        return NULL;
    }
    
    jbyteArray result = env->NewByteArray(outLen);
    env->SetByteArrayRegion(result, 0, outLen, (jbyte*)cResult->data);
    
    crypto_free_byte_array(cResult);
    
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_crypto_lib_CryptoLib_generateAESKey(JNIEnv *env, jobject thiz) {
    size_t outLen = 0;
    CByteArray* cResult = crypto_generate_aes_key(&outLen);
    
    if (cResult == NULL) {
        LOGE("Failed to generate AES key");
        return NULL;
    }
    
    jbyteArray result = env->NewByteArray(outLen);
    env->SetByteArrayRegion(result, 0, outLen, (jbyte*)cResult->data);
    
    crypto_free_byte_array(cResult);
    
    return result;
}

JNIEXPORT jobject JNICALL
Java_com_crypto_lib_CryptoLib_aesGCMEncrypt(JNIEnv *env, jobject thiz, jbyteArray key, jbyteArray plaintext) {
    if (key == NULL || plaintext == NULL) {
        LOGE("Invalid parameters for AES-GCM encryption");
        return NULL;
    }
    
    jbyte* keyBytes = env->GetByteArrayElements(key, NULL);
    jbyte* plaintextBytes = env->GetByteArrayElements(plaintext, NULL);
    jsize keyLen = env->GetArrayLength(key);
    jsize plaintextLen = env->GetArrayLength(plaintext);
    
    CEncryptedData* cResult = crypto_aes_gcm_encrypt(
        (unsigned char*)keyBytes,
        keyLen,
        (unsigned char*)plaintextBytes,
        plaintextLen
    );
    
    env->ReleaseByteArrayElements(key, keyBytes, JNI_ABORT);
    env->ReleaseByteArrayElements(plaintext, plaintextBytes, JNI_ABORT);
    
    if (cResult == NULL) {
        LOGE("AES-GCM encryption failed");
        return NULL;
    }
    
    jclass encryptedDataClass = env->FindClass("com/crypto/lib/EncryptedData");
    if (encryptedDataClass == NULL) {
        LOGE("Failed to find EncryptedData class");
        crypto_free_encrypted_data(cResult);
        return NULL;
    }
    
    jmethodID constructor = env->GetMethodID(encryptedDataClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;)V");
    if (constructor == NULL) {
        LOGE("Failed to find EncryptedData constructor");
        crypto_free_encrypted_data(cResult);
        return NULL;
    }

    jstring ciphertext = env->NewStringUTF(cResult->ciphertext);
    jstring nonce = env->NewStringUTF(cResult->nonce);

    jobject result = env->NewObject(encryptedDataClass, constructor, ciphertext, nonce);
    
    crypto_free_encrypted_data(cResult);
    
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_crypto_lib_CryptoLib_aesGCMDecrypt(JNIEnv *env, jobject thiz, jbyteArray key, jobject encryptedData) {
    if (key == NULL || encryptedData == NULL) {
        LOGE("Invalid parameters for AES-GCM decryption");
        return NULL;
    }
    
    jclass encryptedDataClass = env->GetObjectClass(encryptedData);

    jfieldID ciphertextField = env->GetFieldID(encryptedDataClass, "ciphertext", "Ljava/lang/String;");
    jfieldID nonceField = env->GetFieldID(encryptedDataClass, "nonce", "Ljava/lang/String;");

    jstring ciphertext = (jstring)env->GetObjectField(encryptedData, ciphertextField);
    jstring nonce = (jstring)env->GetObjectField(encryptedData, nonceField);

    const char* ciphertextStr = env->GetStringUTFChars(ciphertext, NULL);
    const char* nonceStr = env->GetStringUTFChars(nonce, NULL);

    CEncryptedData cEncryptedData;
    cEncryptedData.ciphertext = (char*)ciphertextStr;
    cEncryptedData.nonce = (char*)nonceStr;
    
    jbyte* keyBytes = env->GetByteArrayElements(key, NULL);
    jsize keyLen = env->GetArrayLength(key);
    
    size_t outLen = 0;
    CByteArray* cResult = crypto_aes_gcm_decrypt(
        (unsigned char*)keyBytes,
        keyLen,
        &cEncryptedData,
        &outLen
    );
    
    env->ReleaseByteArrayElements(key, keyBytes, JNI_ABORT);
    env->ReleaseStringUTFChars(ciphertext, ciphertextStr);
    env->ReleaseStringUTFChars(nonce, nonceStr);
    env->ReleaseStringUTFChars(tag, tagStr);
    
    if (cResult == NULL) {
        LOGE("AES-GCM decryption failed");
        return NULL;
    }
    
    jbyteArray result = env->NewByteArray(outLen);
    env->SetByteArrayRegion(result, 0, outLen, (jbyte*)cResult->data);
    
    crypto_free_byte_array(cResult);
    
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_crypto_lib_CryptoLib_getVersion(JNIEnv *env, jobject thiz) {
    const char* version = crypto_get_version();
    return env->NewStringUTF(version);
}

}