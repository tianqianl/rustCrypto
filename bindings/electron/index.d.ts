export interface KeyPair {
    publicKey: string;
    privateKey: string;
}

export interface EncryptedData {
    ciphertext: string;
    nonce: string;
}

export function generateRSAKeyPair(bits: number): KeyPair;
export function rsaEncrypt(publicKeyPem: string, plaintext: string): string;
export function rsaDecrypt(privateKeyPem: string, ciphertext: string): string;
export function generateAESKey(): string;
export function aesEncrypt(key: string, plaintext: string): EncryptedData;
export function aesDecrypt(key: string, encryptedData: EncryptedData): string;