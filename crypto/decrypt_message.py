def decrypt_message(key: bytes, ciphertext: bytes, iv: bytes, tag: bytes) -> str:
    """Decrypts a message encrypted with AES-GCM using the provided key."""
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode()
