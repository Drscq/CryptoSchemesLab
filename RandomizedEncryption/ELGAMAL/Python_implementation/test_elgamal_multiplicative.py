from elgamal_encryption import ElGamalEncryption

def test_elgamal_multiplicative_homomorphism():
    # Initialize the ElGamal encryption system
    elgamal = ElGamalEncryption(bit_length=512)
    
    # Generate keys
    private_key, public_key = elgamal.generate_keys()
    
    # Define two messages
    message1 = 123789
    message2 = 456
    
    # Encrypt the messages
    ciphertext1 = elgamal.encrypt(public_key, message1)
    ciphertext2 = elgamal.encrypt(public_key, message2)
    
    # Multiply the ciphertexts homomorphically
    c1_combined = (ciphertext1[0] * ciphertext2[0]) % elgamal.p
    c2_combined = (ciphertext1[1] * ciphertext2[1]) % elgamal.p
    combined_ciphertext = (c1_combined, c2_combined)
    elgamal.randomize_ciphertext(public_key, combined_ciphertext)
    elgamal.randomize_ciphertext(public_key, combined_ciphertext)
    # Decrypt the combined ciphertext
    decrypted_combined = elgamal.decrypt(private_key, combined_ciphertext)
    print(f"Decrypted combined message: {decrypted_combined}")
    # Verify the multiplicative homomorphic property
    expected_product = (message1 * message2) % elgamal.p
    assert decrypted_combined == expected_product, "Multiplicative homomorphism failed"
    
    print("Test passed: Multiplicative homomorphism verified.")

# Run the test
test_elgamal_multiplicative_homomorphism()
