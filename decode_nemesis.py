#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def decode_nemesis_debug(file_path):
    """
    Décode le fichier nemesis.debug en utilisant la même clé XOR que le code C++
    """
    key = "gDjXkAP0Aw"
    key_len = len(key)
    
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted = bytearray()
        for i, byte in enumerate(encrypted_data):
            decrypted.append(byte ^ ord(key[i % key_len]))
        
        decoded_text = decrypted.decode('utf-8', errors='ignore').rstrip('\x00')
        return decoded_text
        
    except FileNotFoundError:
        return "Fichier nemesis.debug non trouvé"
    except Exception as e:
        return f"Erreur lors du décodage: {e}"

if __name__ == "__main__":
    import sys
    
    file_path = sys.argv[1] if len(sys.argv) > 1 else "nemesis.debug"
    
    result = decode_nemesis_debug(file_path)
    print(f"Contenu décodé: {result}")
