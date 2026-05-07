from se_module import SecureElement
with SecureElement() as se:
    data = open('data.txt', 'rb').read()
    sig = se.sign(data)
    open('sig.bin', 'wb').write(sig)
    print ('Signature sauvegardee dans sig.bin')
    print ('Taille signature:', len(sig), 'bytes')
