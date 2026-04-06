from se_module import sign_data
data = open('data.txt', 'rb').read()
sig = sign_data(data)
open('sig.bin', 'wb').write(sig)
print('Signature sauvegardee dans sig.bin')
print ('Taille signature:', len(sig), 'bytes')
