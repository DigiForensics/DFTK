from dftk.primitives.crypto import load_wordlist,validate_bip39

def test_wordlist_is_complete():
    w=load_wordlist(); assert len(w)==2048; assert len(set(w))==2048

def test_known_vector_checksum():
    words=('abandon '*11+'about').split()
    v=validate_bip39(words); assert v['valid'] is True

def test_invalid_checksum():
    words=('abandon '*12).split()
    v=validate_bip39(words); assert v['valid'] is False; assert v['reason']=='checksum_mismatch'
