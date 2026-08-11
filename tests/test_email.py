from dftk.primitives.email_auth import auth_analyze

def test_header_difference_is_not_spoof_verdict(tmp_path):
    p=tmp_path/'m.eml'; p.write_bytes(b'From: Alice <alice@example.com>\r\nSender: relay@sender.example\r\nReply-To: help@example.net\r\nSubject: hi\r\n\r\nbody')
    obs=auth_analyze(str(p))
    assert obs.facts['verdict']=='undetermined_offline'
    assert any(x['type']=='from_sender_differ' for x in obs.facts['header_relationships'])
