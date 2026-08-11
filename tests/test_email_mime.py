from email.message import EmailMessage
from dftk.primitives.email_auth import mime_inventory


def test_mime_inventory_attachment(tmp_path):
    m=EmailMessage(); m['From']='a@example.com'; m['To']='b@example.com'; m['Subject']='x'; m.set_content('hello'); m.add_attachment(b'abc',maintype='application',subtype='octet-stream',filename='x.bin')
    p=tmp_path/'m.eml'; p.write_bytes(m.as_bytes())
    obs=mime_inventory(str(p)); assert len(obs.facts['attachments'])==1; assert obs.facts['attachments'][0]['filename']=='x.bin'; assert len(obs.facts['attachments'][0]['sha256'])==64
