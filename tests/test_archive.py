import zipfile
from dftk.primitives.files import archive_inventory

def test_zip_inventory(tmp_path):
    p=tmp_path/'a.zip'
    with zipfile.ZipFile(p,'w') as z:z.writestr('x.txt','abc')
    obs=archive_inventory(str(p)); assert obs.facts['format']=='zip'; assert obs.facts['members'][0]['name']=='x.txt'
