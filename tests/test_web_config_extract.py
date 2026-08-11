from dftk.primitives.linux import web_config_extract


def test_config_extract_redaction_and_explicit_values(tmp_path):
    p=tmp_path/'.env'; p.write_text('API_URL=https://api.example\nPASSWORD=secret123\n',encoding='utf-8')
    obs=web_config_extract(str(p)); vals={x['key']:x for x in obs.facts['values']}
    assert vals['API_URL']['value']=='https://api.example'; assert vals['PASSWORD']['value']=='<redacted>'
    obs2=web_config_extract(str(p),include_values=True); vals2={x['key']:x for x in obs2.facts['values']}; assert vals2['PASSWORD']['value']=='secret123'
