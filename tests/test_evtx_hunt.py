from dftk.primitives.windows import _evtx_event, _evtx_hunt


def test_evtx_hunt_normalizes_security_process_creation():
    xml = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>
      <TimeCreated SystemTime="2026-01-01T00:00:00.000Z"/><Channel>Security</Channel>
      <Computer>HOST.example.test</Computer><Security UserID="S-1-5-18"/></System>
      <EventData><Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="SubjectUserName">alice</Data></EventData></Event>'''
    event = _evtx_event(xml, 42)
    hit = _evtx_hunt(event)
    assert event['record_id'] == 42
    assert event['data']['NewProcessName'].endswith('cmd.exe')
    assert hit is not None
    assert hit['title'] == 'Process creation'
    assert hit['severity'] == 'medium'
