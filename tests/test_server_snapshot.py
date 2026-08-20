from dftk.primitives.server import _profile_commands


def test_remote_snapshot_profiles_are_fixed_and_nonempty():
    incident = _profile_commands('incident')
    assert 'processes' in incident
    assert 'auth_log_tail' in incident
    assert all(isinstance(command, str) and command for command in incident.values())


def test_remote_snapshot_rejects_unknown_profile():
    try:
        _profile_commands('shell')
        assert False, 'expected ValueError'
    except ValueError:
        pass
