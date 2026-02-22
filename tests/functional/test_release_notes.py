"""
Functional tests for the release notes modal feature.
Issue #16: Clickable version number with release notes.

Written first (TDD) — these tests define the expected behaviour
before any implementation exists.
"""
import json
import pytest
import app as app_module


class TestReleaseNotesFooter:

    def test_footer_version_is_clickable(self, auth_client):
        """Version number in footer should be a clickable element."""
        resp = auth_client.get('/')
        assert resp.status_code == 200
        data = resp.data.decode()
        # Should be a button or have onclick/cursor-pointer
        assert 'openReleaseNotes' in data

    def test_footer_shows_current_version(self, auth_client):
        """Footer should display the current application version."""
        resp = auth_client.get('/')
        assert app_module.VERSION in resp.data.decode()

    def test_footer_version_present_on_budget_page(self, auth_client):
        """Version should appear in footer on all pages (via base.html)."""
        resp = auth_client.get('/budget')
        assert resp.status_code == 200
        assert app_module.VERSION in resp.data.decode()


class TestReleaseNotesModal:

    def test_modal_present_in_page(self, auth_client):
        """Modal element should be rendered in the page HTML."""
        resp = auth_client.get('/')
        assert b'release-notes-modal' in resp.data

    def test_modal_has_close_button(self, auth_client):
        """Modal should have a JS close function."""
        resp = auth_client.get('/')
        assert b'closeReleaseNotes' in resp.data

    def test_release_notes_shown_newest_first(self, auth_client, tmp_path, monkeypatch):
        """Release notes should appear in reverse chronological order (newest first)."""
        notes = [
            {"version": "1.0.0", "date": "2024-01-01", "changes": ["Initial release"]},
            {"version": "2.0.0", "date": "2025-01-01", "changes": ["Major update"]},
            {"version": "2.1.0", "date": "2026-01-01", "changes": ["Latest changes"]},
        ]
        notes_file = tmp_path / "release_notes.json"
        notes_file.write_text(json.dumps(notes))
        monkeypatch.setattr(app_module, 'RELEASE_NOTES_PATH', str(notes_file))

        resp = auth_client.get('/')
        data = resp.data.decode()
        pos_210 = data.index('2.1.0')
        pos_200 = data.index('2.0.0')
        pos_100 = data.index('1.0.0')
        assert pos_210 < pos_200 < pos_100

    def test_current_version_marked(self, auth_client, tmp_path, monkeypatch):
        """The currently installed version should be visually marked as 'Current'."""
        notes = [
            {"version": app_module.VERSION, "date": "2026-01-01", "changes": ["Current release"]},
            {"version": "1.0.0", "date": "2024-01-01", "changes": ["Old version"]},
        ]
        notes_file = tmp_path / "release_notes.json"
        notes_file.write_text(json.dumps(notes))
        monkeypatch.setattr(app_module, 'RELEASE_NOTES_PATH', str(notes_file))

        resp = auth_client.get('/')
        assert b'Current' in resp.data

    def test_all_versions_present_in_modal(self, auth_client, tmp_path, monkeypatch):
        """All versions in the release notes file should appear in the modal."""
        notes = [
            {"version": "1.0.0", "date": "2024-01-01", "changes": ["First release"]},
            {"version": "2.0.0", "date": "2025-06-01", "changes": ["Big update"]},
            {"version": "2.1.0", "date": "2026-01-01", "changes": ["Latest"]},
        ]
        notes_file = tmp_path / "release_notes.json"
        notes_file.write_text(json.dumps(notes))
        monkeypatch.setattr(app_module, 'RELEASE_NOTES_PATH', str(notes_file))

        resp = auth_client.get('/')
        data = resp.data.decode()
        assert '1.0.0' in data
        assert '2.0.0' in data
        assert '2.1.0' in data

    def test_changes_listed_in_modal(self, auth_client, tmp_path, monkeypatch):
        """Individual change items should appear in the modal content."""
        unique_change = "UniqueChangeDescriptionXYZ9876"
        notes = [
            {"version": "2.1.0", "date": "2026-01-01", "changes": [unique_change]},
        ]
        notes_file = tmp_path / "release_notes.json"
        notes_file.write_text(json.dumps(notes))
        monkeypatch.setattr(app_module, 'RELEASE_NOTES_PATH', str(notes_file))

        resp = auth_client.get('/')
        assert unique_change.encode() in resp.data

    def test_release_date_shown_in_modal(self, auth_client, tmp_path, monkeypatch):
        """Each release entry should display its release date."""
        notes = [
            {"version": "2.1.0", "date": "2026-02-22", "changes": ["Some change"]},
        ]
        notes_file = tmp_path / "release_notes.json"
        notes_file.write_text(json.dumps(notes))
        monkeypatch.setattr(app_module, 'RELEASE_NOTES_PATH', str(notes_file))

        resp = auth_client.get('/')
        assert b'2026-02-22' in resp.data

    def test_modal_present_on_multiple_pages(self, auth_client):
        """Release notes modal should be available on all pages (via base.html)."""
        for path in ['/', '/budget', '/settings']:
            resp = auth_client.get(path)
            assert resp.status_code == 200
            assert b'release-notes-modal' in resp.data, f"Modal not found on {path}"

    def test_graceful_when_notes_file_missing(self, auth_client, tmp_path, monkeypatch):
        """Page should still load if the release notes file is absent."""
        monkeypatch.setattr(app_module, 'RELEASE_NOTES_PATH',
                            str(tmp_path / 'nonexistent.json'))
        resp = auth_client.get('/')
        assert resp.status_code == 200
