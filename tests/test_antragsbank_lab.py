import importlib.util
import json
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name('antragsbank-lab.py')
spec = importlib.util.spec_from_file_location('antragsbank_lab', MODULE_PATH)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


def body(payload):
    return json.dumps(payload).encode()


class EventListTests(unittest.TestCase):
    def test_list_containing_synthetic_event_is_accepted(self):
        record = lab.expect_event_list(body([{'id': 'other'}, {'id': 'nexus-lab-event'}]))
        self.assertEqual(record['id'], 'nexus-lab-event')

    def test_missing_or_malformed_events_are_rejected(self):
        for payload in (b'{}', b'"nexus-lab-event"', body([]), body([{'id': 'other'}]), b'[42]'):
            with self.assertRaises(Exception, msg=payload):
                lab.expect_event_list(payload)


class CreatedProposalTests(unittest.TestCase):
    def record(self):
        return {
            'id': 'nexus-lab-event-01',
            'seq': 1,
            'title': 'Synthetic API proposal',
            'lines': [{'type': 'paragraph', 'content': 'Acknowledged synthetic content'}],
            'footnotes': ['Synthetic footnote'],
            'keywords': ['synthetic'],
            'status': 'offen',
        }

    def test_created_record_is_accepted(self):
        record = lab.expect_created(body(self.record()))
        self.assertEqual(record['status'], 'offen')

    def test_wrong_id_title_or_content_are_rejected(self):
        mutations = [
            {'id': 'nexus-lab-event-02'},
            {'seq': 2},
            {'seq': True},
            {'seq': '1'},
            {'title': 'Mutated'},
            {'lines': [{'type': 'paragraph', 'content': 'mutated'}]},
            {'lines': []},
            {'footnotes': []},
            {'footnotes': ['Synthetic footnote', 'extra']},
            {'keywords': []},
        ]
        for change in mutations:
            record = self.record()
            record.update(change)
            with self.assertRaises(Exception, msg=change):
                lab.expect_created(body(record))

    def test_scalar_and_error_payloads_are_rejected(self):
        for payload in (b'"nexus-lab-event-01"', b'[]', b'{"detail":"denied"}', b'42'):
            with self.assertRaises(Exception, msg=payload):
                lab.expect_created(payload)


class ProposalListTests(unittest.TestCase):
    def record(self):
        return {
            'id': 'nexus-lab-event-01',
            'seq': 1,
            'title': 'Synthetic API proposal',
            'lines': [{'type': 'paragraph', 'content': 'Acknowledged synthetic content'}],
            'footnotes': ['Synthetic footnote'],
            'keywords': ['synthetic'],
        }

    def test_created_record_in_list_is_accepted(self):
        record = lab.expect_proposal_list(body([{'id': 'other'}, self.record()]))
        self.assertEqual(record['id'], 'nexus-lab-event-01')

    def test_missing_or_wrong_title_are_rejected(self):
        for payload in (body([]), body([{'id': 'nexus-lab-event-01', 'title': 'Mutated'}]), b'{}'):
            with self.assertRaises(Exception, msg=payload):
                lab.expect_proposal_list(payload)

    def test_duplicate_matching_ids_are_rejected(self):
        record = self.record()
        with self.assertRaises(Exception):
            lab.expect_proposal_list(body([record, dict(record)]))

    def test_body_loss_after_matching_id_is_rejected(self):
        record = self.record()
        record['lines'] = []
        with self.assertRaises(Exception):
            lab.expect_proposal_list(body([record]))


class ArchiveProposalTests(unittest.TestCase):
    def record(self):
        return {
            'proposal_id': 'nexus-lab-archive',
            'year': 2026,
            'seq': 1,
            'title': 'Synthetic archive',
            'lines': [{'type': 'paragraph', 'content': 'Persisted archive content'}],
            'footnotes': [],
            'keywords': ['synthetic'],
            'version': 1,
        }

    def test_seeded_archive_record_is_accepted(self):
        record = lab.expect_archive(body(self.record()))
        self.assertEqual(record['version'], 1)

    def test_mutated_archive_records_are_rejected(self):
        mutations = [
            {'proposal_id': 'other'},
            {'year': 2025},
            {'year': '2026'},
            {'seq': True},
            {'title': 'Mutated'},
            {'lines': [{'type': 'paragraph', 'content': 'mutated'}]},
            {'footnotes': ['injected']},
            {'keywords': []},
        ]
        for change in mutations:
            record = self.record()
            record.update(change)
            with self.assertRaises(Exception, msg=change):
                lab.expect_archive(body(record))


if __name__ == '__main__':
    unittest.main()
