"""Node-side JSON driver for the repository adapter VM fixture.

Reads one request object from stdin, runs a trusted-caller
ResticRepository operation inside the test VM, and prints one JSON
result object. Fixture plumbing only: the adapter itself remains a
library with no CLI contract.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import recovery
import repository


def _fail(code):
    return {'status': 'failed', 'error': code}


def main():
    try:
        request = json.loads(sys.stdin.read())
    except ValueError:
        print(json.dumps(_fail('invalid-request')))
        return
    try:
        repo = repository.ResticRepository(request['config'])
        operation = request['operation']
        if operation == 'store':
            record = repo.store(
                request['stageDir'], request['definition'],
                request['source'], request['capture'],
                capture_id=request['captureId'],
                secret_bundle=request.get('secretBundle'))
            result = {'status': 'completed', 'record': record}
        elif operation == 'inspect':
            result = {'status': 'completed',
                      'record': repo.inspect(request['snapshotId'])}
        elif operation == 'list_points':
            result = {'status': 'completed',
                      'records': repo.list_points()}
        elif operation == 'check':
            repo.check()
            result = {'status': 'completed'}
        elif operation == 'verify_identity':
            result = {'status': 'completed',
                      'identity': repo.verify_identity()}
        elif operation == 'restore':
            result = {'status': 'completed',
                      'record': repo.restore(request['snapshotId'],
                                             request['destination'])}
        else:
            result = {'status': 'failed', 'error': 'unknown-operation'}
    except repository.RepositoryError as error:
        result = _fail(error.code)
    except recovery.RecoveryError as error:
        result = _fail(str(error))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
