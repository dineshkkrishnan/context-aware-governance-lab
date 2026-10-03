"""Evaluate synthetic JSON requests and write minimal hash-linked audit records."""
import argparse
import json
from collections import Counter
from pathlib import Path
from governance import audit_batch,verify_chain


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',default='data/requests.json')
    parser.add_argument('--output',default='output/audit.json')
    parser.add_argument('--verify',help='Verify an existing audit JSON instead of evaluating requests')
    args=parser.parse_args()
    try:
        if args.verify:
            valid=verify_chain(json.loads(Path(args.verify).read_text()))
            print('Chain valid' if valid else 'Chain INVALID')
            return 0 if valid else 1
        records=audit_batch(json.loads(Path(args.input).read_text()))
        path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(records,indent=2)+'\n')
        print(json.dumps(dict(Counter(r['outcome'] for r in records)),sort_keys=True))
        print(f'Audit: {path}; chain valid: {verify_chain(records)}')
        return 0
    except (OSError,ValueError,TypeError) as exc:
        parser.error(str(exc))

if __name__=='__main__':raise SystemExit(main())
