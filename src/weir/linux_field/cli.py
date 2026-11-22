"""Inspect the host and export the exact eligible page template without opening a site."""

import argparse
import json

from weir.linux_field.review import local_readiness, page_template
from weir.linux_field.runtime import _CONFIG, _INGRESS, _WITNESS


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("readiness", "template"))
    args = parser.parse_args(argv)
    report = page_template() if args.operation == "template" else local_readiness(_CONFIG, _INGRESS.parent, _WITNESS)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
