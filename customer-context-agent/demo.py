import argparse
import json

from graph import build_graph


def _parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Run customer-context demo")
	parser.add_argument(
		"--network",
		default="141.92.164.1/32",
		help="Target network CIDR to look up",
	)
	parser.add_argument(
		"--locations",
		nargs="+",
		default=["ams5"],
		help="Requested locations",
	)
	return parser.parse_args()


def main() -> None:
	args = _parse_args()
	graph = build_graph()
	result = graph.invoke({"network": args.network, "locations": args.locations})
	print(json.dumps(result, indent=2))


if __name__ == "__main__":
	main()
