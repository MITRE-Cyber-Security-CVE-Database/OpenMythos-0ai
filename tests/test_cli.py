from open_mythos.cli import build_parser, main


def test_cli_parser_builds():
    parser = build_parser()
    assert parser.prog == "openmythos"


def test_cli_info_runs():
    assert main(["info"]) == 0
