from scanner.dependency_parser import parse_requirements


def test_parse_exact_pins():
    dependencies, errors = parse_requirements("requests==2.31.0\nFlask==3.0.0")
    assert [(item["name"], item["version"]) for item in dependencies] == [
        ("requests", "2.31.0"),
        ("Flask", "3.0.0"),
    ]
    assert errors == []


def test_comments_and_blank_lines_are_ignored():
    dependencies, errors = parse_requirements("# comment\n\nrequests==2.31.0\n")
    assert len(dependencies) == 1
    assert errors == []


def test_unpinned_requirement_is_reported():
    dependencies, errors = parse_requirements("requests>=2.0")
    assert dependencies == []
    assert errors[0]["line"] == 1


def test_nested_and_editable_requirements_are_reported():
    dependencies, errors = parse_requirements("-r base.txt\n-e .")
    assert dependencies == []
    assert len(errors) == 2


def test_direct_url_requirement_is_not_silently_accepted():
    dependencies, errors = parse_requirements("demo @ https://example.invalid/demo.whl")
    assert dependencies == []
    assert "Direct URL" in errors[0]["message"]


def test_environment_marker_is_respected():
    dependencies, errors = parse_requirements('requests==2.31.0; python_version < "2.0"')
    assert dependencies == []
    assert errors == []
