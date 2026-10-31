from packaging.requirements import Requirement


def parse_requirements(content):
    dependencies = []
    errors = []

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith(("-r ", "--requirement ", "-e ", "--editable ")):
            errors.append({
                "line": line_number,
                "message": "Nested or editable requirements are not supported."
            })
            continue

        try:
            requirement = Requirement(line)

            if requirement.url:
                errors.append({
                    "line": line_number,
                    "message": "Direct URL dependencies require separate verification."
                })
                continue

            if requirement.marker and not requirement.marker.evaluate():
                continue

            if len(requirement.specifier) == 0:
                errors.append({
                    "line": line_number,
                    "message": "Dependency has no version constraint."
                })
                continue

            versions = [
                spec.version
                for spec in requirement.specifier
                if spec.operator in ("==", "===")
            ]

            if len(versions) != 1:
                errors.append({
                    "line": line_number,
                    "message": "Provide an exact package version for vulnerability checking."
                })
                continue

            version = versions[0]

            if "*" in version or version.endswith("."):
                errors.append({
                    "line": line_number,
                    "message": "Invalid exact version."
                })
                continue

            dependencies.append({
                "name": requirement.name,
                "version": version,
                "ecosystem": "PyPI"
            })

        except Exception:
            errors.append({
                "line": line_number,
                "message": "Unable to parse this dependency."
            })

    return dependencies, errors
