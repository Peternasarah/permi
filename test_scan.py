from scanner.scan import scan, print_results, summary

findings = scan(
    path="./test_project",
    project_name="test-project"
)

print_results(findings)
summary(findings)
