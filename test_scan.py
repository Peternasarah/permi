from scanner.scan import scan, print_results, summary

findings = scan(
    path="./test_project",
    project_name="test-project-ai",
    offline=False        # set to True to skip AI and save API calls
)

print_results(findings)
summary(findings)
