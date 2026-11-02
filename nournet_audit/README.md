# Nournet passive audit — GitHub Actions

This folder contains a **limited, unauthenticated** HTTP(S) check of the **exact** bug-bounty scope \`https://nour.net.sa\`. It sends one GET to each of \`/\`, \`/robots.txt\`, and \`/sitemap.xml\`; redirects off the exact HTTPS origin are blocked. No login attempts, fuzzing, discovery, enumeration, exploitation, or performance testing.

## Run from an iPhone without installing an app

1. Review and merge the pull request containing these files.
2. In Safari open the repo **Actions** tab, choose **Nournet passive audit** from the left, and tap **Run workflow**. Use the \`main\` branch.
3. Open the finished workflow run, find **Artifacts**, and download \`nournet-passive-report\` (ZIP); extract to view \`report.json\`.
4. If no report is uploaded, inspect the run logs.

The workflow is **manual only**, not scheduled. You do not need to enter a URL or tokens.

**Important:** The result is informational. Missing headers do not establish an exploitable vulnerability. If the GitHub runner cannot resolve the host or a redirect is blocked, the report records an error; this does not indicate a site vulnerability. Obey the complete program rules, including any cloud-hosted testing restrictions.

Local usage: \`python3 nournet_audit/audit.py https://nour.net.sa --output report.json\`.
Local unit tests: \`python3 -m unittest discover -s nournet_audit -v\`.
