
# Summary

PoshPwned was a quick little project of mine to generate local HTML docs via scheduled tasks to keep an eye on password pwnage. The project just about completely wraps the HaveIBeenPwned v3 REST API [here](https://haveibeenpwned.com/API/v3).

The functions exported all fully support standard PowerShell help text.

# Disclaimer

- I've chosen to store my HIBP token in plaintext in the HKCU environment variable registry key - as such, the `Set-HIBP -Token [ token ]` performs this as well.
- Since this is a $3/month programmatic-access-only token, I've determined this as an acceptable level of security for my little project.
- **But**, it's important to stress plaintext secret storage is generally bad practice and where possible a purpose-built solution such as HashiCorp Vault should be utilized.
