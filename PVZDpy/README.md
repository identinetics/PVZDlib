Portalverbund zentrale Dienste - Shared Library
===============================================

Funktionen für die PVZD Anwendungen ohne Abhängigkeiten zu einem Webframework oder CLI-Client.

### Coding Style

Das Projekt verwendet PEP8 in der Varianten von Django (https://docs.djangoproject.com/en/dev/internals/contributing/writing-code/coding-style/)

Der Source Code Validator wird wie folgt aufgerufen:

    flake8 --max-line-length 119 --ignore=F811   # F811 wegen pytest fixtures