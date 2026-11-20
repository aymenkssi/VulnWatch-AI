"""
Filtres de journalisation.

Sous Windows, asyncio (boucle « Proactor ») journalise une trace
complète chaque fois qu'un navigateur ferme brutalement sa connexion :

    Exception in callback _ProactorBasePipeTransport._call_connection_lost()
    ConnectionResetError: [WinError 10054] ...

C'est sans conséquence (onglet fermé, rafraîchissement, WebSocket
coupé, connexions TLS abandonnées par le navigateur face à un
certificat auto-signé), mais cela noie les vrais messages. Seule cette
trace précise est masquée ; toute autre erreur asyncio reste affichée.
"""

import logging

_INSTALLED = False


class _IgnoreClientDisconnects(logging.Filter):

    def filter(self, record):

        exc = record.exc_info[1] if record.exc_info else None

        if not isinstance(exc, (ConnectionResetError, ConnectionAbortedError)):
            return True

        try:
            message = record.getMessage()
        except Exception:
            return True

        return "_call_connection_lost" not in message


def install_log_filters():
    """Idempotent : Streamlit réexécute app.py à chaque interaction."""

    global _INSTALLED

    if _INSTALLED:
        return

    logging.getLogger("asyncio").addFilter(_IgnoreClientDisconnects())

    _INSTALLED = True
