"""
Synchros automatiques sans navigateur, pour le Planificateur de tâches
Windows (ou cron) : lance les synchros dues (services/scheduler.py), puis
attend qu'elles se terminent.

Tâche planifiée conseillée (PowerShell administrateur, depuis le dossier
de l'application) :

  $action  = New-ScheduledTaskAction -Execute "C:\\VulnWatch-AI\\.venv\\Scripts\\python.exe" `
             -Argument "scheduled_sync.py" -WorkingDirectory "C:\\VulnWatch-AI"
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
             -RepetitionInterval (New-TimeSpan -Minutes 15)
  $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
             -ExecutionTimeLimit (New-TimeSpan -Hours 12)
  Register-ScheduledTask -TaskName "VulnWatch AI - synchros" -Action $action `
             -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest

Avec le compte SYSTEM, configurez l'application Azure (barre latérale >
« Application Azure ») : la connexion Azure CLI d'un utilisateur n'est pas
disponible pour ce compte.

Options :
  --no-wait : ne pas attendre la fin des synchros lancées.
"""

import sys
import time

from database import initialize_database
from services.jobs import get_job
from services.scheduler import run_due_syncs


POLL_SECONDS = 15


def main():

    initialize_database()

    launched = run_due_syncs()

    if not launched:
        print("Aucune synchro due.")
        return 0

    print("Synchro(s) lancée(s) : " + ", ".join(launched))

    if "--no-wait" in sys.argv:
        return 0

    # Le Planificateur de tâches peut arrêter les processus d'une tâche
    # terminée : on reste actif tant que les synchros lancées tournent.
    failed = False
    pending = set(launched)

    while pending:

        time.sleep(POLL_SECONDS)

        for key in sorted(pending):

            job = get_job(key)

            if job and job["running"]:
                continue

            pending.discard(key)
            status = (job or {}).get("status", "?")
            failed |= status != "DONE"

            print(f"{(job or {}).get('label', key)} : {status}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
