' Lance run-broker.bat sans ouvrir de fenetre console.
' Utilise par la tache planifiee "SOC Broker Telegram" (au demarrage de session).
Dim shell, dossier
Set shell = CreateObject("WScript.Shell")
dossier = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
shell.Run "cmd /c """ & dossier & "run-broker.bat""", 0, False
