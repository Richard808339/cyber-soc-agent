' Lance run-digest.bat sans fenetre console.
Dim shell, dossier
Set shell = CreateObject("WScript.Shell")
dossier = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
shell.CurrentDirectory = dossier
shell.Run "cmd /c """ & dossier & "run-digest.bat""", 0, False
