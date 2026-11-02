' Lance run-collector.bat sans afficher de fenetre (utilise par la tache planifiee).
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
dossier = fso.GetParentFolderName(WScript.ScriptFullName)
sh.Run """" & dossier & "\run-collector.bat""", 0, False
