Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
appDir = fso.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = appDir

If fso.FileExists(appDir & "\MCS-AutoLogin.exe") Then
    WshShell.Run """" & appDir & "\MCS-AutoLogin.exe""", 0, False
Else
    WshShell.Run "pythonw main.py", 0, False
End If
