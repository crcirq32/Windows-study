#disable execution policy
#Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted

# list .dll's for firefox
#get-process firefox | select -ExpandProperty modules | group -Property FileName | select name

## list .dll's by PID
#Get-Process | where {$_.Id  -eq 520} | select -ExpandProperty modules | group -Property FileName | select name
#Get-Process -Id 520 | select -ExpandProperty modules | group -Property FileName | select name

#find processes that load .dll
#Get-Process | where {$_.Modules -match 'apisampling.dll'} | select Id, ProcessName

#SID from user
#$username='uciuser'
#$user = New-Object System.Security.Principal.NTAccount($username) 
#$sid = $user.Translate([System.Security.Principal.SecurityIdentifier]) 
#$sid.Value

#User from SID
#$sid='S-1-5-21-2627294711-3217172480-3044335090-1002'
#$osid = New-Object System.Security.Principal.SecurityIdentifier($sid)
#$user = $osid.Translate( [System.Security.Principal.NTAccount])
#$user.Value

#schtasks - query scheduled tasks and binary:: sus:: UUID-style or high-entropy name
#schtasks /query /fo list /v

#Search for LNK files:: C:\Users\$username\AppData\Roaming\Microsoft\Windows\Start menu\programs\startup

#services && exe paths
#Get-WmiObject win32_service | select Name, Displayname, @{Name='Path'; Expression={$_.PathName.split('"')[1]}} | format-list

#service installation generates event log w/ "ID 7045"
#Get-WinEvent -FilterHashtable @{logname='system'; id=7045} | format-list

#Display all open ports
#netstat -a

#Display all established ports && their services
#netstat -b

#Add Chocolately Repo:
#Register-PackageSource -Name chocolatey -ProviderName Chocolatey -Location http://chocolatey.org/api/v2/

#Download Sysinternals Suite: https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite

#run Autorun.exe: to check verified processes/DLLs/etc. *disable/enable tasks that have created registry keys*

#Autoruns.exe color codes:
<#
#Yellow — Startup entry exists, but cannot link itself or find the program installed on your computer.
#Green — Startup entry was recently added since last Autoruns scan, probably due to the installment of a new program.
#Pink — No publisher information exists, either because the digital signature doesn’t exist or publisher information is not included in the program.
#Purple — Indicates where the Autoruns file is located.
#>

# Registry entries known for persistence::
<#
#HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run *SYSTEM BOUND KEY*
#HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run  *USER BOUND KEY*
#HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce *SYSTEM BOUND KEY*
#HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce *USER BOUND KEY*
#>

#Persistence Identification::
<#
$syskeys = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
foreach($key in $syskey){
    Get-ItemProperty Registry::$key
}
#Create array with user profiles, directories, and SIDS
#SIDS will never start with S-1-5\|18\|20, these are reserved for system accounts(NT AUTHORITY\SYSTEM\ISS)
$users = (Get-WmiObject Win32_UserProfile | Where-Object {$_.SID -notmatch 'S-1-5(18|19|20).*'})
$userPaths = $users.localpath
$userPIDS = $users.sid

#Iterate over amount of users, load object(path\|SID) into variable based on value of counter. Load user registry hive
#Obtained most common registry keys for persistence
for ($counter=0; $counter -lt $users.length; $counter++){
    $path = $users[$counter].localpath
    $sid = $users[$counter].sid
    reg load hku\$sid $path\ntuser.dat
}
Get-ItemProperty Registry::\hku\*\Software\Microsoft\windows\currentversion\run;
Get-ItemProperty Registry::\hku\*\Software\Microsoft\windows\currentversion\runonce;

foreach($key in $syskey){
    Get-ItemProperty Registry::$key
}

#TODO: https://social.technet.microsoft.com/Forums/en-US/e19425e6-c406-4064-9283-8bfb8d058ba1/reg-unload-access-denied-in-cmd 
# reg : ERROR: Access is denied.
# reg load hku\$sid $path\ntuser.dat
# Possible open handle to the key
"
#>

#display all services install on system && display name
#Get-WmiObject win32_service | select name, displayname | format-list

#Scheduled tasks(.xml) are located C:\Windows\System32\Tasks
#funct to iterate tasks
<#
$tasks = Get-ChildItem "C:\Windows\system32\tasks" -Recurse
foreach($task in $tasks){
    Write-Host "`r`n[+] Task: $task"
    Write-Host "++++++++++++++++++++++++++`r`n"
    Get-Content $task -ErrorAction SilentlyContinue | Select-String -Pattern '<Command>' -SimpleMatch
}
#>

