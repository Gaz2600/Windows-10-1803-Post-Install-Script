######################################################################################
#                                                                                    #
#  _    _ _           _                       __  _____     __   _____ _____  _____  #
# | |  | (_)         | |                     /  ||  _  |   /  | |  _  |  _  ||____ | #
# | |  | |_ _ __   __| | _____      _____    `| || |/' |   `| |  \ V /| |/' |    / / #
# | |/\| | | '_ \ / _` |/ _ \ \ /\ / / __|    | ||  /| |    | |  / _ \|  /| |    \ \ #
# \  /\  / | | | | (_| | (_) \ V  V /\__ \   _| |\ |_/ /   _| |_| |_| \ |_/ /.___/ / #
#  \/  \/|_|_| |_|\__,_|\___/ \_/\_/ |___/   \___/\___/    \___/\_____/\___/ \____/  #
#                                                                                    #
######################################################################################                                                                                  

#####
#####  Search and edit all the "CHANGEME" sections.  
#####  I'm using Smart Deploy, I've got it set to autologin after applying the base image and map a network drive to "z:", 
#####  which is where this script and associated files live, then run this file. You can do the same thing by saving this and 
#####  associated files to the base image in C:\Windows\Setup\Scripts and set an automated task to run once at login to launch 
#####  this file then run the cleanup tasks at the end of this script to remove everything.
#####

##################################################################
# Check if running as admin, if not open a new instance as Admin #
##################################################################

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

{   
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
}

####################
# Lock Workstation #
####################
#rundll32.exe user32.dll,LockWorkStation

#############################
# lock the keyboard & mouse #
#############################

$code = @"
    [DllImport("user32.dll")]
    public static extern bool BlockInput(bool fBlockIt);
"@
$userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($true)


###############################
# Wait for Network Connection #
###############################

function wait-for-network ($tries) {
    while (1) {
        $x = gwmi -class Win32_NetworkAdapterConfiguration `
                -filter DHCPEnabled=TRUE |
                        where { $_.DefaultIPGateway -ne $null }
        if ( ($x | measure).count -gt 0 ) {
                break
        }
        if ( $tries -gt 0 -and $try++ -ge $tries ) {
                throw "Network unavaiable after $try tries."
        }
        start-sleep -s 1
    }
}

#######################
# Display MSG Window  #
#######################

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()
$form         = New-Object system.Windows.Forms.Form
$pictureBox = new-object Windows.Forms.PictureBox

$file = (get-item 'Z:\images\warning.jpg')
$img = [System.Drawing.Image]::Fromfile($file);

$CenterScreen = [System.Windows.Forms.FormStartPosition]::CenterScreen;
$form.StartPosition = $CenterScreen;
$form.ClientSize = '611,300'
$form.text       = "CHANGEME"
$form.BackColor  = "#fe6c6c"
$form.TopMost    = $false

$pictureBox.Width =  $img.Size.Width;
$pictureBox.Height =  $img.Size.Height;

$pictureBox.Image = $img;
$form.controls.add($pictureBox)
$form.Add_Shown( { $form.Activate() } )
$form.Show()

#######################
# Update Group Policy #
#######################

GPUPDATE /force

###############################
# Copy files from Z: to Local #
###############################

#Login Screen Wallpaper
Copy-Item -Path Z:\images\Wallpaper1920x1080.jpg -Destination c:\windows\web\screen\Wallpaper1920x1080.jpg -Force
#Wallpaper
New-Item -ItemType directory -Path C:\Windows\Web\Wallpaper\CHANGEME
Copy-Item -Path Z:\images\Wallpaper1920x1080.jpg -Destination C:\Windows\Web\Wallpaper\CHANGEME\Wallpaper1920x1080.jpg -Force
#Start Menu Layout
Copy-Item -Path z:\LayoutModification.xml -Destination  C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml -Force
#Wifi Profile
Copy-Item -Path z:\CHANGEME.xml -Destination C:\windows\Setup\CHANGEME.xml

#########################
# Set Lock Screen Image #  *This method worked at after March 2018 Windows updates
#########################

Start-Process -filePath "$env:systemRoot\system32\takeown.exe" -ArgumentList "/F `"$env:programData\Microsoft\Windows\SystemData`" /R /A /D Y" -NoNewWindow -Wait
Start-Process -filePath "$env:systemRoot\system32\icacls.exe" -ArgumentList "`"$env:programData\Microsoft\Windows\SystemData`" /grant Administrators:(OI)(CI)F /T" -NoNewWindow -Wait
Start-Process -filePath "$env:systemRoot\system32\icacls.exe" -ArgumentList "`"$env:programData\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly`" /reset /T" -NoNewWindow -Wait
#Remove-Item -Path "$env:programData\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly\LockScreen_Z\*" -Force
Start-Process -filePath "$env:systemRoot\system32\takeown.exe" -ArgumentList "/F `"$env:systemRoot\Web\Screen`" /R /A /D Y" -NoNewWindow -Wait
Start-Process -filePath "$env:systemRoot\system32\icacls.exe" -ArgumentList "`"$env:systemRoot\Web\Screen`" /grant Administrators:(OI)(CI)F /T" -NoNewWindow -Wait
Start-Process -filePath "$env:systemRoot\system32\icacls.exe" -ArgumentList "`"$env:systemRoot\Web\Screen`" /reset /T" -NoNewWindow -Wait
Copy-Item -Path "$env:systemRoot\Web\Screen\img100.jpg" -Destination "$env:systemRoot\Web\Screen\img200.jpg" -Force
Copy-Item -Path "c:\windows\web\screen\Wallpaper1920x1080.jpg" -Destination "$env:systemRoot\Web\Screen\img100.jpg" -Force


####################
# Install .Net 3.5 #
####################

Start-Job -Name .Net3.5 -ScriptBlock {
    Install-WindowsFeature Net-Framework-Core -source z:\Sources\sxs
}
Wait-Job -Name .Net3.5

################################
# Configuration - With Network #
################################

Start-Job -Name Job1 -ScriptBlock {
    #Add Group/User to local Administrators
    Add-LocalGroupMember -Group "Administrators" -Member "CHANGEME\TechLocalAdmin"
}
Wait-Job -Name Job1

#####################
# Add Registry Keys #
#####################

Start-Job -Name Job2 -ScriptBlock {
    ### Copy Current Location C: ###
    Push-Location

    ### Change Location to HKLM: ###
    Set-Location HKLM:

    ### Hiber Boot Disable ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
    $Name = "HiberbootEnabled"
    $Value = 0
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Hide Sleep Option ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" 
    $Name = "ShowSleepOption"
    $Value = 0
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Hide Hibernate Option ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
    $Name  ="ShowHibernateOption"
    $Value = 0
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Disable Hibernation ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power"
    $Name  ="HibernateEnabled"
    $Value = 0
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Turn Auto Logon Off ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $Name  ="AutoAdminLogon"
    $Value = 0
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Remove Store from TaskBar HKLM ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    $Name  ="NoPinningStoreToTaskbar"
    $Value = 1
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### No New Application Alert ### *Prevents windows from prompting to use Edge vs Chrome on first launch
    $RegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    $Name  ="NoNewAppAlert"
    $Value = 1
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Hide TightVNC Tray Icon ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\Software\TightVNC\Server\"
    $Name  ="RunControlInterface"
    $Value = 0
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Disable Sync Center Part 1 ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync"
    $Name  ="DisableSettingSync"
    $Value = 2
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Disable Sync Center Part 2 ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync"
    $Name  ="DisableSettingSyncUserOverride "
    $Value = 1
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Disable Windows Ink ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
    $Name  ="AllowWindowsInkWorkspace "
    $Value = 0
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Hide Action Center ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $Name  ="HideSCAHealth "
    $Value = 1
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType REG_SZ -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Hide Recently Added Apps ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    $Name  ="HideRecentlyAddedApps"
    $Value = 1
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Enable Windows Defender ###
    $RegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
    $Name  ="DisableAntiSpyware"
    $Value = 0
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       Set-ItemProperty -Path $RegistryPath -Name $name -Value $value -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    ### Remove Edge Icon From the Desktop ###
    $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $Name  ="DisableEdgeDesktopShortcutCreation"
    $Value = 1
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    Pop-Location

    ### Copy Current Location C: ###
    Push-Location

    ### Change Location to HKLM: ###
    Set-Location HKCR:

    ### Remove Network Icon From Explorer ###
    $RegistryPath = "HKEY_CLASSES_ROOT\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder"
    $Name  ="Attributes"
    $Value = "b0940064"
    IF(!(Test-Path $registryPath))
      {New-Item -Path $RegistryPath -Force | Out-Null}
       New-ItemProperty -Path $RegistryPath -Name $name -Value $value -Force | Out-Null
    $RegistryPath=$null; $Name=$null;  $Value=$null

    Pop-Location


    ################################
    # Reg edit for HKEY_LOCAL_USER #
    ################################

    ### Load HKCU Hive ###
    reg load HKU\Temp C:\Users\Default\ntuser.dat
    
    #Remove Mail App in Taskbar
    reg add HKU\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins /v MailPin /t REG_DWORD /d 2 /f
    #Cortana Bar
    reg add HKU\Temp\Software\Microsoft\Windows\CurrentVersion\Search /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f
    #Hide People
    reg add HKU\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People /v PeopleBand /t REG_DWORD /d 0 /f
    #Show all taskbar icons
    reg add HKU\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer /v EnableAutoTray /t REG_DWORD /d 0 /f
    #Show seconds on clock
    reg add HKU\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSecondsInSystemClock /t REG_DWORD /d 1 /f
    #Remove Onedrive from tray
    reg delete HKU\Temp\Software\Microsoft\Windows\CurrentVersion\Run /v OneDriveSetup /f
    reg add HKU\Temp\Software\Microsoft\Windows\CurrentVersion\Run /v OneDriveSetup /t REG_SZ /d "C:\Windows\SysWOW64\OneDriveSetup.exe /silent" /f
    #Turn off Feedback Hub Notifications
    reg add HKU\Temp\SOFTWARE\Microsoft\Siuf\Rules /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
    reg add HKU\Temp\SOFTWARE\Microsoft\Siuf\Rules /v PeriodInNanoSeconds /t REG_QWORD /d 0  /f
    #Turn off Suggested Apps
    reg add HKU\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SubscribedContent-338388Enabled /t REG_DWORD /d 1 /f
    #Hide Recently Used Apps
    reg add HKU\Temp\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Start_TrackProgs /t REG_DWORD /d 0 /f
    #Disable Location Service
    reg add HKU\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44} /v Value /t REG_SZ /d Deny /f
    reg add HKU\Temp\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44} /v SensorPermissionState /t REG_DWORD /d 0 /f
    #Disable Occasonally show suggestions in Start
    reg add HKU\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SystemPaneSuggestionsEnabled  /t REG_DWORD /d 0 /f
    #Disable Show recently opened items in Jump Lists on Start or the taskbar
    reg add HKU\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Start_TrackDocs /t REG_DWORD /d 0 /f
    #Disable Improve Typing
    reg add HKU\Temp\SOFTWARE\Microsoft\Input\TIPC /v Enabled /t DWORD /d 0 /f
    ###Storage Sense
     #(Automatically free up space)
    reg add HKU\Temp\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy /v 01 /t REG_DWORD /d 1 /f
     #(Delete temporary files that my apps aren't using)
    reg add HKU\Temp\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy /v 04 /t REG_DWORD /d 1 /f
     #(Delete files that have been in the recycle bin for over 30 days)
    reg add HKU\Temp\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy /v 08 /t REG_DWORD /d 1 /f
     #(Delete files in my Downloads folder that haven't changed for over 30 days)
    reg add HKU\Temp\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy /v 32 /t REG_DWORD /d 0 /f
    #Disable Notification Center
    reg add HKU\Temp\Software\Policies\Microsoft\Windows\Explorer /v DisableNotificationCenter /t REG_DWORD /d 1 /f
     #Set File Explorer to open to This PC vs Quick Access
    reg add HKU\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v LaunchTo /t REG_DWORD /d 1 /f


    ### Unload HKCU Hive ###
    reg unload HKU\Temp C:\Users\Default\ntuser.dat


    <#
    #############################
    ### Set Lock Screen Image ###  *This method worked at prior to March 2018 Windows updates
    #############################

    $RegistryPath5 = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization"
    $Name5  ="LockScreenImage"
    $Value5 = "c:\windows\web\screen\Wallpaper1920x1080.jpg"
    IF(!(Test-Path $registryPath5))
      {New-Item -Path $RegistryPath5 -Force | Out-Null}
       Set-ItemProperty -Path $RegistryPath5 -Name $name5 -Value $value5 -Force | Out-Null
    #>
}
Wait-Job -Name Job2

############################
# Uninstall Software Other #
############################

Start-Job -Name Job4 -ScriptBlock {
#Get-AppxPackage | Select Name, PackageFullName
    $AppList = "Microsoft.SkypeApp",           
               "Microsoft.MicrosoftSolitaireCollection",
               "Microsoft.MicrosoftOfficeHub",
               "Microsoft.Office.OneNote",
               "Microsoft.XboxApp",
               "Microsoft.Getstarted"
    ForEach ($App in $AppList)
     {
     $PackageFullName = (Get-AppxPackage $App).PackageFullName
     $ProPackageFullName = (Get-AppxProvisionedPackage -online | where {$_.Displayname -eq $App}).PackageName
     write-host $PackageFullName
     Write-Host $ProPackageFullName
     if ($PackageFullName)
     {
     Write-Host "Removing Package: $App"
     remove-AppxPackage -package $PackageFullName
     }
     else
     {
     Write-Host "Unable to find package: $App"
     }
     if ($ProPackageFullName)
     {
     Write-Host "Removing Provisioned Package: $ProPackageFullName"
     Remove-AppxProvisionedPackage -online -packagename $ProPackageFullName
     }
     else
     {
     Write-Host "Unable to find provisioned package: $App"
     }
     }
}
Wait-Job -Name Job4

####################
# Install Software #
####################

#Malwarebytes
$MB = '/I z:\software\Setup.MBEndpointAgent.x64.msi /quiet'
$MBArgs = '/quiet'
Start-Process msiexec.exe -wait -Argumentlist $MB
Start-Sleep -s 60

####################
#    Sync Time     #
####################

w32tm /unregister
w32tm /register
net start w32time
w32time /resync /force

####################
#   Join Domain    #
####################
<#
$domain = "CHANGEME.local"
$password = "CHANGEME" | ConvertTo-SecureString -asPlainText -Force
$username = "$domain\CHANGEME" 
$credential = New-Object System.Management.Automation.PSCredential($username,$password)
Add-Computer -DomainName $domain -Credential $credential
#>

###################
# Install Drivers #
###################

Start-Job -Name Job5 -ScriptBlock {
    #Models
    $Model = (Get-WmiObject -Class:Win32_ComputerSystem).Model
    $Mod7220 = "7220RY8"
    $Mod4518 = "4518W8M"
    $Mod30AU = "30AUS14J00"
    #Driver Root Folders
    $7220 = "C:\Windows\Setup\7220"
    $4518 = "C:\Windows\Setup\4518"
    $30AU = "C:\Windows\Setup\30AU"
    #Video Drivers
    $Q45  = "C:\Windows\Setup\7220\Intel_Q45_Q43"
    $HD  = "C:\Windows\Setup\4518\Intel_HD_Graphics"
    $K1200 = "C:\Windows\Setup\30AU\Nvidia\390.77\Display.Driver"
    #Network Drivers
    $Pro1000 = "C:\Windows\Setup\4518\Intel_Pro1000"
    #Other var
    $Scripts = "C:\Windows\Setup\scripts"

    #Lenovo 7220 (Video)
    IF ($Model -eq $Mod7220)
    {
        Copy-Item -Path Z:\7220 -Destination C:\Windows\Setup -Container -Force -Recurse
        Get-ChildItem $Q45 -Recurse -Filter "igdlh.inf" | ForEach-Object {PNPUtil.exe /add-driver $_.FullName /install}
    } 

    #Lenovo 4518 (Video & NIC)
    IF ($Model -eq $Mod4518)
    {
        Copy-Item -Path Z:\4518 -Destination C:\Windows\Setup -Container -Force -Recurse
        Get-ChildItem $HD -Recurse -Filter "igdlh64.inf" | ForEach-Object {PNPUtil.exe /add-driver $_.FullName /install}
        Get-ChildItem $Pro1000 -Recurse -Filter "e1c65x64.inf" | ForEach-Object {PNPUtil.exe /add-driver $_.FullName /install}
        & C:\Windows\Setup\4518\Intel_PRO1000\PROSETDX\DxSetup.exe ans=1 /qn
        Start-Sleep -Seconds 15
    }

    #Lenovo 30AU "P310" (Video)
    IF ($Model -eq $Mod30AU)
    {
        Copy-Item -Path Z:\K1200 -Destination C:\Windows\Setup -Container -Force -Recurse
        Get-ChildItem $K1200 -Recurse -Filter "<#INSERT DRIVER HERE#>" | ForEach-Object {PNPUtil.exe /add-driver $_.FullName /install}
    } 
}
Wait-Job -Name Job5

###### Z: mapping broken past this point ######

##############################
# Configuration - No Network #
##############################

Start-Job -Name Job6 -ScriptBlock {
    #Disable NIC Sleep
    $nics = Get-WmiObject Win32_NetworkAdapter | where {$_.Name.Contains('Intel')}

    foreach ($nic in $nics)
    {
        $powerMgmt = Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | where {$_.InstanceName -match [regex]::Escape($nic.PNPDeviceID)}
        if ($powerMgmt.Enable -eq $True){
         $powerMgmt.Enable = $False
         $powerMgmt.psbase.Put()
         }
    }
    #Disable Hibernation
    powercfg /hibernate off

    #Import WiFI settings
    netsh wlan add profile filename="C:\windows\Setup\SECURE.xml" user=all

    ### Wait 5 seconds ###
    Start-Sleep -Seconds 5

    #Remove default printers
    Remove-Printer -Name "Microsoft Print to PDF"
    Remove-Printer -Name "Microsoft XPS Document Writer"
    Remove-Printer -Name "Send To OneNote 16"
    Remove-Printer -Name "Fax"

<#
    #VLC no ask privacy/updates
    $TargetFile = '"C:\Program Files (x86)\VideoLAN\VLC\vlc.exe" --no-qt-privacy-ask --no-qt-updates-notif'
    $ShortcutFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\VideoLAN\vlc media player.lnk"
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
    $Shortcut.TargetPath = "C:\Program Files (x86)\VideoLAN\VLC\vlc.exe"
    $shortcut.Arguments = "--no-qt-privacy-ask --no-qt-updates-notif"
    $Shortcut.Save()
#>
}
Wait-Job -Name Job6


###############################################
#  Default File and Application Associations  #
###############################################

Start-Job -Name Job7 -ScriptBlock {
    ### Set Default App/File Associations ###
    $filepath ="$env:SystemDrive\Windows\System32" 
    $filename = "\oemdefaultassociations.xml" 
    $filefullpath = $filepath + $filename 
    $findstring = '<Association Identifier=".pdf" ProgId="AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXk660crfh0gw7gd9swc1nws708mn7qjr1" />'
    $replacestring = '<Association Identifier=".pdf" ProgId="AcroExch.Document.DC" ApplicationName="Adobe Acrobat Reader DC" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" />'

    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath

    $filepath = "$env:SystemDrive\Windows\System32"
    $filename = "\oemdefaultassociations.xml"
    $filefullpath = $filepath + $filename

    ##################
    #      Mail      #
    ##################

    $findstring    = '<Association Identifier="mailto" ProgId="AppXydk58wgm44se4b399557yyyj1w7mbmvd" ApplicationName="Mail" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier="mailto" ProgId="ChromeHTML" ApplicationName="Google Chrome" ApplyOnUpgrade="true"/>'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    ##################
    #  Media Player  #
    ##################
    $findstring    = '<Association Identifier=".3g2" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.3G2" />'
    $replacestring = '<Association Identifier=".3g2" ProgId="VLC.3g2" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".3gp" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.3GP" />'
    $replacestring = '<Association Identifier=".3gp" ProgId="VLC.3gp" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".3gp2" ProgId="WMP11.AssocFile.3G2" ApplicationName="Windows Media Player" />'
    $replacestring = '<Association Identifier=".3gp2" ProgId="VLC.3gp2" ApplicationName="VLC" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".3gpp" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.3GP" />'
    $replacestring = '<Association Identifier=".3gpp" ProgId="VLC.3gpp" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".aac" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.ADTS" />'
    $replacestring = '<Association Identifier=".aac" ProgId="VLC.aac" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".adts" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.ADTS" />'
    $replacestring = '<Association Identifier=".adts" ProgId="VLC.adts" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".ac3" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".ac3" ProgId="VLC.ac3" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".adt" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.ADTS" />'
    $replacestring = '<Association Identifier=".adt" ProgId="VLC.adt" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".amr" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".amr" ProgId="VLC.amr" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".avi" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.AVI" />'
    $replacestring = '<Association Identifier=".avi" ProgId="VLC.avi" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".flac" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".flac" ProgId="VLC.flac" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".m2t" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.M2TS" />'
    $replacestring = '<Association Identifier=".m2t" ProgId="VLC.m2t" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".m2ts" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.M2TS" />'
    $replacestring = '<Association Identifier=".m2ts" ProgId="VLC.m2ts" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".m3u" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".m3u" ProgId="VLC.m3u" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".m4a" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.M4A" />'
    $replacestring = '<Association Identifier=".m4a" ProgId="VLC.m4a" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".m4r" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".m4r" ProgId="VLC.m4r" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".m4v" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.MP4"/>'
    $replacestring = '<Association Identifier=".m4v" ProgId="VLC.m4v" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mka" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.MKA"/>'
    $replacestring = '<Association Identifier=".mka" ProgId="VLC.mka" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mkv" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".mkv" ProgId="VLC.mkv" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mod" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.MPEG" />'
    $replacestring = '<Association Identifier=".mod" ProgId="VLC.mod" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mov" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.MOV" />'
    $replacestring = '<Association Identifier=".mov" ProgId="VLC.mov" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".ec3" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".ec3" ProgId="VLC.ec3" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".MP2" ProgId="WMP11.AssocFile.MP3" ApplicationName="Windows Media Player" />'
    $replacestring = '<Association Identifier=".MP2" ProgId="VLC.mp2" ApplicationName="VLC" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mp3" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.MP3" />'
    $replacestring = '<Association Identifier=".mp3" ProgId="VLC.mp3" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mp4" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.MP4" />'
    $replacestring = '<Association Identifier=".mp4" ProgId="VLC.mp4" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mp4v" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.MP4" />'
    $replacestring = '<Association Identifier=".mp4v" ProgId="VLC.mp4v" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mpa" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.MPEG" />'
    $replacestring = '<Association Identifier=".mpa" ProgId="VLC.mpa" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".MPE" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.MPEG" />'
    $replacestring = '<Association Identifier=".MPE" ProgId="VLC.mpe" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mpeg" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.MPEG" />'
    $replacestring = '<Association Identifier=".mpeg" ProgId="VLC.mpeg" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mpg" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.MPEG" />'
    $replacestring = '<Association Identifier=".mpg" ProgId="VLC.mpg" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mpv2" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.MPEG" />'
    $replacestring = '<Association Identifier=".mpv2" ProgId="VLC.mpv2" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mts" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.M2TS" />'
    $replacestring = '<Association Identifier=".mts" ProgId="VLC.mts" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".tod" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".tod" ProgId="VLC.tod" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".TS" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.TTS" />'
    $replacestring = '<Association Identifier=".TS" ProgId="VLC.ts" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".TTS" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.TTS" />'
    $replacestring = '<Association Identifier=".TTS" ProgId="VLC.tts" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".wav" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.WAV" />'
    $replacestring = '<Association Identifier=".wav" ProgId="VLC.wav" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".wm" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.ASF" />'
    $replacestring = '<Association Identifier=".wm" ProgId="VLC.wm" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".wma" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.WMA" />'
    $replacestring = '<Association Identifier=".wma" ProgId="VLC.wma" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".wmv" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.WMV" />'
    $replacestring = '<Association Identifier=".wmv" ProgId="VLC.wmv" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    <# Not supported by VLC
    $findstring    = '<Association Identifier=".WPL" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.WPL" />'
    $replacestring = '<Association Identifier=".WPL" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" OverwriteIfProgIdIs="WMP11.AssocFile.WPL" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null
    #>

    $findstring    = '<Association Identifier="mswindowsmusic" ProgId="AppXtggqqtcfspt6ks3fjzyfppwc05yxwtwy" ApplicationName="Music" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier="mswindowsmusic" ProgId="VLC.mswindowsmusic" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier="mswindowsvideo" ProgId="AppX6w6n4f8xch1s3vzwf3af6bfe88qhxbza" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier="mswindowsvideo" ProgId="VLC.mswindowsvideo" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".zpl" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".zpl" ProgId="VLC.zpl" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".xvid" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".xvid" ProgId="VLC.xvid" ApplicationName="VLC" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null


    ##################
    #     Browser    #
    ##################
    $findstring    = '<Association Identifier=".epub" ProgId="AppXvepbp3z66accmsd0x877zbbxjctkpr6t" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".epub" ProgId="AppXvepbp3z66accmsd0x877zbbxjctkpr6t" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".htm" ProgId="AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX6k1pws1pa7jjhchyzw9jce3e6hg6vn8d" />'
    $replacestring = '<Association Identifier=".htm" ProgId="ChromeHTML" ApplicationName="Google Chrome" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".html" ProgId="AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX6k1pws1pa7jjhchyzw9jce3e6hg6vn8d" />'
    $replacestring = '<Association Identifier=".html" ProgId="ChromeHTML" ApplicationName="Google Chrome" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier="http" ProgId="AppXq0fevzme2pys62n3e0fbqa7peapykr8v" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXehk712w0hx4w5b8k25kg808a9h84jamg" />'
    $replacestring = '<Association Identifier="http" ProgId="ChromeHTML" ApplicationName="Google Chrome" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier="https" ProgId="AppX90nv6nhay5n6a98fnetv7tpk64pp35es" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXz8ws88f5y0y5nyrw1b3pj7xtm779tj2t" />'
    $replacestring = '<Association Identifier="https" ProgId="ChromeHTML" ApplicationName="Google Chrome" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".url" ProgId="IE.AssocFile.URL" ApplicationName="Internet Explorer" />'
    $replacestring = '<Association Identifier=".url" ProgId="IE.AssocFile.URL" ApplicationName="Google Chrome" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".website" ProgId="IE.AssocFile.WEBSITE" ApplicationName="Internet Explorer" />'
    $replacestring = '<Association Identifier=".website" ProgId="IE.AssocFile.WEBSITE" ApplicationName="Google Chrome" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null


    ##################
    # Acrobat Reader #
    ##################
    $findstring    = '<Association Identifier=".pdf" ProgId="AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXk660crfh0gw7gd9swc1nws708mn7qjr1;AppX86746z2101ayy2ygv3g96e4eqdf8r99j" />'
    $replacestring = '<Association Identifier=".pdf" ProgId="AcroExch.Document.DC" ApplicationName="Adobe Acrobat Reader DC" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null


    ##################
    #     Photos     #
    ##################
    <#
    $findstring    = '<Association Identifier=".3mf" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg;AppXr0rz9yckydawgnrx5df1t9s57ne60yhn"  />'
    $replacestring = '<Association Identifier=".3mf" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg;AppXr0rz9yckydawgnrx5df1t9s57ne60yhn"  />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".arw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".arw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".bmp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;Paint.Picture" />'
    $replacestring = '<Association Identifier=".bmp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;Paint.Picture" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".cr2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".cr2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".crw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".crw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".dib" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;Paint.Picture" />'
    $replacestring = '<Association Identifier=".dib" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;Paint.Picture" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".erf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".erf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".gif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;giffile" />'
    $replacestring = '<Association Identifier=".gif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;giffile" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".jfif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;pjpegfile" />'
    $replacestring = '<Association Identifier=".jfif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;pjpegfile" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".jpe" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;jpegfile" />'
    $replacestring = '<Association Identifier=".jpe" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;jpegfile" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".jpeg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;jpegfile" />'
    $replacestring = '<Association Identifier=".jpeg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;jpegfile" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".jpg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;jpegfile" />'
    $replacestring = '<Association Identifier=".jpg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;jpegfile" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".jxr" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;wdpfile" />'
    $replacestring = '<Association Identifier=".jxr" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;wdpfile" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".kdc" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".kdc" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".mrw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".mrw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".nef" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".nef" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".nrw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".nrw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".orf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".orf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".pef" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".pef" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".png" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;pngfile" />'
    $replacestring = '<Association Identifier=".png" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;pngfile" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".raf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".raf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".raw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".raw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".rw2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".rw2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".rwl" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".rwl" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".tif" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX86746z2101ayy2ygv3g96e4eqdf8r99j;AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;TIFImage.Document" />'
    $replacestring = '<Association Identifier=".tif" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX86746z2101ayy2ygv3g96e4eqdf8r99j;AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;TIFImage.Document" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".tiff" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX86746z2101ayy2ygv3g96e4eqdf8r99j;AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;TIFImage.Document" />'
    $replacestring = '<Association Identifier=".tiff" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX86746z2101ayy2ygv3g96e4eqdf8r99j;AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;TIFImage.Document" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".sr2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".sr2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".srw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".srw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".wdp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    $replacestring = '<Association Identifier=".wdp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null
    #>

    ##################
    #    3D Photos   #
    ##################
    <#
    $findstring    = '<Association Identifier=".fbx" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".fbx" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".glb" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".glb" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".gltf" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".gltf" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".obj" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".obj" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".ply" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier=".ply" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".stl" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg;AppXr0rz9yckydawgnrx5df1t9s57ne60yhn"  />'
    $replacestring = '<Association Identifier=".stl" ProgId="AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp" ApplicationName="View 3D" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg;AppXr0rz9yckydawgnrx5df1t9s57ne60yhn"  />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null
    #>


    ##################
    #   XPS Viewer   #
    ##################
    <#
    $findstring    = '<Association Identifier=".oxps" ProgId="Windows.XPSReachViewer" ApplicationName="XPS Viewer" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX86746z2101ayy2ygv3g96e4eqdf8r99j" />'
    $replacestring = '<Association Identifier=".oxps" ProgId="Windows.XPSReachViewer" ApplicationName="XPS Viewer" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX86746z2101ayy2ygv3g96e4eqdf8r99j" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier=".xps" ProgId="Windows.XPSReachViewer" ApplicationName="XPS Viewer" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX86746z2101ayy2ygv3g96e4eqdf8r99j" />'
    $replacestring = '<Association Identifier=".xps" ProgId="Windows.XPSReachViewer" ApplicationName="XPS Viewer" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX86746z2101ayy2ygv3g96e4eqdf8r99j" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null
    #>

    ##################
    #      Other     #
    ##################
    <#
    $findstring    = '<Association Identifier=".txt" ProgId="txtfile" ApplicationName="Notepad" />'
    $replacestring = '<Association Identifier=".txt" ProgId="txtfile" ApplicationName="Notepad" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier="bingmaps" ProgId="AppXp9gkwccvk6fa6yyfq3tmsk8ws2nprk1p" ApplicationName="Maps" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXde453qzh223ys1wt2jpyxz3z4cn10ngt;AppXsmrmb683pb8qxt0pktr3q27hkbyjm8sb" />'
    $replacestring = '<Association Identifier="bingmaps" ProgId="AppXp9gkwccvk6fa6yyfq3tmsk8ws2nprk1p" ApplicationName="Maps" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppXde453qzh223ys1wt2jpyxz3z4cn10ngt;AppXsmrmb683pb8qxt0pktr3q27hkbyjm8sb" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null

    $findstring    = '<Association Identifier="mailto" ProgId="AppXydk58wgm44se4b399557yyyj1w7mbmvd" ApplicationName="Mail" ApplyOnUpgrade="true" />'
    $replacestring = '<Association Identifier="mailto" ProgId="AppXydk58wgm44se4b399557yyyj1w7mbmvd" ApplicationName="Mail" ApplyOnUpgrade="true" />'
    (get-content $filefullpath) | foreach-object {$_ -replace $findstring, $replacestring} | Set-Content $filefullpath
    $findstring    = $null
    $replacestring = $null
    #>
}
Wait-Job -Name Job7

#################
# Cleanup files #
#################

Start-Job -Name Job8 -ScriptBlock {
    Remove-Item C:\Windows\Setup\*.bat -Confirm:$False -Force
    Remove-Item C:\Windows\Setup\*.xml -Confirm:$False -Force

    #delete file inside the root folder
    $a = Test-Path $7220
    $b = Test-Path $4518
    $c = Test-Path $30AU
    $d = Test-Path $Scripts

    If($a -eq $true) {Get-ChildItem $7220 -Force -Recurse | Sort-Object -Property FullName -Descending | Remove-Item -Recurse -Force}
    If($b -eq $true) {Get-ChildItem $4518 -Force -Recurse | Sort-Object -Property FullName -Descending | Remove-Item -Recurse -Force}
    If($c -eq $true) {Get-ChildItem $30AU -Force -Recurse | Sort-Object -Property FullName -Descending | Remove-Item -Recurse -Force}
    If($d -eq $true) {Get-ChildItem $Scripts -Force -Recurse | Sort-Object -Property FullName -Descending | Remove-Item -Recurse -Force}

    #delete root folder
    If($a -eq $true) {Remove-Item $7220 -Force}
    If($b -eq $true) {Remove-Item $4518 -Force}
    If($c -eq $true) {Remove-Item $30AU -Force}
    If($d -eq $true) {Remove-Item $Scripts -Force}

    #Delete Scheduled Task
    Unregister-ScheduledTask -TaskName "Initial Configuration" -Confirm:$False

}
Wait-Job -Name Job8


##########
# Reboot #
##########

Restart-Computer -Force
