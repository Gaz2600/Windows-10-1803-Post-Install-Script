# Windows-10-1803-Post-Install-Script

This script was built for my environment, you will need to modify to fit yours.  I am using Smart Deploy to deploy my base image, after the base install SD will auto login and I've got it set to map a network drive to z: and launch the Run_Once.ps1 post install script.  You can do this other ways.  Another way would be to save the post install files locally in the base image, I suggest in C:\Windows\Setup\Scripts then set a scheduled task to run run_once.bat at first login.
