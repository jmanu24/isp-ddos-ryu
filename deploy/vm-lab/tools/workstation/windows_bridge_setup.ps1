# Run in an elevated PowerShell on the Windows host with lab-wifi-gateway POWERED OFF.
# Maps VMware VMnet0 to Ethernet 2 (the direct 1 Gbps link) and adds the link NIC (trunk0) to the gateway VMX.
# The link carries VXLAN over plain IP (172.31.252.0/30); 802.1Q tags are NOT used (the Realtek NIC strips them on receive).
# Rollback: reg import C:\Users\Usuario\vmnetbridge-before.reg and delete the ethernet8.* lines (backup: <vmx>.before-trunk).
$ErrorActionPreference = 'Stop'
$vmx = 'C:\Users\Usuario\Documents\Codex\2026-10-01\referenced-chatgpt-conversation-this-is-an\work\migration\wifi-gateway-vmx\lab-wifi-gateway\lab-wifi-gateway.vmx'
$k = 'HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMnetLib\VMnetBridge\Adapters'
$eth2 = (Get-NetAdapter -Name 'Ethernet 2').InterfaceGuid
$wifi = (Get-NetAdapter -Name 'Wi-Fi 2').InterfaceGuid
if (Get-CimInstance Win32_Process -Filter "Name='vmware-vmx.exe'" | Where-Object { $_.CommandLine -match 'lab-wifi-gateway' }) { throw 'Power off lab-wifi-gateway first' }
reg export 'HKLM\SOFTWARE\WOW6432Node\VMware, Inc.\VMnetLib\VMnetBridge' C:\Users\Usuario\vmnetbridge-before.reg /y | Out-Null
Get-ChildItem $k | Where-Object { (Get-ItemProperty $_.PSPath).VMnet -eq 0 } | ForEach-Object { Set-ItemProperty $_.PSPath -Name VMnet -Value 4294967295 -Type DWord }
Set-ItemProperty "$k\$eth2" -Name VMnet -Value 0 -Type DWord
Get-ChildItem $k | ForEach-Object { '{0} VMnet={1}' -f $_.PSChildName, (Get-ItemProperty $_.PSPath).VMnet }
if (-not (Select-String -Path $vmx -Pattern '^ethernet8\.present' -Quiet)) {
  Copy-Item $vmx "$vmx.before-trunk"
  Add-Content -Path $vmx -Value @(
    'ethernet8.present = "TRUE"', 'ethernet8.virtualDev = "vmxnet3"', 'ethernet8.startConnected = "TRUE"',
    'ethernet8.addressType = "static"', 'ethernet8.address = "00:50:56:3a:a0:08"', 'ethernet8.connectionType = "bridged"')
}
Select-String -Path $vmx -Pattern '^ethernet8'
Write-Output 'Done. Start lab-wifi-gateway and tell Claude.'
