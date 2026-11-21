$log = 'C:\Users\tfvtd\Desktop\项目\disk-patch\out\_restore_lic.log'
"start" | Out-File -Encoding utf8 $log
foreach ($sub in @('Reg','CReg')) {
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Eassos\DiskGenius\$sub", $true)
    if ($null -ne $k) {
        $k.SetValue('license', [byte[]]@(), 'Binary')
        $k.Close()
        "$sub -> empty" | Out-File -Append -Encoding utf8 $log
    } else { "$sub missing" | Out-File -Append -Encoding utf8 $log }
}
"done" | Out-File -Append -Encoding utf8 $log
