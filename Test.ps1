# Initialize counters
$script:passes = 0
$script:fails = 0
$script:noTest = 0



function getProzent {
    param (
        [int]$a,
        [int]$b
    )

    $total = $a + $b

    $percentage = [math]::Round(($a / $total) * 100)


    return $percentage
}




function Test-IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}





# Unicode Method
$checkMark = [char]0x2705
$NoEntry = [char]0x26D4
$BulletPoint = [char]0x2022

# Create the shield emoji directly using a Unicode escape sequence
# Define the surrogate pair for the shield emoji
$EmojiIcon = [System.Convert]::toInt32("1F6E1",16)
$shield = [System.Char]::ConvertFromUtf32($EmojiIcon)

$record = [System.Text.Encoding]::UTF32.GetString(@([byte]0xFA, [byte]0x23, [byte]0x00, [byte]0x00))





# Define the Test function
function Test {
    param (
        [string]$TestName,  # The name of the test
        [scriptblock]$Func,  # The function to be tested as a script block
        [bool]$RequiresAdmin
    )


    if (-not ($Func)) {
        Write-Host "$record  $TestName"

        return
    }




    try {
        # Ensure $RequiresAdmin is treated as a boolean
        $isAdminRequired = [bool]::Parse($RequiresAdmin.ToString())
    
        if ($isAdminRequired) {
            # Admin check
            if (-not (Test-IsAdmin)) {
                Write-Host "$record $shield  $TestName"
            } else {
                $result = & $Func  # Call the function using the call operator
    
                # Output success message
                if ($result) {
                    Write-Host "$checkMark $shield  $TestName $BulletPoint $result"
                } else {
                    Write-Host "$checkMark $shield  $TestName"
                }
    
                # Increment passes
                $script:passes += 1
            }
    
            return
        }
    
        $result = & $Func  # Call the function using the call operator
    
        # Output success message
        if ($result) {
            Write-Host "$checkMark $TestName $BulletPoint $result"
        } else {
            Write-Host "$checkMark $TestName"
        }
    
        # Increment passes
        $script:passes += 1
    } catch {
        # Increment fails and output error message
        $script:fails += 1


        $isAdminRequired = [bool]::Parse($RequiresAdmin.ToString())

        if ($isAdminRequired -and (Test-IsAdmin)) {
            Write-Host "$NoEntry $shield  $TestName failed: $_" -ForegroundColor Yellow

            return
        }

        Write-Host "$NoEntry $TestName failed: $_" -ForegroundColor Yellow
    }    
}  # <-- Ensure this closing brace is present



Write-Host "UNC Windows Check"
Write-Host "$checkMark - Pass, $NoEntry - Fail, $record  - No Test, $shield  - Requires Administrator Primissions To Test"
Write-Host " "



Write-Host "Protection: "

# Example function to test
function RealTimeProtection {
    $realTimeProtectionStatus = Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring


    if ($realTimeProtectionStatus) {
        throw "RealTime-Protection is Disabled! Making the PC Vulnerable agenst Virus!"

        return
    }

    return "RealTime Protection is Enabled"
}




Test -TestName "RealTime-Protection" -Func { RealTimeProtection }



function checkFor_CheckForSignaturesBeforeRunningScan {
    $realTimeProtectionStatus = Get-MpPreference | Select-Object -ExpandProperty CheckForSignaturesBeforeRunningScan


    if ($realTimeProtectionStatus) {
        throw "This can make Downloading or Running Programs not posible!"

        return
    }
}


Test -TestName "CheckForSignaturesBeforeRunningScan" -Func { checkFor_CheckForSignaturesBeforeRunningScan }



function checkFor_DisableCatchupQuickScan {
    $realTimeProtectionStatus = Get-MpPreference | Select-Object -ExpandProperty DisableCatchupQuickScan


    if (-not ($realTimeProtectionStatus)) {
        throw "This can make Virus Scans miss potensial Virus-/Malware's"

        return
    }
}


function checkFor_DisableScriptScanning {
    $e = Get-MpPreference | Select-Object -ExpandProperty DisableScriptScanning


    if ($e) {
        throw "This can make your PC Vulnerable"
    }
}



function checkFor_Firewall {
    $o = Get-NetFirewallProfile | Select-Object Name, Enabled
    $e = 0
    $y = $false


    if (-not ((Get-NetFirewallProfile -Profile Public).Enabled)) {
        $e += 1
        $y = $true
    }

    if (-not ((Get-NetFirewallProfile -Profile Private).Enabled)) {
        $e += 1
        $y = $true
    }

    if (-not ((Get-NetFirewallProfile -Profile Domain).Enabled)) {
        $e += 1
        $y = $true
    }



    if ($y) {
        throw "Firewall are Disabled! Making your System Vunrable! Count Disabled: $e"
    }



    return "Firewalls are Enabled"
}



Test -TestName "DisableScriptScanning" -Func { checkFor_DisableScriptScanning }




Test -TestName "DisableCatchupQuickScan" -Func { checkFor_DisableCatchupQuickScan }




Test -TestName "Firewall" -Func { checkFor_Firewall }






function checkFor_memoryIntegrity {
    $t = Get-WmiObject -Namespace "root\Microsoft\Windows\DeviceGuard" -Class "Win32_DeviceGuard" | Select-Object -ExpandProperty RequiredSecurityProperties

    if ($t -contains "1") {
        throw "Memory-integrity is Disabled! This can make your PC Vulnerable. By Adding dangures Code into your System!"
    } else {
        
    }
}




Test -TestName "MemoryIntegrity"




function check_CoreIsolationMemoryIntegrity {
    # Check if 'Memory Integrity' (Beskyttelse av utviklerstasjon) is enabled
    $memoryIntegrityStatus = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -ErrorAction SilentlyContinue

    if ($memoryIntegrityStatus.Enabled -eq 1) {
        return "enabled."
    } else {
        throw "disabled. this can make your PC Vunrable, and Allow Unwanted Software too add Dangerus Code Into your System!"
    }
}


Test -TestName "MemoryIntegrity (Beskyttelse av utviklerstasjon)" -Func { check_CoreIsolationMemoryIntegrity }








Write-Host " "
Write-Host "Installed Apps"




function checkProgram {
    param (
        [string]$name,
        [string]$defaultName
    )



    function check {
        $path = $defaultName

        if (-not (Test-Path $path)) {
            throw "$name is not Installed. Can have something to do with how Windows got Installed"
        }


        return "$name is Installed"
    }


    Test -TestName $name -Func { check }
}



function checkFor_Kalkulator_App_Installed {
    # Path to the Calculator executable
    $calculatorApp = Get-AppxPackage -Name "*Calculator*"

    if ($calculatorApp) {
        return "Kalkulator is Installed"
    } else {
        throw "Kalkulator is not Installed. Can have something to do with how Windows got Installed"
    }
}


Test -TestName "Kalkulator" -Func { checkFor_Kalkulator_App_Installed }



function checkFor_voiceRecorderApp {
    $voiceRecorderApp = Get-AppxPackage *SoundRecorder* | Select-Object Name, PackageFullName

    if ($voiceRecorderApp) {
        return "Voice Recorder (Stemmeopptak) is installed."
    } else {
        throw "Voice Recorder (Stemmeopptak) is not installed. Can have something to do with how Windows got Installed"
    }
}



Test -TestName "Voice Recorder (Stemmeopptak)" -Func { checkFor_voiceRecorderApp }




function checkFor_MicrosoftEdge_App {
    # Check if Microsoft Edge is installed
    $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

    if (Test-Path $edgePath) {
        return "Microsoft Edge is installed."
    } else {
        throw "Microsoft Edge is not installed. Can have something to do with how Windows got Installed"
    }
}



Test -TestName "Microsoft Edge" -Func { checkFor_MicrosoftEdge_App }


function checkFor_GoogleChrome_App {
    # Check if Google Chrome is installed
    $chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"

    if (Test-Path $chromePath) {
        return "Google Chrome is installed."
    } else {
        throw "Google Chrome is not installed."
    }
}


Test -TestName "Google Chrome" -Func { checkFor_GoogleChrome_App }



function checkFor_MicrosoftStore_App {
    # Check if Microsoft Store is installed
    $storeApp = Get-AppxPackage -Name "*Microsoft.Store*"

    if ($storeApp) {
        return "Microsoft Store is installed."
    } else {
        throw "Microsoft Store is not installed."
    }
}



Test -TestName "Microsoft Store" -Func { checkFor_MicrosoftStore_App }




function checkFor_Camera_App {
    # Check if the Camera app is installed
    $cameraApp = Get-AppxPackage -Name "*WindowsCamera*"
    if ($cameraApp) {
        return "Camera is installed."
    } else {
        throw "Camera app is not installed."
    }
}


Test -TestName "Camera" -Func { checkFor_Camera_App }



function checkFor_Cleanmgr_App {
    $cleanupPath = "$env:SystemRoot\System32\cleanmgr.exe"
    if (Test-Path $cleanupPath) {
        return "Disk Cleanup is installed."
    } else {
        throw "Disk Cleanup is not installed."
    }
}


Test -TestName "Cleanup Manager" -Func { checkFor_Cleanmgr_App }



function checkFor_Notepad_App {
    $app = Get-AppxPackage *Notepad* | Select-Object Name, PackageFullName

    if ($app) {
        return "Notepad is Installed."
    } else {
        throw "Notepad is not Installed."
    }
}


Test -TestName "Notepad" -Func { checkFor_Notepad_App }




function checkFor_Registry_App {
    # Define the path to the Registry app
    $regeditPath = "C:\Windows\regedit.exe"

    # Check if the Registry app exists
    if (Test-Path $regeditPath) {
        return "Registry is installed."
    } else {
        throw "Registry is not installed."
    }
}


Test -TestName "Registry" -Func { checkFor_Registry_App }



function checkFor_TaskManager_App {
    $taskManagerPath = "C:\Windows\System32\taskmgr.exe"
    if (Test-Path $taskManagerPath) {
        return "Task Manager is installed."
    } else {
        throw "Task Manager is not installed."
    }
}



Test -TestName "TaskManager" -Func { checkFor_TaskManager_App }



function checkFor_CMD_App {
    $cmdPath = "C:\Windows\System32\cmd.exe"
    if (Test-Path $cmdPath) {
        return "Command Prompt is installed."
    } else {
        throw "Command Prompt is not installed."
    }
}



Test -TestName "Command Prompt (CMD)" -Func { checkFor_CMD_App }



function checkFor_SnippingTool_App {
    if (Get-AppxPackage | Where-Object { $_.Name -like "*Snip*" -or $_.Name -like "*Sketch*" }) {
        return "Snipping Tool is installed."
    } else {
        throw "Snipping Tool is not installed."
    }
}


Test -TestName "Snipping Tool (Utklippeverktøy)" -Func { checkFor_SnippingTool_App }





$defaultDir = "C:\Windows\System32"


checkProgram -name "Control Panel" -defaultName "C:\Windows\System32\control.exe"
checkProgram -name "Remote Desktop Connection" -defaultName "C:\Windows\System32\mstsc.exe"
checkProgram -name "Magnifier" -defaultName "C:\Windows\System32\magnify.exe"






Write-Host " "
Write-Host "Windows"



function checkFor_WindowsVersion {
    # Initialize COM object for Windows Update
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

    # Search for available updates
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")

    # Check if updates are available
    if ($SearchResult.Updates.Count -gt 0) {
        throw "Updates are available. Your Windows version is not up to date. $($SearchResult.Updates.Count) updates found."
    } else {
        return "Your Windows version is up to date."
    }
}



Test -TestName "Windows Update" -Func { checkFor_WindowsVersion }



function checkFor_WindowsVersionV2 {
    # Initialize COM object for Windows Update
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

    # Search for available updates
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")

    # Get current Windows version and build number from the registry
    #$currentBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    #$currentVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId


    # Check if updates are available
    if ($SearchResult.Updates.Count -gt 0) {
        throw "There are updates available. Your Windows version may not be the latest."
    } else {
        throw "Your Windows version is up to date."
    }
}


# Test -TestName "Windows Version" -Func { checkFor_WindowsVersionV2 }




function checkIf_User_Windows_Latest_Version {
    # Function to fetch the latest Windows 11 version from the Microsoft Release Information
    function Get-LatestWindows11Version {
        $url = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"

        try {
            # Fetch the webpage content
            $webContent = Invoke-RestMethod -Uri $url

            # Use regex to search for the latest version in the release history
            if ($webContent -match 'Version\s*(\d+H\d+)\s*\(OS build (\d+)\)') {
                $latestVersion = "$($matches[1]) (OS build $($matches[2]))"
                return $latestVersion
            } else {
                throw "Could not find version information for Windows 11."
                return $null
            }
        } catch {
            throw "Failed to fetch the latest version info: $_"
            return $null
        }
    }

    # Main script execution
    $currentBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    #Write-Host "Current OS Build: $currentBuild"

    # Fetch the latest Windows 11 version
    $latestVersion = Get-LatestWindows11Version

    if ($latestVersion) {
        # Extract the OS Build from the latest version info
        if ($latestVersion -match 'OS build (\d+)') {
            $latestBuild = $matches[1]
            #Write-Host "Latest version available for Windows 11: $latestVersion"
        
            # Compare the current OS Build with the latest available build
            if ($currentBuild -eq $latestBuild) {
                return "Your Windows version is up to date. Version: $(((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion") | Select-Object -Property *).DisplayVersion)"
            } else {
                throw "Your Windows version is NOT up to date. Current Version: Current Version: $(((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion") | Select-Object -Property *).DisplayVersion), New Version: $latestVersion"
            }
        } else {
            throw "Could not extract the latest OS Build from version information."
        }
    } else {
        throw "Could not determine the latest Windows version."
    }
}

Test -TestName "Windows Version" -Func { checkIf_User_Windows_Latest_Version }







Write-Host " "
Write-Host " "







$rate = getProzent -a $script:passes -b $script:fails


$all = $script:passes + $script:fails

$outOf = "$script:passes out of $all"



# Output total passes and fails
Write-Host "$checkMark Tested with a $rate% success rate ($outOf)"
Write-Host "$NoEntry $script:fails tests failed"
