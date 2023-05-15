##########
# W10 Optimizations - adapted by Metaljisawa
# Source : https://github.com/Disassembler0
##########


	}
}

$tweaks = @()
$PSCommandArgs = @()

Function AddOrRemoveTweak($tweak) {
	If ($tweak[0] -eq "!") {
		$script:tweaks = $script:tweaks | Where-Object { $_ -ne $tweak.Substring(1) }
	} ElseIf ($tweak -ne "") {
		$script:tweaks += $tweak
	}
}

$i = 0
While ($i -lt $args.Length) {
	If ($args[$i].ToLower() -eq "-include") {
		$include = Resolve-Path $args[++$i]
		$PSCommandArgs += "-include `"$include`""
		Import-Module -Name $include
	} ElseIf ($args[$i].ToLower() -eq "-preset") {
		$preset = Resolve-Path $args[++$i]
		$PSCommandArgs += "-preset `"$preset`""
		Get-Content $preset -ErrorAction Stop | ForEach-Object { AddOrRemoveTweak($_.Split("#")[0].Trim()) }
	} ElseIf ($args[$i].ToLower() -eq "-log") {
		$log = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($args[++$i])
		$PSCommandArgs += "-log `"$log`""
		Start-Transcript $log
	} Else {
		$PSCommandArgs += $args[$i]
		AddOrRemoveTweak($args[$i])
	}
	$i++
}

$tweaks | ForEach-Object { Invoke-Expression $_ }
