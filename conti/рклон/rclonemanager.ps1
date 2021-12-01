$2load = Get-Content -Path '2load.txt'
$sharecount = $2load.Count
$config = Get-Content -Path 'rclone.conf'
$process = 'rclone'
$commandstringBegin = 'rclone.exe copy --max-age 3y ' #можно поменять годы
$commandstringEnd = '-q --ignore-existing --auto-confirm --multi-thread-streams 7 --transfers 7' #можно поменять потоки
#Write-Host $2load
#Write-Host $2load[2]
$workflag = 1
#Write-Host $config[0]
$mega = $config[0]
$mega = $mega.Replace(']','') #\\костыль, пока так
$mega = $mega.Replace('[','') #\\костыль, пока так
Write-Host $mega
$workflag = 1
while($workflag -ne 0)
{	
	$loadedcount = 0
		foreach ( $2loadcheck in $2load)
		{
			
			if ($2loadcheck.IndexOf(' ; loaded') -gt 0 )
			{
				#Write-Host $2loadcheck.IndexOf(' ; loaded')
				$loadedcount++
				
			}
			
			
		}
		if ($sharecount -eq $loadedcount )
		{
				Write-Host('finish')
				exit
		}
	if ( -not (get-process | where {$_.ProcessName -eq 'rclone'}))
	{ 
		Write-Host ('not found. Start rclone')
		
		$loadcount = 0
		$tekflag = 1
		foreach ( $2loadstring in $2load)
		{
			if ($tekflag -eq 1)
			{
				$2loadstring  = $2loadstring.Replace(" ","")
				$2loadstringsplit = $2loadstring.Split(' ; ')
				#Write-Host $2loadstringsplit[0]
				#Write-Host $2loadstringsplit[1]
				if ($2loadstringsplit.Count -eq 1)
				{
				
					#Write-Host ('start loading', $2loadstringsplit)
					$sharestringFull = $2loadstringsplit[0].Split('\')
					#Write-Host('share --   ', $sharestringFull[-1])
					$commandstringMiddle = $mega + ':' + $sharestringFull[-1]
					#Write-Host $commandstringMiddle
					$FinalCommand = $commandstringBegin + '"' + $2loadstring + '"' + ' ' + $commandstringMiddle + ' ' + $commandstringEnd
					Set-content 'rc.bat' $FinalCommand
					
					start 'rc.bat'
					#Write-Host "proc: [$proc]"
					#Write-Host
					Write-Host $FinalCommand
					Start-Sleep -s 1
					$tekflag = 0
					#Write-Host $loadcount
					$2load[$loadcount] = $2loadstring + ' ; loaded' 
					#Write-Host $2load
					
					$loadcount++
					Remove-Item '2load.txt'
					foreach ( $2loadstring in $2load)
					{
				
						Add-content '2load.txt' $2loadstring
								
					}
				
				} else {
			
					#Write-Host('Arlready loaded', $2loadstringsplit)
					$loadcount++
				}
			
			}	
		}
		#Start-Process -FilePath 'c:\windows\notepad.exe'

	} else {
		Write-Host ('Arlready working')
		
		Start-Sleep -s 180
		}

#Remove-Item 'rc.bat'
}
