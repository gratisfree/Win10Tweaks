@echo [off]
powershell.exe -noprofile -executionpolicy bypass -file .\part1.ps1
sleep 3
.\part2.cmd
pause
