#Expected results

###Test file 4fc89505-75a0-4734-ac6d-1ebbdca28caa:

####Corrupted Processes:

 * 005b80688b5904   |   20  |   Database
 * 005b80688b5904   |   90  |   Spawned 
 * second.exe       |   2   |   Spawned
 * fifth.exe        |   5   |   Memory Written

####Instructions executed:

 * 005b80688b5904   |   20  |   200
 * 005b80688b5904   |   90  |   200 
 * second.exe       |   2   |   100
 * fifth.exe        |   5   |   100

####Syscalls executed:

 * 005b80688b5904   |   20  |   1
 * 005b80688b5904   |   90  |   2
 * second.exe       |   2   |   0
 * fifth.exe        |   5   |   1
 
####Special status:

 * 005b80688b5904   |   20  |   Terminated  |   Sleep
 * 005b80688b5904   |   90  |   Terminated  |   Sleep
 * second.exe       |   2   |   Terminated
 * fifth.exe        |   5   |   Terminated  |   Sleep

####Written files:

 * 005b80688b5904   |   20  |
 * 005b80688b5904   |   90  |
 * second.exe       |   2   |
 * fifth.exe        |   5   |   \Windows\system32\mssitlb.dll
