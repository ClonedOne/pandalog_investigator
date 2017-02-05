#Expected results

All the following results are in the format:

 * process name     |   pid |   Value

##Test file 4fc89505-75a0-4734-ac6d-1ebbdca28caa:

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
 * second.exe       |   2   |   Terminated	|
 * fifth.exe        |   5   |   Terminated  |   Sleep

####Written files:

 * 005b80688b5904   |   20  |
 * 005b80688b5904   |   90  |
 * second.exe       |   2   |
 * fifth.exe        |   5   |   \Windows\system32\mssitlb.dll



##Test file d4ec17b9-90ec-4e96-b40b-f6e77f5ca1a7:

####Corrupted Processes:

 * 0e1d93833d3909   |   20  |   Database
 * 0e1d93833d3909   |   90  |   Spawned 
 * second.exe       |   2   |   Spawned
 * fifth.exe        |   5   |   Memory Written

####Instructions executed:

 * 0e1d93833d3909   |   20  |   200
 * 0e1d93833d3909   |   90  |   200 
 * second.exe       |   2   |   100
 * fifth.exe        |   5   |   100

####Syscalls executed:

 * 0e1d93833d3909   |   20  |   1
 * 0e1d93833d3909   |   90  |   2
 * second.exe       |   2   |   1
 * fifth.exe        |   5   |   1
 
####Special status:

 * 0e1d93833d3909   |   20  |   			|   Sleep
 * 0e1d93833d3909   |   90  |   Terminated  |   Sleep
 * second.exe       |   2   |   Terminated	| 	Sleep
 * fifth.exe        |   5   |   Terminated  |   Sleep

####Written files:

 * 0e1d93833d3909   |   20  |
 * 0e1d93833d3909   |   90  |
 * second.exe       |   2   |
 * fifth.exe        |   5   |
