#  Malicious Multiparty PSI and PSI-CA
This is the implementation of our paper: **Fast, Malicious Multiparty PSI and Extensions to PSI-CA**. 

NOTE: the current code is under maintenance to integrate the stand-alone OKVS libs. However, you can still use it to evualate our protocols. 

## Installations
### Clone project
```
git clone --recursive git@github.com:anonymous-PSI-coder/mPSI.git
```

### Quick Installation (Linux)
    $ cd mPSI/thirdparty
    $ bash all_linux.get



## Installations

### Required libraries
 C++ compiler with C++14 support. There are several library dependencies including [`Boost`](https://sourceforge.net/projects/boost/), [`Miracl`](https://github.com/miracl/MIRACL), [`NTL`](http://www.shoup.net/ntl/) , [`libOTe`](https://github.com/osu-crypto/libOTe), and  [`libPaXoS`](https://github.com/asu-crypto/mPSI/tree/paxos/libPaXoS). For `libOTe`, it requires CPU supporting `PCLMUL`, `AES-NI`, and `SSE4.1`. Optional: `nasm` for improved SHA1 performance.   Our code has been tested on both Windows (Microsoft Visual Studio) and Linux. To install the required libraries: 
  * windows: open PowerShell,  `cd ./thirdparty`, and `.\all_win.ps1` 
  * linux: `cd ./thirdparty`, and `bash .\all_linux.get`.   

NOTE: If you meet problem with `all_win.ps1` or `all_linux.get` which builds boost, miracl and libOTe, please follow the more manual instructions at [`libOTe`](https://github.com/osu-crypto/libOTe). For libPaXoS, please follow the more manual instructions at [`libPaXoS`](https://github.com/asu-crypto/mPSI/tree/paxos/libPaXoS)

### Building the Project

##### Windows:
1. build cryptoTools,libOTe, and libOPRF projects in order.
2. add argument for bOPRFmain project (for example: -u)
3. run bOPRFmain project
 
##### Linux:
1. cd ..
2. cmake .
3. make (requirements: `CMake`, `Make`, `g++` or similar)
4. for test:
	./bin/frontend.exe -u


## Running the code
The database is generated randomly. The outputs include the total running time . 
#### Flags:
    -u		unit test which computes PSI of 5 paries, 2 dishonestly colluding, each with set size 2^12 in malicious setting
	-n		number of parties
	-p		party ID
	-m		set size
	-t		number of corrupted parties 	
#### Examples: 
##### 1. Unit test:
	./bin/frontend.exe -u
	
##### 2. mPSI:
Compute mPSI of 5 parties, 2 dishonestly colluding, each with set size 2^12 

	./bin/frontend.exe -m 12 -n 5 -t 2 -p 0 & ./bin/frontend.exe -m 12 -n 5 -t 2 -p 1 & ./bin/frontend.exe -m 12 -n 5 -t 2 -p 2 & ./bin/frontend.exe -m 12 -n 5 -t 2 -p 3 & ./bin/frontend.exe -m 12 -n 5 -t 2 -p 4
	
## Summary
	1. git clone --recursive git@github.com:anonymous-PSI-coder/mPSI.git
	2. cd thirdparty/
	3. bash all_linux.get
	4. cd ..
	5. cmake .
	6. make
	7. ./bin/frontend.exe -u

