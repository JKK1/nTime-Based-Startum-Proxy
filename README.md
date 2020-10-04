# Time_proxy
This is a python stratum proxy that uses time instead of nonce to proxy to a stratum pool, it maintains extranonce2size.
###### Only scrypt works 
Extensive refactoring is needed but it does the job.
Just start it and connect, make sure you fill the appropriate pools. It also has a profit-switching functionality, it used to work for when this proxy was nonce based, but it has not been tested with the time based proxy.
There are lots of deprecated functions in there, but it does the job, so \\(o.O)/
It should be very simple to adapt to any other algorithm.
It also contains a socket for communication to get the shares of every user and a kill command to remove all user miners except one per username password combo, useful to kill connections in nicehash to stop mining immediately in case of profitability changes.
##### I hold no responsibility from the loss of earnings of any kind, however if you do use it please send me some BTC, you can use it without paying, but consider giving me 1% of the edge you make using my proxy (no pressure tho).
####  BTC address: 1Ek6fNnocGprGLgDTixEa8nfAyNz1Xsrsr


###Not maintained, fork or contact me


