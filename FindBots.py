
#------------------------------------------------------------------------------------------
from web3 import Web3

#------------------------Setup Variables and Connections--------------------#
web3 = Web3(Web3.HTTPProvider('ADD YOUR HTTP INFURA URL'))
block = web3.eth.get_block('latest')
toFromPairs = {}
transactionCount = {}
#------------------------Setup Variables and Connections--------------------#


#--------------------Begin Main Code Block-----------------------------------#
#Grab our Transactions and thier transaction hashes
if block and block.transactions: 
    for transaction in block.transactions: 
        tx_hash = transaction.hex() # Convert txhashes from hexBytes format
        tx = web3.eth.get_transaction(tx_hash)

#Check if To/From pairs exist and update count        
        if tx.to != None:
            if tx.to in toFromPairs:
                if toFromPairs[tx.to] == tx["from"]:
                    transactionCount[tx.to] = transactionCount[tx.to] +1 

#Start a running count on any new To addresses and create a to/from pair               
            elif tx.to not in toFromPairs:
                transactionCount[tx.to] = 1
                toFromPairs[tx.to] = tx["from"]

#-------------------- End Main Code Block------------------------------------#



#Print all pairs with exactly 2 transactions in a single block for manual review
for key, value in transactionCount.items():
    if value == 2:
        print(toFromPairs[key])
