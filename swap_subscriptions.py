#!/usr/bin/env python3

# note: if after installing python_graphql_client you get an error involving a "loop parameter",
# your python packages state may require that you also do
# pip3 install --upgrade websockets

from python_graphql_client import GraphqlClient # pip3 install python-graphql-client
import asyncio, datetime, time

websocketClient = GraphqlClient(endpoint='wss://testnet.api.deepwaters.xyz/swap/graphql')

# any of the filter keys in the "where" can be removed,
# as can the entire "(where: ... )" clause, to get the full L3 order updates stream
# also, any of the requested output (e.g. "venueOrderID") can be removed, to shrink the JSON received
# even more filters and output values are possible
ordersL3Query = """
subscription {
	orders(where: {customer: "0x85e7E8E942B8CA402826F8EA55d6a638248d98d0",
    			   customerObjectID_like: "30",
  				   type: LIMIT,
  				   side: BUY,
  				   baseAssetID: "WBTC.GOERLI.5.TESTNET.PROD",
  				   quoteAssetID: "USDC.GOERLI.5.TESTNET.PROD",
  				   status_in: [ACTIVE, CANCELLED, EXPIRED, REJECTED, FILLED, PARTIALLY_FILLED] } ) {
		venueOrderID
		customerObjectID
		baseAssetID
		quoteAssetID
		customer {
			address
		}
		type
		side
		price
		quantity
		originalQuantity
		status
		volume
		averagePrice
		durationType
		createdAt {
			time
			microsSinceEpoch
		}
		modifiedAt {
			time
			microsSinceEpoch
		}
		expiresAt {
			time
			microsSinceEpoch
		}
		expiresIn {
			duration
			micros
		}
	}
}"""

# baseAssetID and quoteAssetID are required
# but requested output (e.g. "reason") can be removed, to shrink the JSON received
ordersL2Query = """
subscription {
 	orderBook(baseAssetID: "WBTC.GOERLI.5.TESTNET.PROD", quoteAssetID: "USDC.GOERLI.5.TESTNET.PROD") {
    	baseAssetID
    	quoteAssetID
    	time {
      		time
      		microsSinceEpoch
    	}
    	side
    	price
    	quantity
    	reason
 	}
}
"""

# any of the filter keys in the "where" can be removed,
# as can the entire "(where: ... )" clause, to get the full trades stream
# also, any of the requested output (e.g. "venueOrderID") can be removed, to shrink the JSON received
# even more filters and output values are possible
tradesQuery = """
subscription {
  	trades(where: {customer: "0x85e7E8E942B8CA402826F8EA55d6a638248d98d0",
    			   customerObjectID_like: "30",
    			   type: PARTIAL_FILL,
    			   baseAssetID: "WBTC.GOERLI.5.TESTNET.PROD",
    			   quoteAssetID: "USDC.GOERLI.5.TESTNET.PROD" }) {
		tradeID
		createdAt {
			time
			microsSinceEpoch
		}
		type
		baseAssetID
		quoteAssetID
		price
		quantity
		volume
		maker {
			remainingQty
			order {
				venueOrderID
				customer {
					address
				}
				status
				type
				side
				price
				quantity
				originalQuantity
				volume
				averagePrice
				createdAt {
					time
					microsSinceEpoch
				}
				modifiedAt {
					time
					microsSinceEpoch
				}
				expiresAt {
					time
					microsSinceEpoch
				}
			}
		}
		aggressor {
			remainingQty
			order {
				venueOrderID
				customer {
					address
				}
				status
				type
				side
				price
				quantity
				originalQuantity
				volume
				averagePrice
				createdAt {
					time
					microsSinceEpoch
				}
				modifiedAt {
					time
					microsSinceEpoch
				}
				expiresAt {
					time
					microsSinceEpoch
				}
			}
		}
	}
}
"""

def log(feed_label, x):
	now = datetime.datetime.now()
	print(now, feed_label, x)
	print()

async def main():
	ordersL3 = asyncio.create_task(websocketClient.subscribe(query=ordersL3Query, handle=lambda d: log('order book L3 update', d)))
	ordersL2 = asyncio.create_task(websocketClient.subscribe(query=ordersL2Query, handle=lambda d: log('order book L2 update', d)))
	trades = asyncio.create_task(websocketClient.subscribe(query=tradesQuery, handle=lambda d: log('trade', d)))
	await asyncio.gather(ordersL3, ordersL2, trades)

while True:
	try:
		asyncio.run(main())
	except Exception as E:
		print(E)
		print('error or disconnected, reconnect in 5 secs...')
		time.sleep(5)
