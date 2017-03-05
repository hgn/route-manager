
# Route Manager

Routes in a broader sense!

- merges, combine routes from differences sources
- controls local routes
- command routes for connected terminals
- routes can be policy routes
- handles packet marking as well

# Tasks

Can be classified into four groups:


## underlay local route processing

set routes towards other routers locally
These routes are gattered from OHNLD or statically configured.

## underlay terminal route processing

set routes towards other routers at terminals These routes are gattered from
OHNLD or statically configured.

## overlay local route processing

set routes towards other networks, do policy based routing
These are the routes gattered from DMPRD

## overlay terminal route processing

set routes towards other routes at terminals
These are the routes gattered from DMPRD
