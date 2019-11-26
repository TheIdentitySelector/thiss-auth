thiss-js cross domain authorization
=====

** NOTE WELL: this is an experimental service not yet implemented in thiss-js **

This repository contains the source of the (first version of) the authorization service for
thiss.io software. The service relies on the experimental "oauth3" - i.e oauth.xyz - transactional
authorization protocol.

In the traditional oauth2 model the resource service is the iframe providing the (cross-domain)
persistence service and the client is the calling page or iframe. The authorization service 
works with a very simple trust model: any client that can wield the private key of any service
or identity provider in a designated metadata aggregate will get an access token in the form
of a JWT which the client can present to the persistence service iframe via a post-message call.

The authorization service is configured with an MDQ service which is queried for metadata
matching the provided key id (kid) of the authorization request. Note that in this model
the user is not involved in the authorization flow. The reason for this is that user data is
not used anywhere and therefore we do not rely on consent.
