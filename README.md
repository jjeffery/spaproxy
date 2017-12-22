# spaproxy

This program makes it reasonably easy to deploy a single page application (SPA)
secured with an OAuth 2 server.

It provides the access token to the SPA via the `/token.json` endpoint. The
access token is refreshed as necessary using the refresh token, which the 
SPA never gets access to.

## Acknowledgement

This repository includes code from `github.com/wolfeidau/dynamodbstore`,
copyright Mark Wolfe license MIT.

