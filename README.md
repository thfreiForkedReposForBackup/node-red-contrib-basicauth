# node-red-contrib-basicauth
Node-RED node providing basic access authentication for the HTTP In node

This node differs from other nodes providing basic authentication in that it provides a second output to allow the user to handle authentication failures as they see fit.

The second output will get called with a `msg` object with this structure:

```javascript
{
  // An error message describing the situation
  payload: string,

  // The URL or endpoint that was hit
  url: string,

  // The username that the client attempted to log in with
  username: string,

  // The value in the X-Real-IP header
  ipAddress: string | undefined,
}
```
