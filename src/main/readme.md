<h1>Steps To Implement JWT</h1>

1) Add dependency (io.jsonwebtoken)
2) Create JWT authentication entry point
3) Create JWT token helper
4) JwtAuthFilter extends OnceRequestFilter
5) Create JwtAuthResponse
   1) Get jwt token from response
   2) validate token
   3) get user from token
   4) load user associated with token
   5) set spring security
6) Create spring security config
7) Create api for login to generate token

![Screenshot (5).png](..%2F..%2F..%2F..%2FPictures%2FScreenshots%2FScreenshot%20%285%29.png)